/*
 * Chimera (X.509 Alternative Keys) support: extension access and independent
 * verification of the alternative (ML-DSA) signature.
 */
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include "chimera.h"

int chimera_get_extension(const X509 *cert, const char *oid,
                          const unsigned char **out, int *out_len)
{
    ASN1_OBJECT *obj = OBJ_txt2obj(oid, 1);
    if (!obj)
        return 0;
    int idx = X509_get_ext_by_OBJ(cert, obj, -1);
    ASN1_OBJECT_free(obj);
    if (idx < 0)
        return 0;
    X509_EXTENSION *ext = X509_get_ext(cert, idx);
    ASN1_OCTET_STRING *data = ext ? X509_EXTENSION_get_data(ext) : NULL;
    if (!data)
        return 0;
    *out = ASN1_STRING_get0_data(data);
    *out_len = ASN1_STRING_length(data);
    return 1;
}

int chimera_has_alt_signature(const X509 *cert)
{
    const unsigned char *p;
    int len;
    return chimera_get_extension(cert, OID_ALT_SIG_ALG, &p, &len) &&
           chimera_get_extension(cert, OID_ALT_SIG_VAL, &p, &len);
}

int chimera_has_alt_pubkey(const X509 *cert)
{
    const unsigned char *p;
    int len;
    return chimera_get_extension(cert, OID_ALT_PUBKEY, &p, &len);
}

int chimera_alt_sig_alg_name(const X509 *cert, char *buf, size_t buf_len)
{
    const unsigned char *raw;
    int raw_len;
    if (!chimera_get_extension(cert, OID_ALT_SIG_ALG, &raw, &raw_len))
        return 0;
    X509_ALGOR *alg = d2i_X509_ALGOR(NULL, &raw, raw_len);
    if (!alg)
        return 0;
    const ASN1_OBJECT *obj;
    X509_ALGOR_get0(&obj, NULL, NULL, alg);
    OBJ_obj2txt(buf, (int)buf_len, obj, 0);
    X509_ALGOR_free(alg);
    return 1;
}

EVP_PKEY *chimera_load_alt_pubkey(const X509 *cert)
{
    const unsigned char *raw;
    int raw_len;
    if (!chimera_get_extension(cert, OID_ALT_PUBKEY, &raw, &raw_len))
        return NULL;
    return d2i_PUBKEY(NULL, &raw, raw_len);
}

/* ---- Minimal DER helpers (bounds-checked, via ASN1_get_object) ---- */

typedef struct {
    const unsigned char *start; /* first byte of the TLV */
    long tlv_len;               /* header + content */
    const unsigned char *content;
    long content_len;
    int tag, xclass;
} der_tlv;

static int der_next(const unsigned char **p, long *remaining, der_tlv *t)
{
    const unsigned char *start = *p, *q = *p;
    long len;
    int tag, xclass;
    int ret = ASN1_get_object(&q, &len, &tag, &xclass, *remaining);
    if (ret & 0x80)
        return -1;
    long hdr = (long)(q - start);
    if (hdr + len > *remaining)
        return -1;
    t->start = start;
    t->content = q;
    t->content_len = len;
    t->tlv_len = hdr + len;
    t->tag = tag;
    t->xclass = xclass;
    *p = start + t->tlv_len;
    *remaining -= t->tlv_len;
    return 0;
}

typedef struct {
    unsigned char *data;
    size_t len, cap;
} buf_t;

static int buf_put(buf_t *b, const void *src, size_t n)
{
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 4096;
        while (cap < b->len + n)
            cap *= 2;
        unsigned char *d = realloc(b->data, cap);
        if (!d)
            return -1;
        b->data = d;
        b->cap = cap;
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

/* Appends tag + DER length + content to b. */
static int buf_put_tlv(buf_t *b, unsigned char tag, const unsigned char *content, size_t len)
{
    unsigned char hdr[6];
    size_t h = 0;
    hdr[h++] = tag;
    if (len < 0x80) {
        hdr[h++] = (unsigned char)len;
    } else {
        unsigned char tmp[4];
        int n = 0;
        for (size_t l = len; l > 0; l >>= 8)
            tmp[n++] = (unsigned char)(l & 0xff);
        hdr[h++] = (unsigned char)(0x80 | n);
        while (n > 0)
            hdr[h++] = tmp[--n];
    }
    if (buf_put(b, hdr, h) < 0)
        return -1;
    return buf_put(b, content, len);
}

/* DER encoding of OID 2.5.29.74 (altSignatureValue) */
static const unsigned char OID_ALT_SIG_VAL_DER[] = {0x55, 0x1d, 0x4a};

/* Builds the message signed by the alternative key (see chimera.h). */
static int build_alt_signed_message(const X509 *cert, buf_t *out)
{
    unsigned char *der = NULL;
    int der_len = i2d_X509(cert, &der); /* original encoding of a parsed cert */
    int rc = -1;
    buf_t fields = {0}, exts = {0}, wrapped = {0};
    if (der_len <= 0)
        return -1;

    const unsigned char *p = der;
    long rem = der_len;
    der_tlv certseq, tbs;
    if (der_next(&p, &rem, &certseq) < 0 || certseq.tag != V_ASN1_SEQUENCE)
        goto done;
    p = certseq.content;
    rem = certseq.content_len;
    if (der_next(&p, &rem, &tbs) < 0 || tbs.tag != V_ASN1_SEQUENCE)
        goto done;

    /* Top-level TBS fields */
    der_tlv f[16];
    int n = 0;
    p = tbs.content;
    rem = tbs.content_len;
    while (rem > 0) {
        if (n == 16 || der_next(&p, &rem, &f[n]) < 0)
            goto done;
        n++;
    }
    /* Last field must be [3] EXPLICIT Extensions */
    if (n < 8 || f[n - 1].xclass != V_ASN1_CONTEXT_SPECIFIC || f[n - 1].tag != 3)
        goto done;

    for (int i = 0; i < n - 1; i++)
        if (i != 2 && buf_put(&fields, f[i].start, (size_t)f[i].tlv_len) < 0)
            goto done;

    /* Extensions without altSignatureValue, original bytes kept */
    der_tlv extseq;
    p = f[n - 1].content;
    rem = f[n - 1].content_len;
    if (der_next(&p, &rem, &extseq) < 0 || extseq.tag != V_ASN1_SEQUENCE)
        goto done;
    p = extseq.content;
    rem = extseq.content_len;
    while (rem > 0) {
        der_tlv ext, oid;
        if (der_next(&p, &rem, &ext) < 0)
            goto done;
        const unsigned char *q = ext.content;
        long qrem = ext.content_len;
        if (der_next(&q, &qrem, &oid) < 0 || oid.tag != V_ASN1_OBJECT)
            goto done;
        int is_alt_sig_val = oid.content_len == (long)sizeof OID_ALT_SIG_VAL_DER &&
                             memcmp(oid.content, OID_ALT_SIG_VAL_DER, sizeof OID_ALT_SIG_VAL_DER) == 0;
        if (!is_alt_sig_val && buf_put(&exts, ext.start, (size_t)ext.tlv_len) < 0)
            goto done;
    }

    buf_t extseq_new = {0};
    if (buf_put_tlv(&extseq_new, 0x30, exts.data, exts.len) < 0 ||
        buf_put_tlv(&wrapped, 0xa3, extseq_new.data, extseq_new.len) < 0 ||
        buf_put(&fields, wrapped.data, wrapped.len) < 0 ||
        buf_put_tlv(out, 0x30, fields.data, fields.len) < 0) {
        free(extseq_new.data);
        goto done;
    }
    free(extseq_new.data);
    rc = 0;

done:
    free(fields.data);
    free(exts.data);
    free(wrapped.data);
    OPENSSL_free(der);
    return rc;
}

int chimera_verify_alt_signature(const X509 *cert, EVP_PKEY *issuer_alt_pkey)
{
    const unsigned char *raw;
    int raw_len;
    if (!issuer_alt_pkey || !chimera_get_extension(cert, OID_ALT_SIG_VAL, &raw, &raw_len))
        return -1;
    ASN1_BIT_STRING *sig = d2i_ASN1_BIT_STRING(NULL, &raw, raw_len);
    if (!sig)
        return -1;

    buf_t msg = {0};
    int result = -1;
    EVP_MD_CTX *ctx = NULL;
    if (build_alt_signed_message(cert, &msg) < 0)
        goto done;

    /* Pure ML-DSA: no digest, empty context */
    ctx = EVP_MD_CTX_new();
    if (!ctx || EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, issuer_alt_pkey, NULL) != 1)
        goto done;
    int rc = EVP_DigestVerify(ctx, ASN1_STRING_get0_data(sig), (size_t)ASN1_STRING_length(sig),
                              msg.data, msg.len);
    result = rc == 1 ? 1 : (rc == 0 ? 0 : -1);

done:
    EVP_MD_CTX_free(ctx);
    free(msg.data);
    ASN1_BIT_STRING_free(sig);
    return result;
}
