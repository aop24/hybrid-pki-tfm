/*
 * Composite (oqs-provider) support: split of composite signatures/keys and
 * independent verification of each component.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/x509.h>

#include "composite.h"

int composite_split(const unsigned char *data, int data_len,
                    const unsigned char **classic, int *classic_len,
                    const unsigned char **pq, int *pq_len)
{
    if (!data || data_len < 4)
        return -1;
    uint32_t len = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                   ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    if (len == 0 || (long)len + 4 >= (long)data_len)
        return -1;
    *classic = data + 4;
    *classic_len = (int)len;
    *pq = data + 4 + len;
    *pq_len = data_len - 4 - (int)len;
    return 0;
}

static void sig_alg_name(const X509 *cert, char *buf, size_t len)
{
    const X509_ALGOR *alg = NULL;
    const ASN1_OBJECT *obj = NULL;
    X509_get0_signature(NULL, &alg, cert);
    X509_ALGOR_get0(&obj, NULL, NULL, alg);
    OBJ_obj2txt(buf, (int)len, obj, 0);
}

/* Component parameters derived from an oqs-provider name like "p384_mldsa65". */
struct comp_params {
    const char *curve;  /* OpenSSL group name */
    const char *digest; /* hash used by the classic component */
    char mldsa[16];     /* oqs-provider ML-DSA name */
};

static int parse_composite_name(const char *name, struct comp_params *cp)
{
    const char *us = strchr(name, '_');
    if (!us || strncmp(us + 1, "mldsa", 5) != 0)
        return -1;
    size_t plen = (size_t)(us - name);
    if (plen == 4 && strncmp(name, "p256", 4) == 0) {
        cp->curve = "P-256";
        cp->digest = "SHA256";
    } else if (plen == 4 && strncmp(name, "p384", 4) == 0) {
        cp->curve = "P-384";
        cp->digest = "SHA384";
    } else if (plen == 4 && strncmp(name, "p521", 4) == 0) {
        cp->curve = "P-521";
        cp->digest = "SHA512";
    } else {
        return -1; /* only ECDSA-based composites are used in the lab */
    }
    snprintf(cp->mldsa, sizeof cp->mldsa, "%s", us + 1);
    return 0;
}

int composite_is_composite_sig(const X509 *cert)
{
    char name[64];
    sig_alg_name(cert, name, sizeof name);
    const char *us = strchr(name, '_');
    return us && strncmp(us + 1, "mldsa", 5) == 0;
}

/* Original DER bytes of the TBSCertificate (no re-encoding). */
static int original_tbs(const X509 *cert, unsigned char **out, long *out_len)
{
    unsigned char *der = NULL;
    int der_len = i2d_X509(cert, &der);
    if (der_len <= 0)
        return -1;
    const unsigned char *p = der, *start;
    long len;
    int tag, xclass;
    if ((ASN1_get_object(&p, &len, &tag, &xclass, der_len) & 0x80) || tag != V_ASN1_SEQUENCE)
        goto fail;
    start = p;
    long rem = len;
    if ((ASN1_get_object(&p, &len, &tag, &xclass, rem) & 0x80) || tag != V_ASN1_SEQUENCE)
        goto fail;
    long tlv_len = (long)(p - start) + len;
    if (tlv_len > rem || !(*out = OPENSSL_malloc((size_t)tlv_len)))
        goto fail;
    memcpy(*out, start, (size_t)tlv_len);
    *out_len = tlv_len;
    OPENSSL_free(der);
    return 0;
fail:
    OPENSSL_free(der);
    return -1;
}

static EVP_PKEY *key_from_data(const char *type, OSSL_PARAM *params)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);
    if (pctx && EVP_PKEY_fromdata_init(pctx) > 0)
        EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

static int verify_with(EVP_PKEY *pkey, const char *digest,
                       const unsigned char *sig, size_t sig_len,
                       const unsigned char *msg, size_t msg_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int rc = -1;
    if (ctx && EVP_DigestVerifyInit_ex(ctx, NULL, digest, NULL, NULL, pkey, NULL) == 1)
        rc = EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len);
    EVP_MD_CTX_free(ctx);
    return rc == 1 ? 1 : (rc == 0 ? 0 : -1);
}

int composite_verify_components(const X509 *cert, const X509 *issuer, int verbose)
{
    char name[64];
    struct comp_params cp;
    sig_alg_name(cert, name, sizeof name);
    if (parse_composite_name(name, &cp) < 0)
        return -1;

    const ASN1_BIT_STRING *sig;
    X509_get0_signature(&sig, NULL, cert);
    const unsigned char *s_cl, *s_pq;
    int s_cl_len, s_pq_len;
    if (composite_split(ASN1_STRING_get0_data(sig), ASN1_STRING_length(sig),
                        &s_cl, &s_cl_len, &s_pq, &s_pq_len) < 0)
        return -1;

    const unsigned char *pk;
    int pk_len;
    X509_PUBKEY_get0_param(NULL, &pk, &pk_len, NULL, X509_get_X509_PUBKEY(issuer));
    const unsigned char *k_cl, *k_pq;
    int k_cl_len, k_pq_len;
    if (composite_split(pk, pk_len, &k_cl, &k_cl_len, &k_pq, &k_pq_len) < 0)
        return -1;

    unsigned char *tbs = NULL;
    long tbs_len = 0;
    if (original_tbs(cert, &tbs, &tbs_len) < 0)
        return -1;

    OSSL_PARAM ec_params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char *)cp.curve, 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)k_cl, (size_t)k_cl_len),
        OSSL_PARAM_construct_end()};
    OSSL_PARAM pq_params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, (void *)k_pq, (size_t)k_pq_len),
        OSSL_PARAM_construct_end()};
    EVP_PKEY *ec = key_from_data("EC", ec_params);
    EVP_PKEY *pq = key_from_data(cp.mldsa, pq_params);

    int ec_rc = ec ? verify_with(ec, cp.digest, s_cl, (size_t)s_cl_len, tbs, (size_t)tbs_len) : -1;
    int pq_rc = pq ? verify_with(pq, NULL, s_pq, (size_t)s_pq_len, tbs, (size_t)tbs_len) : -1;

    if (verbose) {
        printf("composite %s: classic ECDSA %s/%s (sig %d B) -> %s; %s (sig %d B) -> %s\n",
               name, cp.curve, cp.digest, s_cl_len, ec_rc == 1 ? "valid" : "INVALID",
               cp.mldsa, s_pq_len, pq_rc == 1 ? "valid" : "INVALID");
    }

    EVP_PKEY_free(ec);
    EVP_PKEY_free(pq);
    OPENSSL_free(tbs);
    if (ec_rc < 0 || pq_rc < 0)
        return -1;
    return (ec_rc == 1 && pq_rc == 1) ? 1 : 0;
}
