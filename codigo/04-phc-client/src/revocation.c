/*
 * Revocation checking of the peer end-entity certificate (OCSP or CRL).
 * See include/revocation.h for the configuration.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/http.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "phc.h"
#include "revocation.h"

#define HTTP_TIMEOUT_S 5
#define MAX_RESP       (1024 * 1024)

const char *phc_revocation_mode(void)
{
    const char *m = getenv("PHC_REVOCATION");
    if (m && strcmp(m, "ocsp") == 0)
        return "ocsp";
    if (m && strcmp(m, "crl") == 0)
        return "crl";
    return "none";
}

int phc_revocation_hard_fail(void)
{
    const char *f = getenv("PHC_FAIL");
    return !(f && strcmp(f, "soft") == 0);
}

const char *phc_rev_status_name(phc_rev_status s)
{
    switch (s) {
    case PHC_REV_GOOD:    return "good";
    case PHC_REV_REVOKED: return "REVOKED";
    case PHC_REV_UNKNOWN: return "unknown";
    default:              return "unavailable";
    }
}

int phc_revocation_rejects(const phc_rev_result *r)
{
    if (r->status == PHC_REV_REVOKED)
        return 1;
    if (r->status == PHC_REV_GOOD)
        return 0;
    return phc_revocation_hard_fail();
}

static time_t asn1_to_epoch(const ASN1_TIME *t)
{
    struct tm tm;
    if (!t || ASN1_TIME_to_tm(t, &tm) != 1)
        return 0;
    return timegm(&tm);
}

static void set_detail(phc_rev_result *r, const char *fmt, const char *arg)
{
    snprintf(r->detail, sizeof r->detail, fmt, arg ? arg : "");
}

/* ---------------- OCSP ---------------- */

static char *ocsp_url(X509 *leaf)
{
    const char *u = getenv("PHC_OCSP_URL");
    if (u && *u)
        return OPENSSL_strdup(u);
    STACK_OF(OPENSSL_STRING) *aia = X509_get1_ocsp(leaf);
    char *res = (aia && sk_OPENSSL_STRING_num(aia) > 0) ? OPENSSL_strdup(sk_OPENSSL_STRING_value(aia, 0)) : NULL;
    X509_email_free(aia);
    return res;
}

static void check_ocsp(X509 *leaf, X509 *issuer, X509_STORE *store, phc_rev_result *r)
{
    char *url = ocsp_url(leaf), *host = NULL, *port = NULL, *path = NULL;
    int use_ssl = 0;
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *resp = NULL;
    OCSP_BASICRESP *bs = NULL;
    BIO *reqbio = NULL, *respbio = NULL;
    OCSP_CERTID *id = NULL;

    r->status = PHC_REV_ERROR;
    if (!url) {
        set_detail(r, "no OCSP URL (set PHC_OCSP_URL)", NULL);
        goto done;
    }
    if (!OSSL_HTTP_parse_url(url, &use_ssl, NULL, &host, &port, NULL, &path, NULL, NULL)) {
        set_detail(r, "invalid OCSP URL %s", url);
        goto done;
    }
    req = OCSP_REQUEST_new();
    id = OCSP_cert_to_id(NULL, leaf, issuer);
    if (!req || !id || !OCSP_request_add0_id(req, id)) {
        set_detail(r, "cannot build OCSP request", NULL);
        goto done;
    }
    OCSP_CERTID *id_ref = id;
    id = NULL; /* owned by req now */
    OCSP_request_add1_nonce(req, NULL, -1);

    reqbio = BIO_new(BIO_s_mem());
    if (!reqbio || i2d_OCSP_REQUEST_bio(reqbio, req) <= 0)
        goto done;
    respbio = OSSL_HTTP_transfer(NULL, host, port, path, use_ssl, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL,
                                 "application/ocsp-request", reqbio, "application/ocsp-response", 1,
                                 MAX_RESP, HTTP_TIMEOUT_S, 0);
    if (!respbio || !(resp = d2i_OCSP_RESPONSE_bio(respbio, NULL))) {
        set_detail(r, "OCSP responder %s not reachable or bad response", url);
        goto done;
    }
    if (OCSP_response_status(resp) != OCSP_RESPONSE_STATUS_SUCCESSFUL || !(bs = OCSP_response_get1_basic(resp))) {
        set_detail(r, "OCSP response status not successful", NULL);
        goto done;
    }
    if (OCSP_check_nonce(req, bs) <= 0) {
        set_detail(r, "OCSP nonce missing or different", NULL);
        goto done;
    }
    if (OCSP_basic_verify(bs, NULL, store, 0) <= 0) {
        set_detail(r, "OCSP response signature/signer not valid", NULL);
        goto done;
    }
    int status, reason;
    ASN1_GENERALIZEDTIME *rev = NULL, *thisupd = NULL, *nextupd = NULL;
    if (!OCSP_resp_find_status(bs, id_ref, &status, &reason, &rev, &thisupd, &nextupd)) {
        set_detail(r, "certificate not in OCSP response", NULL);
        goto done;
    }
    if (!OCSP_check_validity(thisupd, nextupd, 300, -1)) {
        set_detail(r, "OCSP response outside its validity period", NULL);
        goto done;
    }
    r->this_update = asn1_to_epoch(thisupd);
    r->next_update = asn1_to_epoch(nextupd);
    if (status == V_OCSP_CERTSTATUS_GOOD) {
        r->status = PHC_REV_GOOD;
        set_detail(r, "OCSP %s", url);
    } else if (status == V_OCSP_CERTSTATUS_REVOKED) {
        r->status = PHC_REV_REVOKED;
        snprintf(r->detail, sizeof r->detail, "OCSP %s, reason %s", url,
                 reason >= 0 ? OCSP_crl_reason_str(reason) : "unspecified");
    } else {
        r->status = PHC_REV_UNKNOWN;
        set_detail(r, "OCSP %s answered unknown", url);
    }

done:
    ERR_clear_error();
    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(bs);
    OCSP_RESPONSE_free(resp);
    OCSP_REQUEST_free(req);
    BIO_free(reqbio);
    BIO_free(respbio);
    OPENSSL_free(url);
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
}

/* ---------------- CRL ---------------- */

static char *crl_url(X509 *leaf)
{
    const char *u = getenv("PHC_CRL_URL");
    if (u && *u)
        return OPENSSL_strdup(u);
    STACK_OF(DIST_POINT) *dps = X509_get_ext_d2i(leaf, NID_crl_distribution_points, NULL, NULL);
    char *res = NULL;
    for (int i = 0; dps && !res && i < sk_DIST_POINT_num(dps); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(dps, i);
        if (!dp->distpoint || dp->distpoint->type != 0)
            continue;
        GENERAL_NAMES *gns = dp->distpoint->name.fullname;
        for (int j = 0; !res && j < sk_GENERAL_NAME_num(gns); j++) {
            GENERAL_NAME *gn = sk_GENERAL_NAME_value(gns, j);
            if (gn->type == GEN_URI)
                res = OPENSSL_strdup((const char *)ASN1_STRING_get0_data(gn->d.uniformResourceIdentifier));
        }
    }
    sk_DIST_POINT_pop_free(dps, DIST_POINT_free);
    return res;
}

static void cache_path(const char *url, char *out, size_t len)
{
    const char *dir = getenv("PHC_CRL_CACHE");
    char def[512];
    if (!dir || !*dir) {
        snprintf(def, sizeof def, "%s/.cache/phc", getenv("HOME") ? getenv("HOME") : "/tmp");
        dir = def;
    }
    mkdir(dir, 0700);
    unsigned char md[32];
    unsigned int mdlen;
    EVP_Digest(url, strlen(url), md, &mdlen, EVP_sha256(), NULL);
    snprintf(out, len, "%s/crl-%02x%02x%02x%02x%02x%02x.der", dir, md[0], md[1], md[2], md[3], md[4], md[5]);
}

static X509_CRL *load_crl_file(const char *path, time_t *mtime)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    X509_CRL *crl = d2i_X509_CRL_fp(f, NULL);
    struct stat st;
    if (crl && fstat(fileno(f), &st) == 0)
        *mtime = st.st_mtime;
    fclose(f);
    return crl;
}

static void check_crl(X509 *leaf, X509 *issuer, phc_rev_result *r)
{
    char *url = crl_url(leaf), path[600];
    X509_CRL *crl = NULL;
    BIO *bio = NULL;
    r->status = PHC_REV_ERROR;
    if (!url) {
        set_detail(r, "no CRL URL (set PHC_CRL_URL)", NULL);
        goto done;
    }
    cache_path(url, path, sizeof path);
    time_t now = time(NULL), mtime = 0;
    const char *ma = getenv("PHC_CRL_MAXAGE");
    long maxage = ma ? atol(ma) : -1;

    crl = load_crl_file(path, &mtime);
    if (crl) {
        time_t next = asn1_to_epoch(X509_CRL_get0_nextUpdate(crl));
        if ((next && now >= next) || (maxage >= 0 && now - mtime >= maxage)) {
            X509_CRL_free(crl);
            crl = NULL;
        } else {
            r->from_cache = 1;
        }
    }
    if (!crl) {
        bio = OSSL_HTTP_get(url, NULL, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, 1, MAX_RESP, HTTP_TIMEOUT_S);
        if (!bio || !(crl = d2i_X509_CRL_bio(bio, NULL))) {
            set_detail(r, "CRL %s not reachable or not a DER CRL", url);
            goto done;
        }
        FILE *f = fopen(path, "wb");
        if (f) {
            i2d_X509_CRL_fp(f, crl);
            fclose(f);
        }
    }
    if (X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_get_subject_name(issuer)) != 0 ||
        X509_CRL_verify(crl, X509_get0_pubkey(issuer)) != 1) {
        set_detail(r, "CRL issuer or signature not valid", NULL);
        goto done;
    }
    r->this_update = asn1_to_epoch(X509_CRL_get0_lastUpdate(crl));
    r->next_update = asn1_to_epoch(X509_CRL_get0_nextUpdate(crl));
    if (r->next_update && now > r->next_update) {
        set_detail(r, "CRL expired (nextUpdate passed)", NULL);
        goto done;
    }
    X509_REVOKED *rev = NULL;
    if (X509_CRL_get0_by_cert(crl, &rev, leaf) == 1) {
        r->status = PHC_REV_REVOKED;
        snprintf(r->detail, sizeof r->detail, "CRL %s (%s)", url, r->from_cache ? "cached" : "downloaded");
    } else {
        r->status = PHC_REV_GOOD;
        snprintf(r->detail, sizeof r->detail, "CRL %s (%s)", url, r->from_cache ? "cached" : "downloaded");
    }

done:
    ERR_clear_error();
    X509_CRL_free(crl);
    BIO_free(bio);
    OPENSSL_free(url);
}

phc_rev_status phc_check_revocation(X509 *leaf, X509 *issuer, X509_STORE *store, phc_rev_result *r)
{
    memset(r, 0, sizeof *r);
    double t0 = phc_now_ms();
    const char *mode = phc_revocation_mode();
    if (strcmp(mode, "ocsp") == 0)
        check_ocsp(leaf, issuer, store, r);
    else if (strcmp(mode, "crl") == 0)
        check_crl(leaf, issuer, r);
    else {
        r->status = PHC_REV_GOOD;
        set_detail(r, "revocation checking disabled", NULL);
    }
    r->ms = phc_now_ms() - t0;
    return r->status;
}
