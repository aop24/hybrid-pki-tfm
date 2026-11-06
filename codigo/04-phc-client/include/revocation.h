#ifndef PHC_REVOCATION_H
#define PHC_REVOCATION_H

#include <time.h>
#include <openssl/x509.h>

/*
 * Revocation checking of the peer end-entity certificate (phc-client v2.3).
 * Configured through environment variables, so that the default behaviour is
 * exactly the one of v2.2 (no checking):
 *
 *   PHC_REVOCATION   none (default) | ocsp | crl
 *   PHC_FAIL         hard (default): an unavailable responder/CRL rejects the peer
 *                    soft: it is reported and the peer is accepted
 *   PHC_OCSP_URL     OCSP responder (otherwise the AIA OCSP URL of the certificate)
 *   PHC_CRL_URL      CRL of the issuing CA (otherwise the first CRL distribution point)
 *   PHC_CRL_CACHE    directory of the CRL cache (default $HOME/.cache/phc)
 *   PHC_CRL_MAXAGE   seconds after which a cached CRL is downloaded again even if its
 *                    nextUpdate has not been reached (default: only at nextUpdate)
 */

typedef enum {
    PHC_REV_GOOD,
    PHC_REV_REVOKED,
    PHC_REV_UNKNOWN,  /* responder answered "unknown" */
    PHC_REV_ERROR     /* responder/CRL unavailable or response not valid */
} phc_rev_status;

typedef struct {
    phc_rev_status status;
    double ms;               /* time spent in the check */
    time_t this_update;      /* of the OCSP response or CRL used (0 if none) */
    time_t next_update;
    int from_cache;          /* CRL taken from the local cache */
    char detail[256];
} phc_rev_result;

const char *phc_revocation_mode(void);   /* "none", "ocsp" or "crl" */
int phc_revocation_hard_fail(void);
const char *phc_rev_status_name(phc_rev_status s);

/* Checks the revocation status of leaf (issued by issuer) with the configured
 * method. store is used to verify the OCSP response signer. Returns r->status. */
phc_rev_status phc_check_revocation(X509 *leaf, X509 *issuer, X509_STORE *store, phc_rev_result *r);

/* 1 if the peer must be rejected given the result and the fail policy. */
int phc_revocation_rejects(const phc_rev_result *r);

#endif
