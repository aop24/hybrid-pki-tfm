#ifndef PHC_COMPOSITE_H
#define PHC_COMPOSITE_H

#include <openssl/x509.h>

/* oqs-provider composite encoding (signature and public key alike):
 *   [4 bytes: classic component length, big-endian]
 *   [classic component: ECDSA DER signature / uncompressed EC point]
 *   [ML-DSA component, raw]
 * data/data_len are the BIT STRING contents as returned by OpenSSL
 * (without the unused-bits byte). Returns 0 on success. */
int composite_split(const unsigned char *data, int data_len,
                    const unsigned char **classic, int *classic_len,
                    const unsigned char **pq, int *pq_len);

/* 1 if the certificate signature algorithm is an oqs-provider composite
 * (e.g. p384_mldsa65), as opposed to classic or pure ML-DSA. */
int composite_is_composite_sig(const X509 *cert);

/* Verifies the signature of 'cert' component by component with the issuer's
 * composite public key: the classic part with ECDSA (curve and hash taken from
 * the algorithm name) and the ML-DSA part as pure ML-DSA, both over the
 * unmodified TBSCertificate. Independent of oqs-provider's composite verifier.
 * Returns 1 = both valid, 0 = any invalid, -1 = processing error. */
int composite_verify_components(const X509 *cert, const X509 *issuer, int verbose);

#endif
