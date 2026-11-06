#ifndef PHC_CHIMERA_H
#define PHC_CHIMERA_H

#include <openssl/evp.h>
#include <openssl/x509.h>

/* X.509 Alternative Keys extensions (ITU-T X.509 (2019), section 9.8) */
#define OID_ALT_PUBKEY   "2.5.29.72" /* subjectAltPublicKeyInfo */
#define OID_ALT_SIG_ALG  "2.5.29.73" /* altSignatureAlgorithm   */
#define OID_ALT_SIG_VAL  "2.5.29.74" /* altSignatureValue       */

/* Raw DER content of the extension with the given OID. The returned pointer
 * belongs to the certificate and must not be freed. Returns 1 if found. */
int chimera_get_extension(const X509 *cert, const char *oid,
                          const unsigned char **out, int *out_len);

/* 1 if the certificate carries an alternative signature (2.5.29.73/74). */
int chimera_has_alt_signature(const X509 *cert);

/* 1 if the certificate carries an alternative public key (2.5.29.72). */
int chimera_has_alt_pubkey(const X509 *cert);

/* Name of the alternative signature algorithm into buf (e.g. "ML-DSA-65"). */
int chimera_alt_sig_alg_name(const X509 *cert, char *buf, size_t buf_len);

/* Alternative public key (subjectAltPublicKeyInfo) as an EVP_PKEY.
 * Caller frees it with EVP_PKEY_free. NULL if absent or not decodable. */
EVP_PKEY *chimera_load_alt_pubkey(const X509 *cert);

/* Verifies altSignatureValue of 'cert' with the issuer's alternative key.
 *
 * The signed message is NOT the TBSCertificate. Following BouncyCastle
 * (X509CertificateHolder.isAlternativeSignatureValid), it is rebuilt as
 *   SEQUENCE { every top-level TBS field except field 2 ('signature',
 *              the classic AlgorithmIdentifier) and the original extensions,
 *              [3] EXPLICIT extensions without altSignatureValue }
 * The rebuild works on the certificate's original DER bytes, so no field is
 * re-encoded.
 *
 * Returns 1 = valid, 0 = invalid, -1 = processing error. */
int chimera_verify_alt_signature(const X509 *cert, EVP_PKEY *issuer_alt_pkey);

#endif
