#ifndef PHC_H
#define PHC_H

#include <stddef.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

typedef enum {
    PHC_CLASSIC,
    PHC_CHIMERA,
    PHC_COMPOSITE,
    PHC_PQC_PURE
} phc_model;

phc_model phc_model_of(const X509 *cert);
const char *phc_model_name(phc_model m);

/* Hybrid check of one chain link (cert signed by issuer; issuer == cert for a
 * self-signed root). Chimera: alternative ML-DSA signature with the issuer's
 * alternative key; a missing alternative signature under an issuer that has
 * an alternative key is rejected (downgrade). Composite: component-by-component
 * verification. Classic / pure ML-DSA: nothing beyond standard X.509.
 * Returns 1 = valid, 0 = invalid, -1 = error. */
int phc_verify_link(const X509 *cert, const X509 *issuer, int verbose);

/* Applies phc_verify_link to every link of an already X.509-verified chain
 * (leaf first, trust anchor last). Returns 1 only if every link is valid. */
int phc_verify_chain(STACK_OF(X509) *chain, int verbose);

/* ---- TLS 1.3 mutual authentication ---- */

typedef struct {
    double handshake_ms;
    double hybrid_ms;
    int peer_cert_der;
    phc_model peer_model;
} phc_metrics;

SSL_CTX *phc_tls_ctx(int is_server, const char *cert, const char *key, const char *ca_bundle);
int phc_listen(int port);
int phc_accept(int srv);
int phc_connect(const char *host, int port);

/* Runs the TLS handshake on fd, then the hybrid verification of the peer's
 * verified chain. Returns the SSL object, or NULL (connection must be closed)
 * if the handshake or the hybrid verification fails. */
SSL *phc_handshake(SSL_CTX *ctx, int fd, int is_server, const char *role, phc_metrics *m);

void phc_close(SSL *ssl, int fd);

int phc_write_all(SSL *ssl, const void *buf, size_t len);
int phc_read_all(SSL *ssl, void *buf, size_t len);
int phc_write_u32(SSL *ssl, unsigned int v);
int phc_read_u32(SSL *ssl, unsigned int *v);

double phc_now_ms(void);

#endif
