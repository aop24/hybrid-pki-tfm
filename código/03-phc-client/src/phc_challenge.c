/*
 * phc-challenge: challenge-response proof of possession of the private key
 * over TLS 1.3 with mutual authentication and hybrid verification.
 *
 * The verifier sends a random 32-byte nonce. The prover signs
 *   "PHC-CHALLENGE-v2" || nonce || TLS exporter (32 bytes)
 * with its private key; the verifier checks it with the public key of the
 * certificate presented in the handshake. The TLS exporter (RFC 8446 7.5)
 * binds the response to this TLS session, so it cannot be relayed into
 * another connection.
 *
 * Usage:
 *   phc-challenge server <port> <cert> <key> <ca-bundle>          (verifier)
 *   phc-challenge client <host> <port> <cert> <key> <ca-bundle>   (prover)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "phc.h"

#define NONCE_LEN    32
#define EXPORTER_LEN 32
#define MAX_SIG      (64 * 1024)
static const char LABEL[] = "PHC-CHALLENGE-v2";
static const char EXPORTER_LABEL[] = "EXPORTER-phc-challenge";

/* Message to sign: label || nonce || exporter */
static int build_message(SSL *ssl, const unsigned char *nonce, unsigned char *msg, size_t *len)
{
    unsigned char exp[EXPORTER_LEN];
    if (SSL_export_keying_material(ssl, exp, sizeof exp, EXPORTER_LABEL, strlen(EXPORTER_LABEL),
                                   NULL, 0, 0) != 1)
        return -1;
    size_t l = strlen(LABEL);
    memcpy(msg, LABEL, l);
    memcpy(msg + l, nonce, NONCE_LEN);
    memcpy(msg + l + NONCE_LEN, exp, EXPORTER_LEN);
    *len = l + NONCE_LEN + EXPORTER_LEN;
    return 0;
}

static int prover(SSL *ssl, const char *key_path)
{
    unsigned char nonce[NONCE_LEN], msg[128];
    size_t msg_len;
    if (phc_read_all(ssl, nonce, NONCE_LEN) < 0 || build_message(ssl, nonce, msg, &msg_len) < 0) {
        fprintf(stderr, "[prover] cannot receive the challenge\n");
        return -1;
    }
    printf("[prover] Challenge received (%d bytes), bound to the TLS session.\n", NONCE_LEN);

    FILE *f = fopen(key_path, "r");
    EVP_PKEY *pkey = f ? PEM_read_PrivateKey(f, NULL, NULL, NULL) : NULL;
    if (f)
        fclose(f);
    if (!pkey) {
        fprintf(stderr, "[prover] cannot load private key\n");
        return -1;
    }
    /* Default digest of the key type (SHA-256 for EC/RSA, none for ML-DSA and composites) */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t sig_len = 0;
    unsigned char *sig = NULL;
    double t0 = phc_now_ms();
    int ok = EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, NULL) == 1 &&
             EVP_DigestSign(ctx, NULL, &sig_len, msg, msg_len) == 1 &&
             (sig = malloc(sig_len)) != NULL &&
             EVP_DigestSign(ctx, sig, &sig_len, msg, msg_len) == 1;
    double ms = phc_now_ms() - t0;
    printf("[prover] Signed with %s key: %zu-byte signature (%.2f ms)\n", EVP_PKEY_get0_type_name(pkey), sig_len, ms);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    if (!ok) {
        ERR_print_errors_fp(stderr);
        free(sig);
        return -1;
    }
    int rc = phc_write_u32(ssl, (unsigned int)sig_len) || phc_write_all(ssl, sig, sig_len) ? -1 : 0;
    free(sig);

    char verdict[64] = {0};
    unsigned int vlen;
    if (!rc && phc_read_u32(ssl, &vlen) == 0 && vlen < sizeof verdict && phc_read_all(ssl, verdict, vlen) == 0)
        printf("[prover] Verifier verdict: %s\n", verdict);
    printf("[metrics] role=prover sig_bytes=%zu sign_ms=%.2f\n", sig_len, ms);
    return rc;
}

static int verifier(SSL *ssl)
{
    unsigned char nonce[NONCE_LEN], msg[128];
    size_t msg_len;
    if (RAND_bytes(nonce, NONCE_LEN) != 1 || build_message(ssl, nonce, msg, &msg_len) < 0 ||
        phc_write_all(ssl, nonce, NONCE_LEN) < 0)
        return -1;
    printf("[verifier] Challenge sent (%d random bytes).\n", NONCE_LEN);

    unsigned int sig_len;
    if (phc_read_u32(ssl, &sig_len) < 0 || sig_len == 0 || sig_len > MAX_SIG)
        return -1;
    unsigned char *sig = malloc(sig_len);
    if (!sig || phc_read_all(ssl, sig, sig_len) < 0) {
        free(sig);
        return -1;
    }

    EVP_PKEY *pub = X509_get0_pubkey(SSL_get0_peer_certificate(ssl));
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    double t0 = phc_now_ms();
    int rc = EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pub, NULL) == 1
                 ? EVP_DigestVerify(ctx, sig, sig_len, msg, msg_len) : -1;
    double ms = phc_now_ms() - t0;
    EVP_MD_CTX_free(ctx);
    free(sig);

    const char *verdict = rc == 1 ? "VALID" : "INVALID";
    printf("[verifier] Response: %u-byte %s signature, verified with the peer certificate key (%.2f ms)\n",
           sig_len, EVP_PKEY_get0_type_name(pub), ms);
    printf("[verifier] RESULT: challenge-response %s%s\n", verdict,
           rc == 1 ? " - the peer holds the private key of its certificate" : "");
    printf("[metrics] role=verifier sig_bytes=%u verify_ms=%.2f\n", sig_len, ms);
    phc_write_u32(ssl, (unsigned int)strlen(verdict));
    phc_write_all(ssl, verdict, strlen(verdict));
    return rc == 1 ? 0 : -1;
}

int main(int argc, char **argv)
{
    int is_server = argc == 6 && strcmp(argv[1], "server") == 0;
    int is_client = argc == 7 && strcmp(argv[1], "client") == 0;
    if (!is_server && !is_client) {
        fprintf(stderr, "usage:\n  %s server <port> <cert> <key> <ca-bundle>          (verifier)\n"
                        "  %s client <host> <port> <cert> <key> <ca-bundle>   (prover)\n", argv[0], argv[0]);
        return 2;
    }
    const char *role = is_server ? "verifier" : "prover";
    int a = is_server ? 3 : 4;
    SSL_CTX *ctx = phc_tls_ctx(is_server, argv[a], argv[a + 1], argv[a + 2]);
    if (!ctx)
        return 1;

    int srv = -1, fd;
    if (is_server) {
        srv = phc_listen(atoi(argv[2]));
        if (srv < 0)
            return 1;
        printf("[verifier] Listening on port %s...\n", argv[2]);
        fd = phc_accept(srv);
    } else {
        fd = phc_connect(argv[2], atoi(argv[3]));
    }
    if (fd < 0)
        return 1;

    phc_metrics m;
    SSL *ssl = phc_handshake(ctx, fd, is_server, role, &m);
    int rc = 1;
    if (ssl)
        rc = (is_server ? verifier(ssl) : prover(ssl, argv[a + 1])) == 0 ? 0 : 1;

    phc_close(ssl, fd);
    if (srv >= 0)
        phc_close(NULL, srv);
    SSL_CTX_free(ctx);
    return rc;
}
