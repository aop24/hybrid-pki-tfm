/*
 * Common phc-client code: model detection, hybrid chain verification and the
 * TLS 1.3 mutual-authentication channel shared by phc-msg, phc-file and
 * phc-challenge.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "chimera.h"
#include "composite.h"
#include "phc.h"
#include "revocation.h"

double phc_now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1e6;
}

phc_model phc_model_of(const X509 *cert)
{
    if (chimera_has_alt_signature(cert))
        return PHC_CHIMERA;
    if (composite_is_composite_sig(cert))
        return PHC_COMPOSITE;
    const X509_ALGOR *alg = NULL;
    const ASN1_OBJECT *obj = NULL;
    char name[64];
    X509_get0_signature(NULL, &alg, cert);
    X509_ALGOR_get0(&obj, NULL, NULL, alg);
    OBJ_obj2txt(name, sizeof name, obj, 0);
    if (strncmp(name, "mldsa", 5) == 0 || strncmp(name, "ML-DSA", 6) == 0)
        return PHC_PQC_PURE;
    return PHC_CLASSIC;
}

const char *phc_model_name(phc_model m)
{
    switch (m) {
    case PHC_CHIMERA:   return "chimera";
    case PHC_COMPOSITE: return "composite";
    case PHC_PQC_PURE:  return "pqc-pure";
    default:            return "classic";
    }
}

static void subject_cn(const X509 *cert, char *buf, size_t len)
{
    buf[0] = '\0';
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, buf, (int)len);
}

int phc_verify_link(const X509 *cert, const X509 *issuer, int verbose)
{
    char cn[128];
    subject_cn(cert, cn, sizeof cn);
    phc_model m = phc_model_of(cert);

    if (m == PHC_CHIMERA) {
        char alg[64] = "?";
        chimera_alt_sig_alg_name(cert, alg, sizeof alg);
        EVP_PKEY *alt = chimera_load_alt_pubkey(issuer);
        if (!alt) {
            if (verbose)
                printf("    [%s] chimera: issuer has no usable alternative key -> INVALID\n", cn);
            return 0;
        }
        int rc = chimera_verify_alt_signature(cert, alt);
        EVP_PKEY_free(alt);
        if (verbose)
            printf("    [%s] chimera: alternative signature %s -> %s\n", cn, alg,
                   rc == 1 ? "valid" : (rc == 0 ? "INVALID" : "ERROR"));
        return rc;
    }
    if (m == PHC_COMPOSITE) {
        if (verbose)
            printf("    [%s] ", cn);
        return composite_verify_components(cert, issuer, verbose);
    }
    /* Classic or pure ML-DSA: covered by standard X.509 verification, unless
     * the issuer is a Chimera CA (alternative-signature downgrade). */
    if (chimera_has_alt_pubkey(issuer) && issuer != cert) {
        if (verbose)
            printf("    [%s] issued by a Chimera CA but has no alternative signature -> INVALID\n", cn);
        return 0;
    }
    if (verbose)
        printf("    [%s] %s: no hybrid component (standard X.509 only)\n", cn, phc_model_name(m));
    return 1;
}

int phc_verify_chain(STACK_OF(X509) *chain, int verbose)
{
    int n = sk_X509_num(chain);
    if (n <= 0)
        return 0;
    for (int i = 0; i < n; i++) {
        X509 *cert = sk_X509_value(chain, i);
        X509 *issuer = (i + 1 < n) ? sk_X509_value(chain, i + 1) : cert;
        if (phc_verify_link(cert, issuer, verbose) != 1)
            return 0;
    }
    return 1;
}

/* ---- TLS ---- */

SSL_CTX *phc_tls_ctx(int is_server, const char *cert, const char *key, const char *ca_bundle)
{
    setvbuf(stdout, NULL, _IOLBF, 0); /* keep log order when redirected */
    SSL_CTX *ctx = SSL_CTX_new(is_server ? TLS_server_method() : TLS_client_method());
    if (!ctx)
        goto err;
    /* OpenSSL's security-level tables do not know provider algorithms
     * (composite keys would be rejected as "md too weak"). */
    SSL_CTX_set_security_level(ctx, 0);
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_check_private_key(ctx) <= 0 ||
        SSL_CTX_load_verify_locations(ctx, ca_bundle, NULL) <= 0)
        goto err;
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    return ctx;
err:
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return NULL;
}

int phc_listen(int port)
{
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0)
        return -1;
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port),
                               .sin_addr.s_addr = htonl(INADDR_ANY)};
    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) < 0 || listen(srv, 4) < 0) {
        perror("bind/listen");
        close(srv);
        return -1;
    }
    return srv;
}

int phc_accept(int srv)
{
    struct sockaddr_in peer;
    socklen_t len = sizeof peer;
    int fd;
    do {
        fd = accept(srv, (struct sockaddr *)&peer, &len);
    } while (fd < 0 && errno == EINTR);
    if (fd >= 0) {
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof ip);
        printf("[server] TCP connection from %s\n", ip);
    }
    return fd;
}

int phc_connect(const char *host, int port)
{
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *res;
    char portstr[8];
    snprintf(portstr, sizeof portstr, "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        fprintf(stderr, "cannot resolve %s\n", host);
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        perror("connect");
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0)
        printf("[client] TCP connection to %s:%d\n", host, port);
    return fd;
}

SSL *phc_handshake(SSL_CTX *ctx, int fd, int is_server, const char *role, phc_metrics *m)
{
    SSL *ssl = SSL_new(ctx);
    if (!ssl)
        return NULL;
    SSL_set_fd(ssl, fd);

    double t0 = phc_now_ms();
    int rc = is_server ? SSL_accept(ssl) : SSL_connect(ssl);
    m->handshake_ms = phc_now_ms() - t0;
    if (rc <= 0) {
        fprintf(stderr, "[%s] TLS handshake failed\n", role);
        long vr = SSL_get_verify_result(ssl);
        if (vr != X509_V_OK)
            fprintf(stderr, "[%s] certificate verification: %s\n", role, X509_verify_cert_error_string(vr));
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return NULL;
    }

    X509 *peer = SSL_get0_peer_certificate(ssl);
    STACK_OF(X509) *chain = SSL_get0_verified_chain(ssl);
    char subj[256];
    X509_NAME_oneline(X509_get_subject_name(peer), subj, sizeof subj);
    m->peer_model = phc_model_of(peer);
    m->peer_cert_der = i2d_X509(peer, NULL);
    printf("[%s] TLS handshake OK: %s, %s, peer %s (%s, %d B DER)\n", role,
           SSL_get_version(ssl), SSL_get_cipher(ssl), subj,
           phc_model_name(m->peer_model), m->peer_cert_der);

    printf("[%s] Hybrid verification of the peer chain (%d certificates):\n", role, sk_X509_num(chain));
    t0 = phc_now_ms();
    int ok = phc_verify_chain(chain, 1);
    m->hybrid_ms = phc_now_ms() - t0;
    printf("[%s] Hybrid verification: %s\n", role, ok ? "VALID" : "FAILED - closing connection");
    m->revocation_ms = 0;
    if (ok && strcmp(phc_revocation_mode(), "none") != 0)
        ok = !phc_peer_revocation(ssl, role, &m->revocation_ms);
    printf("[metrics] role=%s model=%s handshake_ms=%.2f hybrid_verify_ms=%.2f revocation=%s revocation_ms=%.2f peer_cert_der=%d\n",
           role, phc_model_name(m->peer_model), m->handshake_ms, m->hybrid_ms, phc_revocation_mode(),
           m->revocation_ms, m->peer_cert_der);
    if (!ok) {
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

void phc_close(SSL *ssl, int fd)
{
    if (ssl) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (fd >= 0)
        close(fd);
}

int phc_write_all(SSL *ssl, const void *buf, size_t len)
{
    const unsigned char *p = buf;
    while (len > 0) {
        int n = SSL_write(ssl, p, len > 1 << 30 ? 1 << 30 : (int)len);
        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int phc_read_all(SSL *ssl, void *buf, size_t len)
{
    unsigned char *p = buf;
    while (len > 0) {
        int n = SSL_read(ssl, p, len > 1 << 30 ? 1 << 30 : (int)len);
        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

int phc_write_u32(SSL *ssl, unsigned int v)
{
    uint32_t be = htonl(v);
    return phc_write_all(ssl, &be, 4);
}

int phc_read_u32(SSL *ssl, unsigned int *v)
{
    uint32_t be;
    if (phc_read_all(ssl, &be, 4) < 0)
        return -1;
    *v = ntohl(be);
    return 0;
}

int phc_peer_revocation(SSL *ssl, const char *role, double *ms)
{
    STACK_OF(X509) *chain = SSL_get0_verified_chain(ssl);
    X509 *leaf = SSL_get0_peer_certificate(ssl);
    X509 *issuer = (chain && sk_X509_num(chain) > 1) ? sk_X509_value(chain, 1) : NULL;
    phc_rev_result r;
    if (!leaf || !issuer) {
        printf("[%s] Revocation (%s): no issuer in the verified chain\n", role, phc_revocation_mode());
        return phc_revocation_hard_fail();
    }
    phc_check_revocation(leaf, issuer, SSL_CTX_get_cert_store(SSL_get_SSL_CTX(ssl)), &r);
    if (ms)
        *ms = r.ms;
    char tu[32] = "-", nu[32] = "-";
    if (r.this_update)
        strftime(tu, sizeof tu, "%H:%M:%S", gmtime(&r.this_update));
    if (r.next_update)
        strftime(nu, sizeof nu, "%Y-%m-%d %H:%M:%S", gmtime(&r.next_update));
    int reject = phc_revocation_rejects(&r);
    printf("[%s] Revocation (%s, %s-fail): %s (%.2f ms; thisUpdate %s, nextUpdate %s UTC; %s)%s\n", role,
           phc_revocation_mode(), phc_revocation_hard_fail() ? "hard" : "soft", phc_rev_status_name(r.status),
           r.ms, tu, nu, r.detail, reject ? " -> REJECTING PEER" : "");
    return reject;
}
