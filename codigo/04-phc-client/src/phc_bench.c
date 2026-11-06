/*
 * phc-bench: performance measurements for block 13 (RNF1).
 *
 *   phc-bench sig <alg> <n> <warmup> <csv>
 *       Sign and verify a 1024-byte message with a fresh key of <alg>:
 *       rsa4096 | ecdsa-p256 | ecdsa-p384 | ecdsa-p521 | mldsa65 | mldsa87 | p384_mldsa65 | p521_mldsa87
 *       (ECDSA P-384/P-521 with SHA-384/SHA-512: the classic components of the composites)
 *
 *   phc-bench verify <model> <cert> <ca-bundle> <n> <warmup> <csv>
 *       Per iteration: standard X.509 chain validation (X509_verify_cert, root
 *       self-signature included) and phc hybrid verification of the same chain.
 *
 *   phc-bench tls-server <port> <cert> <key> <ca-bundle>
 *       Accepts connections forever: TLS 1.3 handshake, hybrid verification of
 *       the client chain, close.
 *       PHC_BENCH_WORKERS=W (block 16, default 1): W pre-forked processes accept on the
 *       same socket, so up to W handshakes are served in parallel. The listen backlog
 *       is raised to 512 so that concurrent clients queue instead of having their SYN
 *       dropped (phc_listen uses 4).
 *
 *   phc-bench tls-client <model> <host> <port> <cert> <key> <ca-bundle> <n> <warmup> <csv>
 *       n full handshakes (new TCP connection, no resumption, X25519 only):
 *       TCP connect, TLS handshake, hybrid verification of the server chain and
 *       bytes exchanged during the handshake.
 *
 *   phc-bench revpoll <model> <cert> <ca-bundle> <interval_ms> <max_s> <csv>
 *       Block 14: checks the revocation status of <cert> every interval_ms with the
 *       method of PHC_REVOCATION (ocsp | crl), writing a wall-clock timestamp (UTC, ms)
 *       per check. Stops after 3 consecutive "REVOKED" results or after max_s seconds.
 *
 *   phc-bench revcheck <model> <cert> <ca-bundle> <n> <warmup> <csv>
 *       Block 14: cost of one revocation check (n checks, same method).
 *
 * PHC_BENCH_PAUSE_MS (tls-client): pause between handshakes, so that the server
 *   finishes the work of the previous connection (hybrid verification of the
 *   client chain) before the next one starts. Default 0. Recorded in the CSV.
 *
 * Chain sent in TLS (server and client), environment variable PHC_CHAIN:
 *   auto      (default, as phc-msg/file/challenge) OpenSSL builds the chain from
 *             the trust store and sends leaf + intermediate + root.
 *   explicit  SSL_MODE_NO_AUTO_CHAIN: exactly the certificates of <cert>
 *             (give a file with leaf + intermediate).
 *
 * Phases written to the CSV: "warmup" for the first <warmup> iterations,
 * "measure" for the rest. With n = 1 and warmup = 0 the single sample is
 * labelled "cold" (first operation of a fresh process).
 * Rows are appended; the header is written only if the file is new.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "phc.h"
#include "revocation.h"
#include <sys/time.h>

#define MSG_LEN 1024

static FILE *open_csv(const char *path, const char *header)
{
    FILE *f = fopen(path, "a+");
    if (!f) {
        perror(path);
        exit(1);
    }
    fseek(f, 0, SEEK_END);
    if (ftell(f) == 0)
        fprintf(f, "%s\n", header);
    return f;
}

static const char *phase(int i, int n, int warmup)
{
    if (n == 1 && warmup == 0)
        return "cold";
    return i < warmup ? "warmup" : "measure";
}

static char g_host[64];

/* ---------------- sig ---------------- */

static EVP_PKEY *gen_key(const char *alg, const char **md)
{
    EVP_PKEY *pkey = NULL;
    *md = NULL;
    if (strcmp(alg, "rsa4096") == 0) {
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)4096);
        *md = "SHA256";
    } else if (strcmp(alg, "ecdsa-p256") == 0) {
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256");
        *md = "SHA256";
    } else if (strcmp(alg, "ecdsa-p384") == 0) {
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-384");
        *md = "SHA384";
    } else if (strcmp(alg, "ecdsa-p521") == 0) {
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-521");
        *md = "SHA512";
    } else {
        EVP_PKEY_CTX *c = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
        if (c && EVP_PKEY_keygen_init(c) > 0)
            EVP_PKEY_generate(c, &pkey);
        EVP_PKEY_CTX_free(c);
    }
    return pkey;
}

static int cmd_sig(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: phc-bench sig <alg> <n> <warmup> <csv>\n");
        return 2;
    }
    const char *alg = argv[2];
    int n = atoi(argv[3]), warmup = atoi(argv[4]);
    const char *md;
    EVP_PKEY *pkey = gen_key(alg, &md);
    if (!pkey) {
        fprintf(stderr, "cannot generate key for %s\n", alg);
        ERR_print_errors_fp(stderr);
        return 1;
    }
    unsigned char msg[MSG_LEN];
    RAND_bytes(msg, sizeof msg);
    FILE *csv = open_csv(argv[5], "host,alg,op,phase,iter,ms,sig_bytes");

    for (int i = 0; i < n; i++) {
        size_t sig_len = 0;
        unsigned char *sig = NULL;
        EVP_MD_CTX *s = EVP_MD_CTX_new();
        double t0 = phc_now_ms();
        int ok = EVP_DigestSignInit_ex(s, NULL, md, NULL, NULL, pkey, NULL) == 1 &&
                 EVP_DigestSign(s, NULL, &sig_len, msg, sizeof msg) == 1 &&
                 (sig = malloc(sig_len)) != NULL &&
                 EVP_DigestSign(s, sig, &sig_len, msg, sizeof msg) == 1;
        double t_sign = phc_now_ms() - t0;
        EVP_MD_CTX_free(s);

        EVP_MD_CTX *v = EVP_MD_CTX_new();
        t0 = phc_now_ms();
        ok = ok && EVP_DigestVerifyInit_ex(v, NULL, md, NULL, NULL, pkey, NULL) == 1 &&
             EVP_DigestVerify(v, sig, sig_len, msg, sizeof msg) == 1;
        double t_verify = phc_now_ms() - t0;
        EVP_MD_CTX_free(v);
        free(sig);
        if (!ok) {
            fprintf(stderr, "sign/verify failed for %s\n", alg);
            ERR_print_errors_fp(stderr);
            return 1;
        }
        const char *ph = phase(i, n, warmup);
        fprintf(csv, "%s,%s,sign,%s,%d,%.4f,%zu\n", g_host, alg, ph, i, t_sign, sig_len);
        fprintf(csv, "%s,%s,verify,%s,%d,%.4f,%zu\n", g_host, alg, ph, i, t_verify, sig_len);
    }
    fclose(csv);
    EVP_PKEY_free(pkey);
    printf("sig %s: %d iterations (%d warm-up) -> %s\n", alg, n, n == 1 && warmup == 0 ? 0 : warmup, argv[5]);
    return 0;
}

/* ---------------- verify ---------------- */

static X509 *load_cert(const char *path)
{
    FILE *f = fopen(path, "r");
    X509 *c = f ? PEM_read_X509(f, NULL, NULL, NULL) : NULL;
    if (f)
        fclose(f);
    return c;
}

static int cmd_verify(int argc, char **argv)
{
    if (argc != 8) {
        fprintf(stderr, "usage: phc-bench verify <model> <cert> <ca-bundle> <n> <warmup> <csv>\n");
        return 2;
    }
    const char *model = argv[2];
    X509 *cert = load_cert(argv[3]);
    X509_STORE *store = X509_STORE_new();
    int n = atoi(argv[5]), warmup = atoi(argv[6]);
    if (!cert || !store || X509_STORE_load_file(store, argv[4]) != 1) {
        fprintf(stderr, "cannot load certificate or CA bundle\n");
        return 1;
    }
    /* Also verify the self-signature of the root, so that both methods cover the same links */
    X509_STORE_set_flags(store, X509_V_FLAG_CHECK_SS_SIGNATURE);
    FILE *csv = open_csv(argv[7], "host,model,phase,iter,x509_ms,hybrid_ms,chain_len");

    for (int i = 0; i < n; i++) {
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        X509_STORE_CTX_init(ctx, store, cert, NULL);
        double t0 = phc_now_ms();
        int ok = X509_verify_cert(ctx) == 1;
        double t_x509 = phc_now_ms() - t0;
        if (!ok) {
            fprintf(stderr, "X.509 verification failed: %s\n",
                    X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
            return 1;
        }
        STACK_OF(X509) *chain = X509_STORE_CTX_get1_chain(ctx);
        t0 = phc_now_ms();
        ok = phc_verify_chain(chain, 0);
        double t_hyb = phc_now_ms() - t0;
        if (!ok) {
            fprintf(stderr, "hybrid verification failed\n");
            return 1;
        }
        fprintf(csv, "%s,%s,%s,%d,%.4f,%.4f,%d\n", g_host, model, phase(i, n, warmup), i, t_x509, t_hyb,
                sk_X509_num(chain));
        OSSL_STACK_OF_X509_free(chain);
        X509_STORE_CTX_free(ctx);
    }
    fclose(csv);
    printf("verify %s: %d iterations -> %s\n", model, n, argv[7]);
    return 0;
}

/* ---------------- TLS ---------------- */

static const char *chain_policy(void)
{
    const char *c = getenv("PHC_CHAIN");
    return (c && strcmp(c, "explicit") == 0) ? "explicit" : "auto";
}

static SSL_CTX *bench_ctx(int is_server, const char *cert, const char *key, const char *bundle)
{
    SSL_CTX *ctx = phc_tls_ctx(is_server, cert, key, bundle);
    if (!ctx)
        return NULL;
    /* Same key exchange for every model: only authentication differs. No resumption. */
    if (SSL_CTX_set1_groups_list(ctx, "X25519") != 1) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_num_tickets(ctx, 0);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    if (strcmp(chain_policy(), "explicit") == 0)
        SSL_CTX_set_mode(ctx, SSL_MODE_NO_AUTO_CHAIN);
    return ctx;
}

static int cmd_tls_server(int argc, char **argv)
{
    if (argc != 6) {
        fprintf(stderr, "usage: phc-bench tls-server <port> <cert> <key> <ca-bundle>\n");
        return 2;
    }
    SSL_CTX *ctx = bench_ctx(1, argv[3], argv[4], argv[5]);
    int srv = ctx ? phc_listen(atoi(argv[2])) : -1;
    if (srv < 0)
        return 1;
    listen(srv, 512); /* a second listen() on a listening socket only updates the backlog */
    const char *w = getenv("PHC_BENCH_WORKERS");
    int workers = w ? atoi(w) : 1;
    if (workers < 1)
        workers = 1;
    for (int i = 1; i < workers; i++)
        if (fork() == 0)
            break; /* children leave the loop and serve like the parent */
    printf("[bench-server %d] listening on port %s, chain policy %s, %d worker(s) (Ctrl+C to stop)\n", (int)getpid(),
           argv[2], chain_policy(), workers);
    long served = 0, failed = 0;
    for (;;) {
        int fd = accept(srv, NULL, NULL);
        if (fd < 0)
            continue;
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        int ok = SSL_accept(ssl) == 1 && phc_verify_chain(SSL_get0_verified_chain(ssl), 0) == 1;
        if (ok) {
            served++;
            SSL_shutdown(ssl);
        } else {
            failed++;
            ERR_clear_error();
        }
        SSL_free(ssl);
        close(fd);
        if ((served + failed) % 50 == 0)
            printf("[bench-server %d] connections: %ld ok, %ld failed\n", (int)getpid(), served, failed);
    }
}

static int tcp_connect(const char *host, int port)
{
    struct addrinfo hints = {.ai_family = AF_INET, .ai_socktype = SOCK_STREAM}, *res;
    char p[8];
    snprintf(p, sizeof p, "%d", port);
    if (getaddrinfo(host, p, &hints, &res) != 0)
        return -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    }
    return fd;
}

static int cmd_tls_client(int argc, char **argv)
{
    if (argc != 11) {
        fprintf(stderr, "usage: phc-bench tls-client <model> <host> <port> <cert> <key> <ca-bundle> <n> <warmup> <csv>\n");
        return 2;
    }
    const char *model = argv[2], *host = argv[3];
    int port = atoi(argv[4]), n = atoi(argv[8]), warmup = atoi(argv[9]);
    const char *pe = getenv("PHC_BENCH_PAUSE_MS");
    int pause_ms = pe ? atoi(pe) : 0;
    SSL_CTX *ctx = bench_ctx(0, argv[5], argv[6], argv[7]);
    if (!ctx)
        return 1;
    FILE *csv = open_csv(argv[10], "host,model,chain,pause_ms,phase,iter,tcp_ms,handshake_ms,hybrid_ms,total_ms,"
                                    "hs_bytes_sent,hs_bytes_recv,peer_chain_certs,group,cipher");
    int failures = 0;
    for (int i = 0; i < n; i++) {
        double t0 = phc_now_ms();
        int fd = tcp_connect(host, port);
        if (fd < 0) {
            fprintf(stderr, "connect failed (iteration %d): %s\n", i, strerror(errno));
            return 1;
        }
        double t1 = phc_now_ms();
        BIO *bio = BIO_new_socket(fd, BIO_NOCLOSE);
        SSL *ssl = SSL_new(ctx);
        SSL_set_bio(ssl, bio, bio);
        int ok = SSL_connect(ssl) == 1;
        double t2 = phc_now_ms();
        int hyb = ok ? phc_verify_chain(SSL_get0_verified_chain(ssl), 0) : 0;
        double t3 = phc_now_ms();
        if (!ok || hyb != 1) {
            fprintf(stderr, "iteration %d: %s\n", i, ok ? "hybrid verification failed" : "handshake failed");
            ERR_print_errors_fp(stderr);
            failures++;
        } else {
            char group[64] = "?";
            int nid = SSL_get_negotiated_group(ssl);
            const char *gname = SSL_group_to_name(ssl, nid);
            if (gname)
                snprintf(group, sizeof group, "%s", gname);
            STACK_OF(X509) *sent = SSL_get_peer_cert_chain(ssl);
            fprintf(csv, "%s,%s,%s,%d,%s,%d,%.4f,%.4f,%.4f,%.4f,%lu,%lu,%d,%s,%s\n", g_host, model, chain_policy(),
                    pause_ms, phase(i, n, warmup), i, t1 - t0, t2 - t1, t3 - t2, t3 - t0,
                    (unsigned long)BIO_number_written(bio), (unsigned long)BIO_number_read(bio),
                    sent ? sk_X509_num(sent) : 0, group, SSL_get_cipher(ssl));
            SSL_shutdown(ssl);
        }
        SSL_free(ssl);
        close(fd);
        if (pause_ms > 0)
            usleep((useconds_t)pause_ms * 1000);
    }
    fclose(csv);
    printf("tls-client %s: %d handshakes, %d failed -> %s\n", model, n, failures, argv[10]);
    return failures ? 1 : 0;
}

/* ---------------- revocation (block 14) ---------------- */

static X509 *find_issuer(X509 *cert, const char *bundle)
{
    FILE *f = fopen(bundle, "r");
    X509 *c, *found = NULL;
    while (f && !found && (c = PEM_read_X509(f, NULL, NULL, NULL)) != NULL) {
        if (X509_check_issued(c, cert) == X509_V_OK)
            found = c;
        else
            X509_free(c);
    }
    if (f)
        fclose(f);
    return found;
}

static long long epoch_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int rev_setup(char **argv, X509 **cert, X509 **issuer, X509_STORE **store)
{
    *cert = load_cert(argv[3]);
    *issuer = *cert ? find_issuer(*cert, argv[4]) : NULL;
    *store = X509_STORE_new();
    if (!*cert || !*issuer || !*store || X509_STORE_load_file(*store, argv[4]) != 1) {
        fprintf(stderr, "cannot load certificate, its issuer or the CA bundle\n");
        return -1;
    }
    if (strcmp(phc_revocation_mode(), "none") == 0) {
        fprintf(stderr, "set PHC_REVOCATION=ocsp or crl\n");
        return -1;
    }
    return 0;
}

static int cmd_revpoll(int argc, char **argv)
{
    if (argc != 8) {
        fprintf(stderr, "usage: phc-bench revpoll <model> <cert> <ca-bundle> <interval_ms> <max_s> <csv>\n");
        return 2;
    }
    X509 *cert, *issuer;
    X509_STORE *store;
    if (rev_setup(argv, &cert, &issuer, &store) < 0)
        return 1;
    int interval = atoi(argv[5]);
    long long deadline = epoch_ms() + atoll(argv[6]) * 1000;
    FILE *csv = open_csv(argv[7], "host,model,method,epoch_ms,utc,status,check_ms,this_update,next_update,from_cache,detail");
    int revoked_in_a_row = 0, n = 0;
    printf("revpoll %s (%s): every %d ms, up to %s s\n", argv[2], phc_revocation_mode(), interval, argv[6]);
    while (epoch_ms() < deadline && revoked_in_a_row < 3) {
        long long t = epoch_ms();
        phc_rev_result r;
        phc_check_revocation(cert, issuer, store, &r);
        time_t sec = (time_t)(t / 1000);
        char utc[32];
        strftime(utc, sizeof utc, "%H:%M:%S", gmtime(&sec));
        for (char *p = r.detail; *p; p++)
            if (*p == ',')
                *p = ';';
        fprintf(csv, "%s,%s,%s,%lld,%s.%03lld,%s,%.3f,%ld,%ld,%d,%s\n", g_host, argv[2], phc_revocation_mode(), t, utc,
                t % 1000, phc_rev_status_name(r.status), r.ms, (long)r.this_update, (long)r.next_update, r.from_cache,
                r.detail);
        fflush(csv);
        if (n++ % 10 == 0 || r.status != PHC_REV_GOOD)
            printf("  %s.%03lld UTC  %s (%.1f ms)\n", utc, t % 1000, phc_rev_status_name(r.status), r.ms);
        revoked_in_a_row = r.status == PHC_REV_REVOKED ? revoked_in_a_row + 1 : 0;
        long long next = t + interval;
        while (epoch_ms() < next)
            usleep(1000);
    }
    fclose(csv);
    printf("revpoll %s: %d checks, %s\n", argv[2], n, revoked_in_a_row >= 3 ? "revocation observed" : "time limit reached");
    return 0;
}

static int cmd_revcheck(int argc, char **argv)
{
    if (argc != 8) {
        fprintf(stderr, "usage: phc-bench revcheck <model> <cert> <ca-bundle> <n> <warmup> <csv>\n");
        return 2;
    }
    X509 *cert, *issuer;
    X509_STORE *store;
    if (rev_setup(argv, &cert, &issuer, &store) < 0)
        return 1;
    int n = atoi(argv[5]), warmup = atoi(argv[6]);
    FILE *csv = open_csv(argv[7], "host,model,method,phase,iter,check_ms,status,from_cache");
    for (int i = 0; i < n; i++) {
        phc_rev_result r;
        phc_check_revocation(cert, issuer, store, &r);
        fprintf(csv, "%s,%s,%s,%s,%d,%.4f,%s,%d\n", g_host, argv[2], phc_revocation_mode(), phase(i, n, warmup), i, r.ms,
                phc_rev_status_name(r.status), r.from_cache);
    }
    fclose(csv);
    printf("revcheck %s (%s): %d checks -> %s\n", argv[2], phc_revocation_mode(), n, argv[7]);
    return 0;
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    gethostname(g_host, sizeof g_host - 1);
    if (argc >= 2 && strcmp(argv[1], "sig") == 0)
        return cmd_sig(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "verify") == 0)
        return cmd_verify(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "tls-server") == 0)
        return cmd_tls_server(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "tls-client") == 0)
        return cmd_tls_client(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "revpoll") == 0)
        return cmd_revpoll(argc, argv);
    if (argc >= 2 && strcmp(argv[1], "revcheck") == 0)
        return cmd_revcheck(argc, argv);
    fprintf(stderr, "usage: phc-bench sig|verify|tls-server|tls-client|revpoll|revcheck ... (see source header)\n");
    return 2;
}
