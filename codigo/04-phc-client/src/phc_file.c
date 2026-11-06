/*
 * phc-file: file transfer over TLS 1.3 with mutual authentication and hybrid
 * verification of the peer chain. The receiver returns the SHA-256 of what it
 * stored and the sender compares it with its own.
 *
 * Usage:
 *   phc-file server <port> <cert> <key> <ca-bundle> <output_dir>   (receiver)
 *   phc-file client <host> <port> <cert> <key> <ca-bundle> <file>  (sender)
 *
 * Protocol: name_len(4) | name | size(8) | content ; reply: "OK <sha256hex>"
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "phc.h"

#define MAX_NAME  255
#define MAX_SIZE  ((uint64_t)1 << 30) /* 1 GiB */
#define CHUNK     65536

static void hex(const unsigned char *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++)
        sprintf(out + 2 * i, "%02x", in[i]);
}

static int write_u64(SSL *ssl, uint64_t v)
{
    return phc_write_u32(ssl, (unsigned int)(v >> 32)) || phc_write_u32(ssl, (unsigned int)v) ? -1 : 0;
}

static int read_u64(SSL *ssl, uint64_t *v)
{
    unsigned int hi, lo;
    if (phc_read_u32(ssl, &hi) < 0 || phc_read_u32(ssl, &lo) < 0)
        return -1;
    *v = ((uint64_t)hi << 32) | lo;
    return 0;
}

/* Only a plain file name is accepted from the peer: no paths, no dot names. */
static int safe_name(const char *n)
{
    if (!*n || strcmp(n, ".") == 0 || strcmp(n, "..") == 0)
        return 0;
    for (const char *p = n; *p; p++)
        if (*p == '/' || *p == '\\' || (unsigned char)*p < 0x20)
            return 0;
    return 1;
}

static int send_file(SSL *ssl, const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        perror(path);
        return -1;
    }
    struct stat st;
    fstat(fileno(f), &st);
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    uint64_t size = (uint64_t)st.st_size;
    if (strlen(base) > MAX_NAME || size > MAX_SIZE) {
        fprintf(stderr, "file name or size not allowed\n");
        fclose(f);
        return -1;
    }

    double t0 = phc_now_ms();
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), NULL);
    int rc = phc_write_u32(ssl, (unsigned int)strlen(base)) || phc_write_all(ssl, base, strlen(base)) ||
             write_u64(ssl, size);
    unsigned char buf[CHUNK];
    size_t n;
    while (!rc && (n = fread(buf, 1, sizeof buf, f)) > 0) {
        EVP_DigestUpdate(md, buf, n);
        rc = phc_write_all(ssl, buf, n);
    }
    fclose(f);
    unsigned char dig[32];
    char my_hex[65], reply[80] = {0};
    EVP_DigestFinal_ex(md, dig, NULL);
    EVP_MD_CTX_free(md);
    hex(dig, 32, my_hex);
    if (rc) {
        fprintf(stderr, "[sender] transfer interrupted\n");
        return -1;
    }
    printf("[sender] Sent '%s' (%llu bytes). SHA-256: %s\n", base, (unsigned long long)size, my_hex);

    unsigned int rlen;
    if (phc_read_u32(ssl, &rlen) < 0 || rlen >= sizeof reply || phc_read_all(ssl, reply, rlen) < 0) {
        fprintf(stderr, "[sender] no confirmation from receiver\n");
        return -1;
    }
    double ms = phc_now_ms() - t0;
    int match = strncmp(reply, "OK ", 3) == 0 && strcmp(reply + 3, my_hex) == 0;
    printf("[sender] Receiver replied: %s\n", reply);
    printf("[sender] Integrity %s\n", match ? "CONFIRMED (hashes match)" : "FAILED (hash mismatch)");
    printf("[metrics] transfer_bytes=%llu transfer_ms=%.2f\n", (unsigned long long)size, ms);
    return match ? 0 : -1;
}

static int receive_file(SSL *ssl, const char *outdir)
{
    unsigned int nlen;
    char name[MAX_NAME + 1];
    uint64_t size;
    if (phc_read_u32(ssl, &nlen) < 0 || nlen == 0 || nlen > MAX_NAME || phc_read_all(ssl, name, nlen) < 0 ||
        read_u64(ssl, &size) < 0) {
        fprintf(stderr, "[receiver] malformed header\n");
        return -1;
    }
    name[nlen] = '\0';
    if (strlen(name) != nlen || !safe_name(name) || size > MAX_SIZE) {
        fprintf(stderr, "[receiver] rejected file name or size\n");
        return -1;
    }
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", outdir, name);
    FILE *f = fopen(path, "wb");
    if (!f) {
        perror(path);
        return -1;
    }

    EVP_MD_CTX *md = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md, EVP_sha256(), NULL);
    unsigned char buf[CHUNK];
    uint64_t left = size;
    int rc = 0;
    while (left > 0 && !rc) {
        size_t want = left > sizeof buf ? sizeof buf : (size_t)left;
        rc = phc_read_all(ssl, buf, want);
        if (!rc) {
            EVP_DigestUpdate(md, buf, want);
            rc = fwrite(buf, 1, want, f) == want ? 0 : -1;
            left -= want;
        }
    }
    fclose(f);
    unsigned char dig[32];
    char h[65], reply[80];
    EVP_DigestFinal_ex(md, dig, NULL);
    EVP_MD_CTX_free(md);
    if (rc) {
        fprintf(stderr, "[receiver] transfer interrupted, removing partial file\n");
        remove(path);
        return -1;
    }
    hex(dig, 32, h);
    printf("[receiver] Received '%s' (%llu bytes) -> %s\n", name, (unsigned long long)size, path);
    printf("[receiver] SHA-256: %s\n", h);
    snprintf(reply, sizeof reply, "OK %s", h);
    return phc_write_u32(ssl, (unsigned int)strlen(reply)) || phc_write_all(ssl, reply, strlen(reply)) ? -1 : 0;
}

int main(int argc, char **argv)
{
    int is_server = argc == 7 && strcmp(argv[1], "server") == 0;
    int is_client = argc == 8 && strcmp(argv[1], "client") == 0;
    if (!is_server && !is_client) {
        fprintf(stderr, "usage:\n  %s server <port> <cert> <key> <ca-bundle> <output_dir>\n"
                        "  %s client <host> <port> <cert> <key> <ca-bundle> <file>\n", argv[0], argv[0]);
        return 2;
    }
    const char *role = is_server ? "server" : "client";
    int a = is_server ? 3 : 4;
    SSL_CTX *ctx = phc_tls_ctx(is_server, argv[a], argv[a + 1], argv[a + 2]);
    if (!ctx)
        return 1;

    int srv = -1, fd;
    if (is_server) {
        srv = phc_listen(atoi(argv[2]));
        if (srv < 0)
            return 1;
        printf("[server] Listening on port %s, files will be stored in %s\n", argv[2], argv[6]);
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
        rc = (is_server ? receive_file(ssl, argv[6]) : send_file(ssl, argv[7])) == 0 ? 0 : 1;

    phc_close(ssl, fd);
    if (srv >= 0)
        phc_close(NULL, srv);
    SSL_CTX_free(ctx);
    return rc;
}
