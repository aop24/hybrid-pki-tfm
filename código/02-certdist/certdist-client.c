/*
 * certdist-client: requests a certificate from certdist-server over WireGuard.
 *
 * Usage: certdist-client <chimera|composite|classic> <common_name> <csr_file> <output_cert>
 *
 * Only the CSR is sent; the private key stays on this machine.
 * Protocol: see certdist-server.c.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define SERVER_ADDR  "10.10.0.1"
#define SERVER_PORT  9998
#define MAX_CN       64
#define MAX_CSR      (64 * 1024)
#define MAX_CERT     (64 * 1024)
#define MAX_ERRMSG   1024
#define IO_TIMEOUT_S 60

static int read_full(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_u32(int fd, uint32_t *v)
{
    uint32_t be;
    if (read_full(fd, &be, sizeof be) < 0)
        return -1;
    *v = ntohl(be);
    return 0;
}

static int write_u32(int fd, uint32_t v)
{
    uint32_t be = htonl(v);
    return write_full(fd, &be, sizeof be);
}

static int die(const char *msg)
{
    fprintf(stderr, "ERROR: %s\n", msg);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        fprintf(stderr, "usage: %s <chimera|composite|classic> <common_name> <csr_file> <output_cert>\n", argv[0]);
        return 2;
    }
    const char *model = argv[1], *cn = argv[2], *csr_path = argv[3], *out_path = argv[4];

    uint8_t type;
    if (strcmp(model, "chimera") == 0)
        type = 0x01;
    else if (strcmp(model, "composite") == 0)
        type = 0x02;
    else if (strcmp(model, "classic") == 0)
        type = 0x03;
    else
        return die("model must be chimera, composite or classic");

    size_t cn_len = strlen(cn);
    if (cn_len == 0 || cn_len > MAX_CN)
        return die("common name must be 1-64 characters");

    FILE *f = fopen(csr_path, "rb");
    if (!f)
        return die("cannot open CSR file");
    static uint8_t csr[MAX_CSR];
    size_t csr_len = fread(csr, 1, sizeof csr, f);
    int too_big = (csr_len == sizeof csr) && fgetc(f) != EOF;
    fclose(f);
    if (csr_len == 0 || too_big)
        return die("CSR file is empty or larger than 64 KiB");

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return die("socket");
    struct timeval tv = {.tv_sec = IO_TIMEOUT_S};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(SERVER_PORT)};
    inet_pton(AF_INET, SERVER_ADDR, &addr.sin_addr);
    printf("Connecting to %s:%d (WireGuard)...\n", SERVER_ADDR, SERVER_PORT);
    fflush(stdout);
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        fprintf(stderr, "connect: %s\n", strerror(errno));
        fprintf(stderr, "Could not connect. Is the WireGuard VPN up on this machine?\n");
        close(fd);
        return 1;
    }

    if (write_full(fd, &type, 1) < 0 || write_u32(fd, (uint32_t)cn_len) < 0 ||
        write_full(fd, cn, cn_len) < 0 || write_u32(fd, (uint32_t)csr_len) < 0 ||
        write_full(fd, csr, csr_len) < 0) {
        close(fd);
        return die("failed to send request");
    }

    uint32_t cert_len;
    if (read_u32(fd, &cert_len) < 0) {
        close(fd);
        return die("no response from server");
    }
    if (cert_len == 0) {
        uint32_t msg_len;
        char msg[MAX_ERRMSG + 1] = "unknown error";
        if (read_u32(fd, &msg_len) == 0 && msg_len > 0 && msg_len <= MAX_ERRMSG &&
            read_full(fd, msg, msg_len) == 0)
            msg[msg_len] = '\0';
        close(fd);
        fprintf(stderr, "ERROR: server refused the request: %s\n", msg);
        return 1;
    }
    if (cert_len > MAX_CERT) {
        close(fd);
        return die("certificate too large");
    }
    static uint8_t cert[MAX_CERT];
    if (read_full(fd, cert, cert_len) < 0) {
        close(fd);
        return die("truncated certificate");
    }
    close(fd);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    FILE *o = fopen(out_path, "wb");
    if (!o || fwrite(cert, 1, cert_len, o) != cert_len || fclose(o) != 0)
        return die("cannot write output certificate");

    double ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    printf("Certificate received (%u bytes, %.1f ms) -> %s\n", cert_len, ms, out_path);
    return 0;
}
