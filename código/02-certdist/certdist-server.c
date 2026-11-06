/*
 * certdist-server: certificate distribution service for the PHC lab.
 *
 * Listens only on the WireGuard address of the CA, so it is unreachable from
 * outside the management VPN. A client sends a CSR (its private key never
 * leaves the client) and receives a certificate issued by the requested model.
 *
 * Protocol (all lengths are 32-bit big-endian):
 *   request : type(1) | cn_len(4) | cn | csr_len(4) | csr (PEM)
 *             type 0x01 = Chimera, 0x02 = Composite, 0x03 = classic
 *   response: cert_len(4) | cert (PEM)
 *             cert_len = 0 -> msg_len(4) | error message
 *
 * Requests are served one at a time on purpose: the issuance back-ends (EJBCA
 * end entity re-creation, openssl ca index.txt) are not safe under concurrency.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define LISTEN_ADDR  "10.10.0.1"
#define LISTEN_PORT  9998
#define MAX_CN       64
#define MAX_CSR      (64 * 1024)
#define MAX_CERT     (64 * 1024)
#define IO_TIMEOUT_S 15
#define BASE_DIR     "/home/ca/phc-certdist"
#define WORK_DIR     BASE_DIR "/work"

struct model {
    uint8_t type;
    const char *name;
    const char *script;
};

static const struct model MODELS[] = {
    {0x01, "chimera",   BASE_DIR "/sign_chimera.sh"},
    {0x02, "composite", BASE_DIR "/sign_composite.sh"},
    {0x03, "classic",   BASE_DIR "/sign_classic.sh"},
};

static void log_msg(const char *peer, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void log_msg(const char *peer, const char *fmt, ...)
{
    va_list ap;
    printf("[%s] ", peer);
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
    fflush(stdout);
}

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

static void send_error(int fd, const char *msg)
{
    size_t len = strlen(msg);
    if (write_u32(fd, 0) == 0 && write_u32(fd, (uint32_t)len) == 0)
        write_full(fd, msg, len);
}

/* Same rule as the signing scripts: 1-64 chars of [A-Za-z0-9.-]. */
static int valid_cn(const char *cn)
{
    size_t len = strlen(cn);
    if (len == 0 || len > MAX_CN)
        return 0;
    for (size_t i = 0; i < len; i++) {
        char c = cn[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-'))
            return 0;
    }
    return 1;
}

static const struct model *find_model(uint8_t type)
{
    for (size_t i = 0; i < sizeof MODELS / sizeof MODELS[0]; i++)
        if (MODELS[i].type == type)
            return &MODELS[i];
    return NULL;
}

/* Runs the signing script without a shell: arguments are never interpreted. */
static int run_script(const char *script, const char *cn, const char *csr, const char *out)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        char *const argv[] = {(char *)script, (char *)cn, (char *)csr, (char *)out, NULL};
        execv(script, argv);
        perror("execv");
        _exit(127);
    }
    int status;
    while (waitpid(pid, &status, 0) < 0)
        if (errno != EINTR)
            return -1;
    return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

static int write_file(const char *path, const void *buf, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    int ok = fwrite(buf, 1, len, f) == len;
    return (fclose(f) == 0 && ok) ? 0 : -1;
}

static uint8_t *read_file(const char *path, size_t max, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    uint8_t *buf = malloc(max);
    size_t n = buf ? fread(buf, 1, max, f) : 0;
    int too_big = (n == max) && fgetc(f) != EOF;
    fclose(f);
    if (!buf || n == 0 || too_big) {
        free(buf);
        return NULL;
    }
    *len = n;
    return buf;
}

static double elapsed_ms(const struct timespec *t0)
{
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t1);
    return (t1.tv_sec - t0->tv_sec) * 1000.0 + (t1.tv_nsec - t0->tv_nsec) / 1e6;
}

static void handle_client(int fd, const char *peer)
{
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint8_t type;
    uint32_t cn_len, csr_len;
    char cn[MAX_CN + 1];

    if (read_full(fd, &type, 1) < 0 || read_u32(fd, &cn_len) < 0) {
        log_msg(peer, "malformed request header");
        return;
    }
    const struct model *m = find_model(type);
    if (!m) {
        log_msg(peer, "rejected: unknown type 0x%02x", type);
        send_error(fd, "unknown certificate type");
        return;
    }
    if (cn_len == 0 || cn_len > MAX_CN || read_full(fd, cn, cn_len) < 0) {
        log_msg(peer, "rejected: bad common name length %u", cn_len);
        send_error(fd, "invalid common name");
        return;
    }
    cn[cn_len] = '\0';
    if (strlen(cn) != cn_len || !valid_cn(cn)) {
        log_msg(peer, "rejected: invalid common name");
        send_error(fd, "invalid common name (allowed: A-Z a-z 0-9 . -, max 64)");
        return;
    }
    if (read_u32(fd, &csr_len) < 0 || csr_len == 0 || csr_len > MAX_CSR) {
        log_msg(peer, "rejected: bad CSR length for '%s'", cn);
        send_error(fd, "invalid CSR length");
        return;
    }
    uint8_t *csr = malloc(csr_len);
    if (!csr || read_full(fd, csr, csr_len) < 0) {
        free(csr);
        log_msg(peer, "rejected: truncated CSR for '%s'", cn);
        return;
    }
    log_msg(peer, "request: model=%s cn='%s' csr=%u bytes", m->name, cn, csr_len);

    char dir[] = WORK_DIR "/req-XXXXXX";
    char csr_path[sizeof dir + 16], crt_path[sizeof dir + 16];
    if (!mkdtemp(dir)) {
        free(csr);
        log_msg(peer, "internal error: mkdtemp: %s", strerror(errno));
        send_error(fd, "internal error");
        return;
    }
    snprintf(csr_path, sizeof csr_path, "%s/request.csr", dir);
    snprintf(crt_path, sizeof crt_path, "%s/issued.crt", dir);

    uint8_t *cert = NULL;
    size_t cert_len = 0;
    if (write_file(csr_path, csr, csr_len) < 0) {
        log_msg(peer, "internal error: cannot write CSR");
        send_error(fd, "internal error");
    } else if (run_script(m->script, cn, csr_path, crt_path) < 0) {
        log_msg(peer, "issuance failed: model=%s cn='%s'", m->name, cn);
        send_error(fd, "issuance failed (see server log)");
    } else if (!(cert = read_file(crt_path, MAX_CERT, &cert_len))) {
        log_msg(peer, "internal error: cannot read issued certificate");
        send_error(fd, "internal error");
    } else if (write_u32(fd, (uint32_t)cert_len) < 0 || write_full(fd, cert, cert_len) < 0) {
        log_msg(peer, "send failed for '%s'", cn);
    } else {
        log_msg(peer, "issued: model=%s cn='%s' cert=%zu bytes time=%.1f ms",
                m->name, cn, cert_len, elapsed_ms(&t0));
    }

    free(cert);
    free(csr);
    unlink(csr_path);
    unlink(crt_path);
    rmdir(dir);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    umask(077);
    if (mkdir(WORK_DIR, 0700) < 0 && errno != EEXIST) {
        perror("mkdir " WORK_DIR);
        return 1;
    }

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket");
        return 1;
    }
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_port = htons(LISTEN_PORT)};
    if (inet_pton(AF_INET, LISTEN_ADDR, &addr.sin_addr) != 1) {
        fprintf(stderr, "invalid listen address\n");
        return 1;
    }
    if (bind(srv, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind " LISTEN_ADDR " (is wg0 up?)");
        return 1;
    }
    if (listen(srv, 16) < 0) {
        perror("listen");
        return 1;
    }
    printf("certdist-server listening on %s:%d (WireGuard only)\n", LISTEN_ADDR, LISTEN_PORT);
    fflush(stdout);

    for (;;) {
        struct sockaddr_in peer_addr;
        socklen_t plen = sizeof peer_addr;
        int fd = accept(srv, (struct sockaddr *)&peer_addr, &plen);
        if (fd < 0) {
            if (errno != EINTR)
                perror("accept");
            continue;
        }
        struct timeval tv = {.tv_sec = IO_TIMEOUT_S};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

        char peer[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer, sizeof peer);
        handle_client(fd, peer);
        close(fd);
    }
}
