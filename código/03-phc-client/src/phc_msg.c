/*
 * phc-msg: bidirectional messaging over TLS 1.3 with mutual authentication
 * and hybrid verification of the peer chain.
 *
 * Usage:
 *   phc-msg server <port> <cert> <key> <ca-bundle>
 *   phc-msg client <host> <port> <cert> <key> <ca-bundle>
 * Type a line and press Enter to send it; "quit" (or end of input) ends the session.
 *
 * A single thread multiplexes keyboard and socket with poll(): one SSL object
 * must not be read and written concurrently from two threads.
 * Frames: 4-byte big-endian length + UTF-8 text.
 *
 * PHC_RECHECK_SECS=N (with PHC_REVOCATION=ocsp|crl): the revocation status of
 * the peer certificate is checked again every N seconds during the session, and
 * the session is closed as soon as the peer must be rejected.
 */
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <time.h>

#include "phc.h"
#include "revocation.h"

#define MAX_LINE 1024

static int send_line(SSL *ssl, const char *text)
{
    size_t len = strlen(text);
    return phc_write_u32(ssl, (unsigned int)len) == 0 && phc_write_all(ssl, text, len) == 0 ? 0 : -1;
}

/* Returns 1 to continue, 0 when the peer ends the session, -1 on error. */
static int receive_line(SSL *ssl)
{
    char buf[MAX_LINE + 1];
    unsigned int len;
    if (phc_read_u32(ssl, &len) < 0 || len > MAX_LINE || phc_read_all(ssl, buf, len) < 0)
        return -1;
    buf[len] = '\0';
    if (strcmp(buf, "quit") == 0) {
        printf("\n[peer left the session]\n");
        return 0;
    }
    printf("\r[peer] %s\n> ", buf);
    fflush(stdout);
    return 1;
}

/* A readable socket does not mean a readable message: TLS 1.3 also sends post-handshake records
 * (NewSessionTicket from the server). A blocking SSL_read on such a record would wait for the next
 * application data and freeze the keyboard side. Peek without blocking first.
 * Returns 1 = application data ready, 0 = nothing for the application, -1 = closed or error. */
static int app_data_ready(SSL *ssl, int fd)
{
    int fl = fcntl(fd, F_GETFL);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    char c;
    int r = SSL_peek(ssl, &c, 1);
    int e = SSL_get_error(ssl, r);
    fcntl(fd, F_SETFL, fl);
    if (r > 0)
        return 1;
    return e == SSL_ERROR_WANT_READ ? 0 : -1;
}

static void chat(SSL *ssl, int fd, const char *role)
{
    const char *rc = getenv("PHC_RECHECK_SECS");
    int recheck = (rc && strcmp(phc_revocation_mode(), "none") != 0) ? atoi(rc) : 0;
    double session_start = phc_now_ms(), last_check = session_start;
    if (recheck > 0)
        printf("[%s] Peer revocation re-checked every %d s during the session\n", role, recheck);
    printf("=== Messaging mode. Type a message and press Enter; 'quit' to finish. ===\n> ");
    fflush(stdout);
    struct pollfd pfd[2] = {{.fd = STDIN_FILENO, .events = POLLIN}, {.fd = fd, .events = POLLIN}};
    char line[MAX_LINE + 2];
    int stdin_open = 1;

    for (;;) {
        if (SSL_pending(ssl) == 0) {
            pfd[0].fd = stdin_open ? STDIN_FILENO : -1;
            int timeout = -1;
            if (recheck > 0) {
                double left = last_check + recheck * 1000.0 - phc_now_ms();
                timeout = left > 0 ? (int)left : 0;
            }
            int pr = poll(pfd, 2, timeout);
            if (pr < 0)
                break;
            if (recheck > 0 && phc_now_ms() - last_check >= recheck * 1000.0) {
                last_check = phc_now_ms();
                time_t now = time(NULL);
                char ts[16];
                strftime(ts, sizeof ts, "%H:%M:%S", gmtime(&now));
                printf("\r[%s] %s UTC re-check after %.0f s of session: ", role, ts,
                       (last_check - session_start) / 1000.0);
                if (phc_peer_revocation(ssl, role, NULL)) {
                    printf("[%s] Closing the session: the peer certificate is no longer acceptable\n", role);
                    break;
                }
                printf("> ");
                fflush(stdout);
                if (pr == 0)
                    continue;
            }
        }
        if (SSL_pending(ssl) > 0 || (pfd[1].revents & (POLLIN | POLLHUP | POLLERR))) {
            if (SSL_pending(ssl) == 0 && app_data_ready(ssl, fd) == 0)
                continue; /* only a post-handshake record was read */
            int r = receive_line(ssl);
            if (r <= 0) {
                if (r < 0)
                    printf("\n[connection closed by peer]\n");
                break;
            }
            continue;
        }
        if (stdin_open && (pfd[0].revents & (POLLIN | POLLHUP))) {
            if (!fgets(line, sizeof line, stdin)) {
                stdin_open = 0; /* end of input: leave the session */
                send_line(ssl, "quit");
                break;
            }
            line[strcspn(line, "\n")] = '\0';
            if (send_line(ssl, line) < 0 || strcmp(line, "quit") == 0)
                break;
            printf("> ");
            fflush(stdout);
        }
    }
    printf("=== Session closed. ===\n");
}

int main(int argc, char **argv)
{
    int is_server = argc == 6 && strcmp(argv[1], "server") == 0;
    int is_client = argc == 7 && strcmp(argv[1], "client") == 0;
    if (!is_server && !is_client) {
        fprintf(stderr, "usage:\n  %s server <port> <cert> <key> <ca-bundle>\n"
                        "  %s client <host> <port> <cert> <key> <ca-bundle>\n", argv[0], argv[0]);
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
        printf("[server] Listening on port %s...\n", argv[2]);
        fd = phc_accept(srv);
    } else {
        fd = phc_connect(argv[2], atoi(argv[3]));
    }
    if (fd < 0)
        return 1;

    phc_metrics m;
    SSL *ssl = phc_handshake(ctx, fd, is_server, role, &m);
    if (ssl)
        chat(ssl, fd, role);

    phc_close(ssl, fd);
    if (srv >= 0)
        phc_close(NULL, srv);
    SSL_CTX_free(ctx);
    return ssl ? 0 : 1;
}
