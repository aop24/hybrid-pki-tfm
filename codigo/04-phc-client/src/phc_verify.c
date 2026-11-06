/*
 * phc-verify: offline verification of a certificate of any of the three
 * models. Standard X.509 chain validation against the CA bundle, followed by
 * the independent hybrid verification of every link of the chain.
 *
 * Usage: phc-verify <certificate.crt> <ca-bundle.crt>
 */
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "phc.h"

static X509 *load_cert(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        perror(path);
        return NULL;
    }
    X509 *c = PEM_read_X509(f, NULL, NULL, NULL);
    fclose(f);
    return c;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <certificate.crt> <ca-bundle.crt>\n", argv[0]);
        return 2;
    }
    X509 *cert = load_cert(argv[1]);
    X509_STORE *store = X509_STORE_new();
    if (!cert || !store || X509_STORE_load_file(store, argv[2]) != 1) {
        fprintf(stderr, "cannot load certificate or CA bundle\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }

    char subj[256], iss[256];
    X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof subj);
    X509_NAME_oneline(X509_get_issuer_name(cert), iss, sizeof iss);
    printf("Certificate: %s\nIssuer:      %s\nModel:       %s (%d B DER)\n\n", subj, iss,
           phc_model_name(phc_model_of(cert)), i2d_X509(cert, NULL));

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, cert, NULL);
    double t0 = phc_now_ms();
    int x509_ok = X509_verify_cert(ctx) == 1;
    double x509_ms = phc_now_ms() - t0;
    printf("1) Standard X.509 chain validation: %s (%.2f ms)\n",
           x509_ok ? "OK" : X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)), x509_ms);
    if (!x509_ok)
        return 1;

    STACK_OF(X509) *chain = X509_STORE_CTX_get1_chain(ctx);
    printf("2) Hybrid verification of each link (%d certificates):\n", sk_X509_num(chain));
    t0 = phc_now_ms();
    int hyb_ok = phc_verify_chain(chain, 1);
    double hyb_ms = phc_now_ms() - t0;
    printf("\nRESULT: %s (x509 %.2f ms, hybrid %.2f ms)\n", hyb_ok ? "VALID" : "INVALID", x509_ms, hyb_ms);

    OSSL_STACK_OF_X509_free(chain);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);
    return hyb_ok ? 0 : 1;
}
