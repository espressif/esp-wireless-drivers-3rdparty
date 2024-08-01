/*
 *  Certificate request reading application
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_RSA_C) ||  \
    !defined(MBEDTLS_X509_CSR_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    defined(MBEDTLS_X509_REMOVE_INFO)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_RSA_C and/or "
                   "MBEDTLS_X509_CSR_PARSE_C and/or MBEDTLS_FS_IO not defined and/or "
                   "MBEDTLS_X509_REMOVE_INFO defined.\n");
    esp_mbedtls_exit(0);
}
#else

#include "mbedtls/x509_csr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DFL_FILENAME            "cert.req"
#define DFL_DEBUG_LEVEL         0

#define USAGE \
    "\n usage: req_app param=<>...\n"                   \
    "\n acceptable parameters:\n"                       \
    "    filename=%%s         default: cert.req\n"      \
    "\n"


/*
 * global options
 */
struct options {
    const char *filename;       /* filename of the certificate request  */
} opt;

int main(int argc, char *argv[])
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    unsigned char buf[100000];
    mbedtls_x509_csr csr;
    int i;
    char *p, *q;

    /*
     * Set to sane values
     */
    esp_mbedtls_x509_csr_init(&csr);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = esp_psa_crypto_init();
    if (status != PSA_SUCCESS) {
        esp_mbedtls_fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n",
                        (int) status);
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if (argc < 2) {
usage:
        esp_mbedtls_printf(USAGE);
        goto exit;
    }

    opt.filename            = DFL_FILENAME;

    for (i = 1; i < argc; i++) {
        p = argv[i];
        if ((q = strchr(p, '=')) == NULL) {
            goto usage;
        }
        *q++ = '\0';

        if (strcmp(p, "filename") == 0) {
            opt.filename = q;
        } else {
            goto usage;
        }
    }

    /*
     * 1.1. Load the CSR
     */
    esp_mbedtls_printf("\n  . Loading the CSR ...");
    fflush(stdout);

    ret = esp_mbedtls_x509_csr_parse_file(&csr, opt.filename);

    if (ret != 0) {
        esp_mbedtls_printf(" failed\n  !  esp_mbedtls_x509_csr_parse_file returned %d\n\n", ret);
        esp_mbedtls_x509_csr_free(&csr);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n");

    /*
     * 1.2 Print the CSR
     */
    esp_mbedtls_printf("  . CSR information    ...\n");
    ret = esp_mbedtls_x509_csr_info((char *) buf, sizeof(buf) - 1, "      ", &csr);
    if (ret == -1) {
        esp_mbedtls_printf(" failed\n  !  esp_mbedtls_x509_csr_info returned %d\n\n", ret);
        esp_mbedtls_x509_csr_free(&csr);
        goto exit;
    }

    esp_mbedtls_printf("%s\n", buf);

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    esp_mbedtls_x509_csr_free(&csr);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    esp_mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    esp_mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_RSA_C && MBEDTLS_X509_CSR_PARSE_C &&
          MBEDTLS_FS_IO */
