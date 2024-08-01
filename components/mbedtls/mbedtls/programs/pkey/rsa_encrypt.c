/*
 *  RSA simple data encryption program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_RSA_C) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_FS_IO) && \
    defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <string.h>
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_RSA_C) ||  \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_CTR_DRBG_C)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_RSA_C and/or "
                   "MBEDTLS_ENTROPY_C and/or MBEDTLS_FS_IO and/or "
                   "MBEDTLS_CTR_DRBG_C not defined.\n");
    esp_mbedtls_exit(0);
}
#else


int main(int argc, char *argv[])
{
    FILE *f;
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char input[1024];
    unsigned char buf[512];
    const char *pers = "rsa_encrypt";
    mbedtls_mpi N, E;

    if (argc != 2) {
        esp_mbedtls_printf("usage: rsa_encrypt <string of max 100 characters>\n");

#if defined(_WIN32)
        esp_mbedtls_printf("\n");
#endif

        esp_mbedtls_exit(exit_code);
    }

    esp_mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    esp_mbedtls_mpi_init(&N); esp_mbedtls_mpi_init(&E);
    esp_mbedtls_rsa_init(&rsa);
    esp_mbedtls_ctr_drbg_init(&ctr_drbg);
    esp_mbedtls_entropy_init(&entropy);

    ret = esp_mbedtls_ctr_drbg_seed(&ctr_drbg, esp_mbedtls_entropy_func,
                                &entropy, (const unsigned char *) pers,
                                strlen(pers));
    if (ret != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ctr_drbg_seed returned %d\n",
                       ret);
        goto exit;
    }

    esp_mbedtls_printf("\n  . Reading public key from rsa_pub.txt");
    fflush(stdout);

    if ((f = fopen("rsa_pub.txt", "rb")) == NULL) {
        esp_mbedtls_printf(" failed\n  ! Could not open rsa_pub.txt\n" \
                       "  ! Please run rsa_genkey first\n\n");
        goto exit;
    }

    if ((ret = esp_mbedtls_mpi_read_file(&N, 16, f)) != 0 ||
        (ret = esp_mbedtls_mpi_read_file(&E, 16, f)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_mpi_read_file returned %d\n\n",
                       ret);
        fclose(f);
        goto exit;
    }
    fclose(f);

    if ((ret = esp_mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_rsa_import returned %d\n\n",
                       ret);
        goto exit;
    }

    if (strlen(argv[1]) > 100) {
        esp_mbedtls_printf(" Input data larger than 100 characters.\n\n");
        goto exit;
    }

    memcpy(input, argv[1], strlen(argv[1]));

    /*
     * Calculate the RSA encryption of the hash.
     */
    esp_mbedtls_printf("\n  . Generating the RSA encrypted value");
    fflush(stdout);

    ret = esp_mbedtls_rsa_pkcs1_encrypt(&rsa, esp_mbedtls_ctr_drbg_random,
                                    &ctr_drbg, strlen(argv[1]), input, buf);
    if (ret != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_rsa_pkcs1_encrypt returned %d\n\n",
                       ret);
        goto exit;
    }

    /*
     * Write the signature into result-enc.txt
     */
    if ((f = fopen("result-enc.txt", "wb+")) == NULL) {
        esp_mbedtls_printf(" failed\n  ! Could not create %s\n\n", "result-enc.txt");
        goto exit;
    }

    for (i = 0; i < esp_mbedtls_rsa_get_len(&rsa); i++) {
        esp_mbedtls_fprintf(f, "%02X%s", buf[i],
                        (i + 1) % 16 == 0 ? "\r\n" : " ");
    }

    fclose(f);

    esp_mbedtls_printf("\n  . Done (created \"%s\")\n\n", "result-enc.txt");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    esp_mbedtls_mpi_free(&N); esp_mbedtls_mpi_free(&E);
    esp_mbedtls_ctr_drbg_free(&ctr_drbg);
    esp_mbedtls_entropy_free(&entropy);
    esp_mbedtls_rsa_free(&rsa);

    esp_mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_RSA_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */
