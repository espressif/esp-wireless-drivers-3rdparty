/*
 *  RSA simple decryption program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_RSA_C) && \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/rsa.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <string.h>

#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_RSA_C) ||  \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_ENTROPY_C) || \
    !defined(MBEDTLS_CTR_DRBG_C)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_RSA_C and/or "
                   "MBEDTLS_FS_IO and/or MBEDTLS_ENTROPY_C and/or "
                   "MBEDTLS_CTR_DRBG_C not defined.\n");
    esp_mbedtls_exit(0);
}
#else


int main(int argc, char *argv[])
{
    FILE *f;
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    unsigned c;
    size_t i;
    mbedtls_rsa_context rsa;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char result[1024];
    unsigned char buf[512];
    const char *pers = "rsa_decrypt";
    ((void) argv);

    memset(result, 0, sizeof(result));

    if (argc != 1) {
        esp_mbedtls_printf("usage: rsa_decrypt\n");

#if defined(_WIN32)
        esp_mbedtls_printf("\n");
#endif

        esp_mbedtls_exit(exit_code);
    }

    esp_mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    esp_mbedtls_rsa_init(&rsa);
    esp_mbedtls_ctr_drbg_init(&ctr_drbg);
    esp_mbedtls_entropy_init(&entropy);
    esp_mbedtls_mpi_init(&N); esp_mbedtls_mpi_init(&P); esp_mbedtls_mpi_init(&Q);
    esp_mbedtls_mpi_init(&D); esp_mbedtls_mpi_init(&E); esp_mbedtls_mpi_init(&DP);
    esp_mbedtls_mpi_init(&DQ); esp_mbedtls_mpi_init(&QP);

    ret = esp_mbedtls_ctr_drbg_seed(&ctr_drbg, esp_mbedtls_entropy_func,
                                &entropy, (const unsigned char *) pers,
                                strlen(pers));
    if (ret != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ctr_drbg_seed returned %d\n",
                       ret);
        goto exit;
    }

    esp_mbedtls_printf("\n  . Reading private key from rsa_priv.txt");
    fflush(stdout);

    if ((f = fopen("rsa_priv.txt", "rb")) == NULL) {
        esp_mbedtls_printf(" failed\n  ! Could not open rsa_priv.txt\n" \
                       "  ! Please run rsa_genkey first\n\n");
        goto exit;
    }

    if ((ret = esp_mbedtls_mpi_read_file(&N, 16, f))  != 0 ||
        (ret = esp_mbedtls_mpi_read_file(&E, 16, f))  != 0 ||
        (ret = esp_mbedtls_mpi_read_file(&D, 16, f))  != 0 ||
        (ret = esp_mbedtls_mpi_read_file(&P, 16, f))  != 0 ||
        (ret = esp_mbedtls_mpi_read_file(&Q, 16, f))  != 0 ||
        (ret = esp_mbedtls_mpi_read_file(&DP, 16, f)) != 0 ||
        (ret = esp_mbedtls_mpi_read_file(&DQ, 16, f)) != 0 ||
        (ret = esp_mbedtls_mpi_read_file(&QP, 16, f)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_mpi_read_file returned %d\n\n",
                       ret);
        fclose(f);
        goto exit;
    }
    fclose(f);

    if ((ret = esp_mbedtls_rsa_import(&rsa, &N, &P, &Q, &D, &E)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_rsa_import returned %d\n\n",
                       ret);
        goto exit;
    }

    if ((ret = esp_mbedtls_rsa_complete(&rsa)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_rsa_complete returned %d\n\n",
                       ret);
        goto exit;
    }

    /*
     * Extract the RSA encrypted value from the text file
     */
    if ((f = fopen("result-enc.txt", "rb")) == NULL) {
        esp_mbedtls_printf("\n  ! Could not open %s\n\n", "result-enc.txt");
        goto exit;
    }

    i = 0;

    while (fscanf(f, "%02X", (unsigned int *) &c) > 0 &&
           i < (int) sizeof(buf)) {
        buf[i++] = (unsigned char) c;
    }

    fclose(f);

    if (i != esp_mbedtls_rsa_get_len(&rsa)) {
        esp_mbedtls_printf("\n  ! Invalid RSA signature format\n\n");
        goto exit;
    }

    /*
     * Decrypt the encrypted RSA data and print the result.
     */
    esp_mbedtls_printf("\n  . Decrypting the encrypted data");
    fflush(stdout);

    ret = esp_mbedtls_rsa_pkcs1_decrypt(&rsa, esp_mbedtls_ctr_drbg_random,
                                    &ctr_drbg, &i,
                                    buf, result, 1024);
    if (ret != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_rsa_pkcs1_decrypt returned %d\n\n",
                       ret);
        goto exit;
    }

    esp_mbedtls_printf("\n  . OK\n\n");

    esp_mbedtls_printf("The decrypted result is: '%s'\n\n", result);

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    esp_mbedtls_ctr_drbg_free(&ctr_drbg);
    esp_mbedtls_entropy_free(&entropy);
    esp_mbedtls_rsa_free(&rsa);
    esp_mbedtls_mpi_free(&N); esp_mbedtls_mpi_free(&P); esp_mbedtls_mpi_free(&Q);
    esp_mbedtls_mpi_free(&D); esp_mbedtls_mpi_free(&E); esp_mbedtls_mpi_free(&DP);
    esp_mbedtls_mpi_free(&DQ); esp_mbedtls_mpi_free(&QP);

    esp_mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_RSA_C && MBEDTLS_FS_IO */
