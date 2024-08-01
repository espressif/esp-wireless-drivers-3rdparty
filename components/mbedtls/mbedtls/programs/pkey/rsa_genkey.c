/*
 *  Example RSA key generation program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_RSA_C) && defined(MBEDTLS_GENPRIME) && \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/bignum.h"
#include "mbedtls/rsa.h"

#include <stdio.h>
#include <string.h>
#endif

#define KEY_SIZE 2048
#define EXPONENT 65537

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||   \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_GENPRIME) ||      \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_CTR_DRBG_C)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
                   "MBEDTLS_RSA_C and/or MBEDTLS_GENPRIME and/or "
                   "MBEDTLS_FS_IO and/or MBEDTLS_CTR_DRBG_C not defined.\n");
    esp_mbedtls_exit(0);
}
#else


int main(void)
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_rsa_context rsa;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    FILE *fpub  = NULL;
    FILE *fpriv = NULL;
    const char *pers = "rsa_genkey";

    esp_mbedtls_ctr_drbg_init(&ctr_drbg);
    esp_mbedtls_rsa_init(&rsa);
    esp_mbedtls_mpi_init(&N); esp_mbedtls_mpi_init(&P); esp_mbedtls_mpi_init(&Q);
    esp_mbedtls_mpi_init(&D); esp_mbedtls_mpi_init(&E); esp_mbedtls_mpi_init(&DP);
    esp_mbedtls_mpi_init(&DQ); esp_mbedtls_mpi_init(&QP);

    esp_mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    esp_mbedtls_entropy_init(&entropy);
    if ((ret = esp_mbedtls_ctr_drbg_seed(&ctr_drbg, esp_mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n  . Generating the RSA key [ %d-bit ]...", KEY_SIZE);
    fflush(stdout);

    if ((ret = esp_mbedtls_rsa_gen_key(&rsa, esp_mbedtls_ctr_drbg_random, &ctr_drbg, KEY_SIZE,
                                   EXPONENT)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_rsa_gen_key returned %d\n\n", ret);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n  . Exporting the public  key in rsa_pub.txt....");
    fflush(stdout);

    if ((ret = esp_mbedtls_rsa_export(&rsa, &N, &P, &Q, &D, &E)) != 0 ||
        (ret = esp_mbedtls_rsa_export_crt(&rsa, &DP, &DQ, &QP))      != 0) {
        esp_mbedtls_printf(" failed\n  ! could not export RSA parameters\n\n");
        goto exit;
    }

    if ((fpub = fopen("rsa_pub.txt", "wb+")) == NULL) {
        esp_mbedtls_printf(" failed\n  ! could not open rsa_pub.txt for writing\n\n");
        goto exit;
    }

    if ((ret = esp_mbedtls_mpi_write_file("N = ", &N, 16, fpub)) != 0 ||
        (ret = esp_mbedtls_mpi_write_file("E = ", &E, 16, fpub)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_mpi_write_file returned %d\n\n", ret);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n  . Exporting the private key in rsa_priv.txt...");
    fflush(stdout);

    if ((fpriv = fopen("rsa_priv.txt", "wb+")) == NULL) {
        esp_mbedtls_printf(" failed\n  ! could not open rsa_priv.txt for writing\n");
        goto exit;
    }

    if ((ret = esp_mbedtls_mpi_write_file("N = ", &N, 16, fpriv)) != 0 ||
        (ret = esp_mbedtls_mpi_write_file("E = ", &E, 16, fpriv)) != 0 ||
        (ret = esp_mbedtls_mpi_write_file("D = ", &D, 16, fpriv)) != 0 ||
        (ret = esp_mbedtls_mpi_write_file("P = ", &P, 16, fpriv)) != 0 ||
        (ret = esp_mbedtls_mpi_write_file("Q = ", &Q, 16, fpriv)) != 0 ||
        (ret = esp_mbedtls_mpi_write_file("DP = ", &DP, 16, fpriv)) != 0 ||
        (ret = esp_mbedtls_mpi_write_file("DQ = ", &DQ, 16, fpriv)) != 0 ||
        (ret = esp_mbedtls_mpi_write_file("QP = ", &QP, 16, fpriv)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_mpi_write_file returned %d\n\n", ret);
        goto exit;
    }
    esp_mbedtls_printf(" ok\n\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    if (fpub  != NULL) {
        fclose(fpub);
    }

    if (fpriv != NULL) {
        fclose(fpriv);
    }

    esp_mbedtls_mpi_free(&N); esp_mbedtls_mpi_free(&P); esp_mbedtls_mpi_free(&Q);
    esp_mbedtls_mpi_free(&D); esp_mbedtls_mpi_free(&E); esp_mbedtls_mpi_free(&DP);
    esp_mbedtls_mpi_free(&DQ); esp_mbedtls_mpi_free(&QP);
    esp_mbedtls_rsa_free(&rsa);
    esp_mbedtls_ctr_drbg_free(&ctr_drbg);
    esp_mbedtls_entropy_free(&entropy);

    esp_mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_RSA_C &&
          MBEDTLS_GENPRIME && MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */
