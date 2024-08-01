/*
 *  RSASSA-PSS/SHA-256 signature creation program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"
/* md.h is included this early since MD_CAN_XXX macros are defined there. */
#include "mbedtls/md.h"

#if !defined(MBEDTLS_MD_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_MD_CAN_SHA256) ||        \
    !defined(MBEDTLS_PK_PARSE_C) || !defined(MBEDTLS_FS_IO) ||    \
    !defined(MBEDTLS_CTR_DRBG_C)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_MD_C and/or MBEDTLS_ENTROPY_C and/or "
                   "MBEDTLS_RSA_C and/or MBEDTLS_MD_CAN_SHA256 and/or "
                   "MBEDTLS_PK_PARSE_C and/or MBEDTLS_FS_IO and/or "
                   "MBEDTLS_CTR_DRBG_C not defined.\n");
    esp_mbedtls_exit(0);
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/rsa.h"
#include "mbedtls/pk.h"

#include <stdio.h>
#include <string.h>


int main(int argc, char *argv[])
{
    FILE *f;
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char hash[32];
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];
    char filename[512];
    const char *pers = "rsa_sign_pss";
    size_t olen = 0;

    esp_mbedtls_entropy_init(&entropy);
    esp_mbedtls_pk_init(&pk);
    esp_mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = esp_psa_crypto_init();
    if (status != PSA_SUCCESS) {
        esp_mbedtls_fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n",
                        (int) status);
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if (argc != 3) {
        esp_mbedtls_printf("usage: rsa_sign_pss <key_file> <filename>\n");

#if defined(_WIN32)
        esp_mbedtls_printf("\n");
#endif

        goto exit;
    }

    esp_mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    if ((ret = esp_mbedtls_ctr_drbg_seed(&ctr_drbg, esp_mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    esp_mbedtls_printf("\n  . Reading private key from '%s'", argv[1]);
    fflush(stdout);

    if ((ret = esp_mbedtls_pk_parse_keyfile(&pk, argv[1], "",
                                        esp_mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        esp_mbedtls_printf(" failed\n  ! Could not read key from '%s'\n", argv[1]);
        esp_mbedtls_printf("  ! esp_mbedtls_pk_parse_public_keyfile returned %d\n\n", ret);
        goto exit;
    }

    if (!esp_mbedtls_pk_can_do(&pk, MBEDTLS_PK_RSA)) {
        esp_mbedtls_printf(" failed\n  ! Key is not an RSA key\n");
        goto exit;
    }

    if ((ret = esp_mbedtls_rsa_set_padding(esp_mbedtls_pk_rsa(pk),
                                       MBEDTLS_RSA_PKCS_V21,
                                       MBEDTLS_MD_SHA256)) != 0) {
        esp_mbedtls_printf(" failed\n  ! Padding not supported\n");
        goto exit;
    }

    /*
     * Compute the SHA-256 hash of the input file,
     * then calculate the RSA signature of the hash.
     */
    esp_mbedtls_printf("\n  . Generating the RSA/SHA-256 signature");
    fflush(stdout);

    if ((ret = esp_mbedtls_md_file(
             esp_mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
             argv[2], hash)) != 0) {
        esp_mbedtls_printf(" failed\n  ! Could not open or read %s\n\n", argv[2]);
        goto exit;
    }

    if ((ret = esp_mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, 0,
                               buf, sizeof(buf), &olen,
                               esp_mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_pk_sign returned %d\n\n", ret);
        goto exit;
    }

    /*
     * Write the signature into <filename>.sig
     */
    esp_mbedtls_snprintf(filename, 512, "%s.sig", argv[2]);

    if ((f = fopen(filename, "wb+")) == NULL) {
        esp_mbedtls_printf(" failed\n  ! Could not create %s\n\n", filename);
        goto exit;
    }

    if (fwrite(buf, 1, olen, f) != olen) {
        esp_mbedtls_printf("failed\n  ! fwrite failed\n\n");
        fclose(f);
        goto exit;
    }

    fclose(f);

    esp_mbedtls_printf("\n  . Done (created \"%s\")\n\n", filename);

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:
    esp_mbedtls_pk_free(&pk);
    esp_mbedtls_ctr_drbg_free(&ctr_drbg);
    esp_mbedtls_entropy_free(&entropy);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    esp_mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    esp_mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_RSA_C &&
          MBEDTLS_MD_CAN_SHA256 && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO &&
          MBEDTLS_CTR_DRBG_C */
