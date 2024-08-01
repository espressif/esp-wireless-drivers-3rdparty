#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "common.h"

//4 Kb should be enough for every bug ;-)
#define MAX_LEN 0x1000

#if defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_ENTROPY_C)
const char *pers = "fuzz_privkey";
#endif // MBEDTLS_PK_PARSE_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_ENTROPY_C

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#if defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_ENTROPY_C)
    int ret;
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    if (Size > MAX_LEN) {
        //only work on small inputs
        Size = MAX_LEN;
    }

    esp_mbedtls_ctr_drbg_init(&ctr_drbg);
    esp_mbedtls_entropy_init(&entropy);
    esp_mbedtls_pk_init(&pk);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = esp_psa_crypto_init();
    if (status != PSA_SUCCESS) {
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    if (esp_mbedtls_ctr_drbg_seed(&ctr_drbg, dummy_entropy, &entropy,
                              (const unsigned char *) pers, strlen(pers)) != 0) {
        goto exit;
    }

    ret = esp_mbedtls_pk_parse_key(&pk, Data, Size, NULL, 0,
                               dummy_random, &ctr_drbg);
    if (ret == 0) {
#if defined(MBEDTLS_RSA_C)
        if (esp_mbedtls_pk_get_type(&pk) == MBEDTLS_PK_RSA) {
            mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
            mbedtls_rsa_context *rsa;

            esp_mbedtls_mpi_init(&N); esp_mbedtls_mpi_init(&P); esp_mbedtls_mpi_init(&Q);
            esp_mbedtls_mpi_init(&D); esp_mbedtls_mpi_init(&E); esp_mbedtls_mpi_init(&DP);
            esp_mbedtls_mpi_init(&DQ); esp_mbedtls_mpi_init(&QP);

            rsa = esp_mbedtls_pk_rsa(pk);
            if (esp_mbedtls_rsa_export(rsa, &N, &P, &Q, &D, &E) != 0) {
                abort();
            }
            if (esp_mbedtls_rsa_export_crt(rsa, &DP, &DQ, &QP) != 0) {
                abort();
            }

            esp_mbedtls_mpi_free(&N); esp_mbedtls_mpi_free(&P); esp_mbedtls_mpi_free(&Q);
            esp_mbedtls_mpi_free(&D); esp_mbedtls_mpi_free(&E); esp_mbedtls_mpi_free(&DP);
            esp_mbedtls_mpi_free(&DQ); esp_mbedtls_mpi_free(&QP);
        } else
#endif
#if defined(MBEDTLS_ECP_C)
        if (esp_mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY ||
            esp_mbedtls_pk_get_type(&pk) == MBEDTLS_PK_ECKEY_DH) {
            mbedtls_ecp_keypair *ecp = esp_mbedtls_pk_ec(pk);
            mbedtls_ecp_group_id grp_id = esp_mbedtls_ecp_keypair_get_group_id(ecp);
            const mbedtls_ecp_curve_info *curve_info =
                esp_mbedtls_ecp_curve_info_from_grp_id(grp_id);

            /* If the curve is not supported, the key should not have been
             * accepted. */
            if (curve_info == NULL) {
                abort();
            }
        } else
#endif
        {
            /* The key is valid but is not of a supported type.
             * This should not happen. */
            abort();
        }
    }
exit:
    esp_mbedtls_entropy_free(&entropy);
    esp_mbedtls_ctr_drbg_free(&ctr_drbg);
    esp_mbedtls_pk_free(&pk);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    esp_mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#else
    (void) Data;
    (void) Size;
#endif // MBEDTLS_PK_PARSE_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_ENTROPY_C

    return 0;
}
