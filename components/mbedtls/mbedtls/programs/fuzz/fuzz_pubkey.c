#include <stdint.h>
#include <stdlib.h>
#include "mbedtls/pk.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#ifdef MBEDTLS_PK_PARSE_C
    int ret;
    mbedtls_pk_context pk;

    esp_mbedtls_pk_init(&pk);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = esp_psa_crypto_init();
    if (status != PSA_SUCCESS) {
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    ret = esp_mbedtls_pk_parse_public_key(&pk, Data, Size);
    if (ret == 0) {
#if defined(MBEDTLS_RSA_C)
        if (esp_mbedtls_pk_get_type(&pk) == MBEDTLS_PK_RSA) {
            mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
            mbedtls_rsa_context *rsa;

            esp_mbedtls_mpi_init(&N); esp_mbedtls_mpi_init(&P); esp_mbedtls_mpi_init(&Q);
            esp_mbedtls_mpi_init(&D); esp_mbedtls_mpi_init(&E); esp_mbedtls_mpi_init(&DP);
            esp_mbedtls_mpi_init(&DQ); esp_mbedtls_mpi_init(&QP);

            rsa = esp_mbedtls_pk_rsa(pk);
            if (esp_mbedtls_rsa_export(rsa, &N, NULL, NULL, NULL, &E) != 0) {
                abort();
            }
            if (esp_mbedtls_rsa_export(rsa, &N, &P, &Q, &D, &E) != MBEDTLS_ERR_RSA_BAD_INPUT_DATA) {
                abort();
            }
            if (esp_mbedtls_rsa_export_crt(rsa, &DP, &DQ, &QP) != MBEDTLS_ERR_RSA_BAD_INPUT_DATA) {
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

            /* It's a public key, so the private value should not have
             * been changed from its initialization to 0. */
            mbedtls_mpi d;
            esp_mbedtls_mpi_init(&d);
            if (esp_mbedtls_ecp_export(ecp, NULL, &d, NULL) != 0) {
                abort();
            }
            if (esp_mbedtls_mpi_cmp_int(&d, 0) != 0) {
                abort();
            }
            esp_mbedtls_mpi_free(&d);
        } else
#endif
        {
            /* The key is valid but is not of a supported type.
             * This should not happen. */
            abort();
        }
    }
#if defined(MBEDTLS_USE_PSA_CRYPTO)
exit:
    esp_mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */
    esp_mbedtls_pk_free(&pk);
#else
    (void) Data;
    (void) Size;
#endif //MBEDTLS_PK_PARSE_C

    return 0;
}
