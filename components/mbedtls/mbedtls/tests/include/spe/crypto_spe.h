/*
 * Copyright The Mbed TLS Contributors
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 */

/**
 * \file crypto_spe.h
 *
 * \brief When Mbed TLS is built with the MBEDTLS_PSA_CRYPTO_SPM option
 *        enabled, this header is included by all .c files in Mbed TLS that
 *        use PSA Crypto function names. This avoids duplication of symbols
 *        between TF-M and Mbed TLS.
 *
 * \note  This file should be included before including any PSA Crypto headers
 *        from Mbed TLS.
 */

#ifndef CRYPTO_SPE_H
#define CRYPTO_SPE_H

#define PSA_FUNCTION_NAME(x) mbedcrypto__ ## x

#define esp_psa_crypto_init \
    PSA_FUNCTION_NAME(esp_psa_crypto_init)
#define esp_psa_key_derivation_get_capacity \
    PSA_FUNCTION_NAME(esp_psa_key_derivation_get_capacity)
#define esp_psa_key_derivation_set_capacity \
    PSA_FUNCTION_NAME(esp_psa_key_derivation_set_capacity)
#define esp_psa_key_derivation_input_bytes \
    PSA_FUNCTION_NAME(esp_psa_key_derivation_input_bytes)
#define esp_psa_key_derivation_output_bytes \
    PSA_FUNCTION_NAME(esp_psa_key_derivation_output_bytes)
#define esp_psa_key_derivation_input_key \
    PSA_FUNCTION_NAME(esp_psa_key_derivation_input_key)
#define esp_psa_key_derivation_output_key \
    PSA_FUNCTION_NAME(esp_psa_key_derivation_output_key)
#define esp_psa_key_derivation_setup \
    PSA_FUNCTION_NAME(esp_psa_key_derivation_setup)
#define esp_psa_key_derivation_abort \
    PSA_FUNCTION_NAME(esp_psa_key_derivation_abort)
#define esp_psa_key_derivation_key_agreement \
    PSA_FUNCTION_NAME(esp_psa_key_derivation_key_agreement)
#define esp_psa_raw_key_agreement \
    PSA_FUNCTION_NAME(esp_psa_raw_key_agreement)
#define esp_psa_generate_random \
    PSA_FUNCTION_NAME(esp_psa_generate_random)
#define esp_psa_aead_encrypt \
    PSA_FUNCTION_NAME(esp_psa_aead_encrypt)
#define esp_psa_aead_decrypt \
    PSA_FUNCTION_NAME(esp_psa_aead_decrypt)
#define esp_psa_open_key \
    PSA_FUNCTION_NAME(esp_psa_open_key)
#define esp_psa_close_key \
    PSA_FUNCTION_NAME(esp_psa_close_key)
#define esp_psa_import_key \
    PSA_FUNCTION_NAME(esp_psa_import_key)
#define esp_psa_destroy_key \
    PSA_FUNCTION_NAME(esp_psa_destroy_key)
#define esp_psa_get_key_attributes \
    PSA_FUNCTION_NAME(esp_psa_get_key_attributes)
#define esp_psa_reset_key_attributes \
    PSA_FUNCTION_NAME(esp_psa_reset_key_attributes)
#define esp_psa_export_key \
    PSA_FUNCTION_NAME(esp_psa_export_key)
#define esp_psa_export_public_key \
    PSA_FUNCTION_NAME(esp_psa_export_public_key)
#define esp_psa_purge_key \
    PSA_FUNCTION_NAME(esp_psa_purge_key)
#define esp_psa_copy_key \
    PSA_FUNCTION_NAME(esp_psa_copy_key)
#define psa_cipher_operation_init \
    PSA_FUNCTION_NAME(psa_cipher_operation_init)
#define esp_psa_cipher_generate_iv \
    PSA_FUNCTION_NAME(esp_psa_cipher_generate_iv)
#define esp_psa_cipher_set_iv \
    PSA_FUNCTION_NAME(esp_psa_cipher_set_iv)
#define esp_psa_cipher_encrypt_setup \
    PSA_FUNCTION_NAME(esp_psa_cipher_encrypt_setup)
#define esp_psa_cipher_decrypt_setup \
    PSA_FUNCTION_NAME(esp_psa_cipher_decrypt_setup)
#define esp_psa_cipher_update \
    PSA_FUNCTION_NAME(esp_psa_cipher_update)
#define esp_psa_cipher_finish \
    PSA_FUNCTION_NAME(esp_psa_cipher_finish)
#define esp_psa_cipher_abort \
    PSA_FUNCTION_NAME(esp_psa_cipher_abort)
#define psa_hash_operation_init \
    PSA_FUNCTION_NAME(psa_hash_operation_init)
#define esp_psa_hash_setup \
    PSA_FUNCTION_NAME(esp_psa_hash_setup)
#define esp_psa_hash_update \
    PSA_FUNCTION_NAME(esp_psa_hash_update)
#define esp_psa_hash_finish \
    PSA_FUNCTION_NAME(esp_psa_hash_finish)
#define esp_psa_hash_verify \
    PSA_FUNCTION_NAME(esp_psa_hash_verify)
#define esp_psa_hash_abort \
    PSA_FUNCTION_NAME(esp_psa_hash_abort)
#define esp_psa_hash_clone \
    PSA_FUNCTION_NAME(esp_psa_hash_clone)
#define esp_psa_hash_compute \
    PSA_FUNCTION_NAME(esp_psa_hash_compute)
#define esp_psa_hash_compare \
    PSA_FUNCTION_NAME(esp_psa_hash_compare)
#define psa_mac_operation_init \
    PSA_FUNCTION_NAME(psa_mac_operation_init)
#define esp_psa_mac_sign_setup \
    PSA_FUNCTION_NAME(esp_psa_mac_sign_setup)
#define esp_psa_mac_verify_setup \
    PSA_FUNCTION_NAME(esp_psa_mac_verify_setup)
#define esp_psa_mac_update \
    PSA_FUNCTION_NAME(esp_psa_mac_update)
#define esp_psa_mac_sign_finish \
    PSA_FUNCTION_NAME(esp_psa_mac_sign_finish)
#define esp_psa_mac_verify_finish \
    PSA_FUNCTION_NAME(esp_psa_mac_verify_finish)
#define esp_psa_mac_abort \
    PSA_FUNCTION_NAME(esp_psa_mac_abort)
#define esp_psa_sign_hash \
    PSA_FUNCTION_NAME(esp_psa_sign_hash)
#define esp_psa_verify_hash \
    PSA_FUNCTION_NAME(esp_psa_verify_hash)
#define esp_psa_asymmetric_encrypt \
    PSA_FUNCTION_NAME(esp_psa_asymmetric_encrypt)
#define esp_psa_asymmetric_decrypt \
    PSA_FUNCTION_NAME(esp_psa_asymmetric_decrypt)
#define esp_psa_generate_key \
    PSA_FUNCTION_NAME(esp_psa_generate_key)

#endif /* CRYPTO_SPE_H */
