// Copyright 2023 Espressif Systems (Shanghai) PTE LTD
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef _ESP_MBEDTLS_H_
#define _ESP_MBEDTLS_H_

#ifdef __NuttX__
#  define mbedtls_aes_crypt_cbc                     esp_mbedtls_aes_crypt_cbc
#  define mbedtls_aes_crypt_ctr                     esp_mbedtls_aes_crypt_ctr
#  define mbedtls_aes_crypt_ecb                     esp_mbedtls_aes_crypt_ecb
#  define mbedtls_aes_free                          esp_mbedtls_aes_free
#  define mbedtls_aes_init                          esp_mbedtls_aes_init
#  define mbedtls_aes_setkey_dec                    esp_mbedtls_aes_setkey_dec
#  define mbedtls_aes_setkey_enc                    esp_mbedtls_aes_setkey_enc
#  define mbedtls_asn1_write_algorithm_identifier   esp_mbedtls_asn1_write_algorithm_identifier
#  define mbedtls_asn1_write_len                    esp_mbedtls_asn1_write_len
#  define mbedtls_asn1_write_oid                    esp_mbedtls_asn1_write_oid
#  define mbedtls_asn1_write_tag                    esp_mbedtls_asn1_write_tag
#  define mbedtls_ccm_encrypt_and_tag               esp_mbedtls_ccm_encrypt_and_tag
#  define mbedtls_ccm_free                          esp_mbedtls_ccm_free
#  define mbedtls_ccm_init                          esp_mbedtls_ccm_init
#  define mbedtls_ccm_setkey                        esp_mbedtls_ccm_setkey
#  define mbedtls_ccm_star_auth_decrypt             esp_mbedtls_ccm_star_auth_decrypt
#  define mbedtls_cipher_cmac_finish                esp_mbedtls_cipher_cmac_finish
#  define mbedtls_cipher_cmac_starts                esp_mbedtls_cipher_cmac_starts
#  define mbedtls_cipher_cmac_update                esp_mbedtls_cipher_cmac_update
#  define mbedtls_cipher_finish                     esp_mbedtls_cipher_finish
#  define mbedtls_cipher_free                       esp_mbedtls_cipher_free
#  define mbedtls_cipher_info_from_type             esp_mbedtls_cipher_info_from_type
#  define mbedtls_cipher_init                       esp_mbedtls_cipher_init
#  define mbedtls_cipher_reset                      esp_mbedtls_cipher_reset
#  define mbedtls_cipher_set_iv                     esp_mbedtls_cipher_set_iv
#  define mbedtls_cipher_set_padding_mode           esp_mbedtls_cipher_set_padding_mode
#  define mbedtls_cipher_setkey                     esp_mbedtls_cipher_setkey
#  define mbedtls_cipher_setup                      esp_mbedtls_cipher_setup
#  define mbedtls_cipher_update                     esp_mbedtls_cipher_update
#  define mbedtls_ctr_drbg_free                     esp_mbedtls_ctr_drbg_free
#  define mbedtls_ctr_drbg_init                     esp_mbedtls_ctr_drbg_init
#  define mbedtls_ctr_drbg_random                   esp_mbedtls_ctr_drbg_random
#  define mbedtls_ctr_drbg_seed                     esp_mbedtls_ctr_drbg_seed
#  define mbedtls_des_crypt_ecb                     esp_mbedtls_des_crypt_ecb
#  define mbedtls_des_free                          esp_mbedtls_des_free
#  define mbedtls_des_init                          esp_mbedtls_des_init
#  define mbedtls_des_setkey_enc                    esp_mbedtls_des_setkey_enc
#  define mbedtls_ecdh_calc_secret                  esp_mbedtls_ecdh_calc_secret
#  define mbedtls_ecdh_free                         esp_mbedtls_ecdh_free
#  define mbedtls_ecdh_gen_public                   esp_mbedtls_ecdh_gen_public
#  define mbedtls_ecdh_get_params                   esp_mbedtls_ecdh_get_params
#  define mbedtls_ecdh_init                         esp_mbedtls_ecdh_init
#  define mbedtls_ecdsa_free                        esp_mbedtls_ecdsa_free
#  define mbedtls_ecdsa_from_keypair                esp_mbedtls_ecdsa_from_keypair
#  define mbedtls_ecdsa_init                        esp_mbedtls_ecdsa_init
#  define mbedtls_ecdsa_read_signature              esp_mbedtls_ecdsa_read_signature
#  define mbedtls_ecdsa_sign                        esp_mbedtls_ecdsa_sign
#  define mbedtls_ecdsa_verify                      esp_mbedtls_ecdsa_verify
#  define mbedtls_ecp_check_pubkey                  esp_mbedtls_ecp_check_pubkey
#  define mbedtls_ecp_copy                          esp_mbedtls_ecp_copy
#  define mbedtls_ecp_curve_info_from_grp_id        esp_mbedtls_ecp_curve_info_from_grp_id
#  define mbedtls_ecp_curve_info_from_name          esp_mbedtls_ecp_curve_info_from_name
#  define mbedtls_ecp_gen_key                       esp_mbedtls_ecp_gen_key
#  define mbedtls_ecp_group_copy                    esp_mbedtls_ecp_group_copy
#  define mbedtls_ecp_group_free                    esp_mbedtls_ecp_group_free
#  define mbedtls_ecp_group_init                    esp_mbedtls_ecp_group_init
#  define mbedtls_ecp_group_load                    esp_mbedtls_ecp_group_load
#  define mbedtls_ecp_is_zero                       esp_mbedtls_ecp_is_zero
#  define mbedtls_ecp_mul                           esp_mbedtls_ecp_mul
#  define mbedtls_ecp_muladd                        esp_mbedtls_ecp_muladd
#  define mbedtls_ecp_point_cmp                     esp_mbedtls_ecp_point_cmp
#  define mbedtls_ecp_point_free                    esp_mbedtls_ecp_point_free
#  define mbedtls_ecp_point_init                    esp_mbedtls_ecp_point_init
#  define mbedtls_ecp_point_write_binary            esp_mbedtls_ecp_point_write_binary
#  define mbedtls_entropy_free                      esp_mbedtls_entropy_free
#  define mbedtls_entropy_func                      esp_mbedtls_entropy_func
#  define mbedtls_entropy_init                      esp_mbedtls_entropy_init
#  define mbedtls_md_finish                         esp_mbedtls_md_finish
#  define mbedtls_md_free                           esp_mbedtls_md_free
#  define mbedtls_md_get_type                       esp_mbedtls_md_get_type
#  define mbedtls_md_hmac_finish                    esp_mbedtls_md_hmac_finish
#  define mbedtls_md_hmac_starts                    esp_mbedtls_md_hmac_starts
#  define mbedtls_md_hmac_update                    esp_mbedtls_md_hmac_update
#  define mbedtls_md_info_from_ctx                  esp_mbedtls_md_info_from_ctx
#  define mbedtls_md_info_from_type                 esp_mbedtls_md_info_from_type
#  define mbedtls_md_init                           esp_mbedtls_md_init
#  define mbedtls_md_setup                          esp_mbedtls_md_setup
#  define mbedtls_md_starts                         esp_mbedtls_md_starts
#  define mbedtls_md_update                         esp_mbedtls_md_update
#  define mbedtls_mpi_add_int                       esp_mbedtls_mpi_add_int
#  define mbedtls_mpi_add_mpi                       esp_mbedtls_mpi_add_mpi
#  define mbedtls_mpi_bitlen                        esp_mbedtls_mpi_bitlen
#  define mbedtls_mpi_cmp_int                       esp_mbedtls_mpi_cmp_int
#  define mbedtls_mpi_cmp_mpi                       esp_mbedtls_mpi_cmp_mpi
#  define mbedtls_mpi_copy                          esp_mbedtls_mpi_copy
#  define mbedtls_mpi_div_int                       esp_mbedtls_mpi_div_int
#  define mbedtls_mpi_div_mpi                       esp_mbedtls_mpi_div_mpi
#  define mbedtls_mpi_exp_mod                       esp_mbedtls_mpi_exp_mod
#  define mbedtls_mpi_free                          esp_mbedtls_mpi_free
#  define mbedtls_mpi_get_bit                       esp_mbedtls_mpi_get_bit
#  define mbedtls_mpi_init                          esp_mbedtls_mpi_init
#  define mbedtls_mpi_inv_mod                       esp_mbedtls_mpi_inv_mod
#  define mbedtls_mpi_lset                          esp_mbedtls_mpi_lset
#  define mbedtls_mpi_mod_mpi                       esp_mbedtls_mpi_mod_mpi
#  define mbedtls_mpi_mul_mpi                       esp_mbedtls_mpi_mul_mpi
#  define mbedtls_mpi_random                        esp_mbedtls_mpi_random
#  define mbedtls_mpi_read_binary                   esp_mbedtls_mpi_read_binary
#  define mbedtls_mpi_shift_r                       esp_mbedtls_mpi_shift_r
#  define mbedtls_mpi_size                          esp_mbedtls_mpi_size
#  define mbedtls_mpi_sub_int                       esp_mbedtls_mpi_sub_int
#  define mbedtls_mpi_sub_mpi                       esp_mbedtls_mpi_sub_mpi
#  define mbedtls_mpi_write_binary                  esp_mbedtls_mpi_write_binary
#  define mbedtls_mpi_write_string                  esp_mbedtls_mpi_write_string
#  define mbedtls_nist_kw_free                      esp_mbedtls_nist_kw_free
#  define mbedtls_nist_kw_init                      esp_mbedtls_nist_kw_init
#  define mbedtls_nist_kw_setkey                    esp_mbedtls_nist_kw_setkey
#  define mbedtls_nist_kw_unwrap                    esp_mbedtls_nist_kw_unwrap
#  define mbedtls_nist_kw_wrap                      esp_mbedtls_nist_kw_wrap
#  define mbedtls_oid_get_oid_by_ec_grp             esp_mbedtls_oid_get_oid_by_ec_grp
#  define mbedtls_oid_get_oid_by_pk_alg             esp_mbedtls_oid_get_oid_by_pk_alg
#  define mbedtls_pk_can_do                         esp_mbedtls_pk_can_do
#  define mbedtls_pk_check_pair                     esp_mbedtls_pk_check_pair
#  define mbedtls_pk_ec                             esp_mbedtls_pk_ec
#  define mbedtls_pk_free                           esp_mbedtls_pk_free
#  define mbedtls_pk_get_bitlen                     esp_mbedtls_pk_get_bitlen
#  define mbedtls_pk_get_type                       esp_mbedtls_pk_get_type
#  define mbedtls_pk_info_from_type                 esp_mbedtls_pk_info_from_type
#  define mbedtls_pk_init                           esp_mbedtls_pk_init
#  define mbedtls_pk_parse_key                      esp_mbedtls_pk_parse_key
#  define mbedtls_pk_parse_public_key               esp_mbedtls_pk_parse_public_key
#  define mbedtls_pk_parse_subpubkey                esp_mbedtls_pk_parse_subpubkey
#  define mbedtls_pk_rsa                            esp_mbedtls_pk_rsa
#  define mbedtls_pk_setup                          esp_mbedtls_pk_setup
#  define mbedtls_pk_write_key_der                  esp_mbedtls_pk_write_key_der
#  define mbedtls_pk_write_pubkey                   esp_mbedtls_pk_write_pubkey
#  define mbedtls_pk_write_pubkey_der               esp_mbedtls_pk_write_pubkey_der
#  define mbedtls_pkcs5_pbkdf2_hmac                 esp_mbedtls_pkcs5_pbkdf2_hmac
#  define mbedtls_pkcs5_pbkdf2_hmac_ext             esp_mbedtls_pkcs5_pbkdf2_hmac_ext
#  define mbedtls_platform_zeroize                  esp_mbedtls_platform_zeroize
#  define mbedtls_rsa_copy                          esp_mbedtls_rsa_copy
#  define mbedtls_rsa_get_len                       esp_mbedtls_rsa_get_len
#  define mbedtls_rsa_pkcs1_encrypt                 esp_mbedtls_rsa_pkcs1_encrypt
#  define mbedtls_rsa_pkcs1_sign                    esp_mbedtls_rsa_pkcs1_sign
#  define mbedtls_rsa_public                        esp_mbedtls_rsa_public
#  define mbedtls_rsa_rsaes_pkcs1_v15_decrypt       esp_mbedtls_rsa_rsaes_pkcs1_v15_decrypt
#  define mbedtls_ssl_conf_authmode                 esp_mbedtls_ssl_conf_authmode
#  define mbedtls_ssl_conf_ca_chain                 esp_mbedtls_ssl_conf_ca_chain
#  define mbedtls_ssl_conf_cert_profile             esp_mbedtls_ssl_conf_cert_profile
#  define mbedtls_ssl_conf_ciphersuites             esp_mbedtls_ssl_conf_ciphersuites
#  define mbedtls_ssl_conf_own_cert                 esp_mbedtls_ssl_conf_own_cert
#  define mbedtls_ssl_conf_rng                      esp_mbedtls_ssl_conf_rng
#  define mbedtls_ssl_conf_sig_algs                 esp_mbedtls_ssl_conf_sig_algs
#  define mbedtls_ssl_config_defaults               esp_mbedtls_ssl_config_defaults
#  define mbedtls_ssl_config_free                   esp_mbedtls_ssl_config_free
#  define mbedtls_ssl_config_init                   esp_mbedtls_ssl_config_init
#  define mbedtls_ssl_free                          esp_mbedtls_ssl_free
#  define mbedtls_ssl_get_ciphersuite               esp_mbedtls_ssl_get_ciphersuite
#  define mbedtls_ssl_get_version                   esp_mbedtls_ssl_get_version
#  define mbedtls_ssl_handshake_step                esp_mbedtls_ssl_handshake_step
#  define mbedtls_ssl_init                          esp_mbedtls_ssl_init
#  define mbedtls_ssl_is_handshake_over             esp_mbedtls_ssl_is_handshake_over
#  define mbedtls_ssl_read                          esp_mbedtls_ssl_read
#  define mbedtls_ssl_session_reset                 esp_mbedtls_ssl_session_reset
#  define mbedtls_ssl_set_bio                       esp_mbedtls_ssl_set_bio
#  define mbedtls_ssl_set_export_keys_cb            esp_mbedtls_ssl_set_export_keys_cb
#  define mbedtls_ssl_setup                         esp_mbedtls_ssl_setup
#  define mbedtls_ssl_tls_prf                       esp_mbedtls_ssl_tls_prf
#  define mbedtls_ssl_write                         esp_mbedtls_ssl_write
#  define mbedtls_x509_crt_free                     esp_mbedtls_x509_crt_free
#  define mbedtls_x509_crt_init                     esp_mbedtls_x509_crt_init
#  define mbedtls_x509_crt_parse                    esp_mbedtls_x509_crt_parse
#  define mbedtls_x509_crt_verify                   esp_mbedtls_x509_crt_verify
#endif

#endif /* _ESP_MBEDTLS_H_ */
