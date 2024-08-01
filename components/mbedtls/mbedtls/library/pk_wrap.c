/*
 *  Public Key abstraction layer: wrapper functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_PK_C)
#include "pk_wrap.h"
#include "pk_internal.h"
#include "mbedtls/error.h"
#include "mbedtls/psa_util.h"

/* Even if RSA not activated, for the sake of RSA-alt */
#include "mbedtls/rsa.h"

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_ECDSA_C)
#include "mbedtls/ecdsa.h"
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa_util_internal.h"
#include "psa/crypto.h"
#include "mbedtls/psa_util.h"

#if defined(MBEDTLS_RSA_C)
#include "pkwrite.h"
#include "rsa_internal.h"
#endif

#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
#include "mbedtls/asn1write.h"
#include "mbedtls/asn1.h"
#endif
#endif  /* MBEDTLS_USE_PSA_CRYPTO */

#include "mbedtls/platform.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

#if defined(MBEDTLS_RSA_C)
static int esp_rsa_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_RSA ||
           type == MBEDTLS_PK_RSASSA_PSS;
}

static size_t esp_rsa_get_bitlen(mbedtls_pk_context *pk)
{
    const mbedtls_rsa_context *rsa = (const mbedtls_rsa_context *) pk->pk_ctx;
    return esp_mbedtls_rsa_get_bitlen(rsa);
}

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int esp_rsa_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    int esp_key_len;
    unsigned char buf[MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES];
    unsigned char *p = buf + sizeof(buf);
    psa_algorithm_t psa_alg_md;
    size_t rsa_len = esp_mbedtls_rsa_get_len(rsa);

#if SIZE_MAX > UINT_MAX
    if (md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    if (esp_mbedtls_rsa_get_padding_mode(rsa) == MBEDTLS_RSA_PKCS_V21) {
        psa_alg_md = PSA_ALG_RSA_PSS(esp_mbedtls_md_psa_alg_from_type(md_alg));
    } else {
        psa_alg_md = PSA_ALG_RSA_PKCS1V15_SIGN(esp_mbedtls_md_psa_alg_from_type(md_alg));
    }

    if (sig_len < rsa_len) {
        return MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }

    esp_key_len = esp_mbedtls_rsa_write_pubkey(rsa, buf, &p);
    if (esp_key_len <= 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, psa_alg_md);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);

    status = esp_psa_import_key(&attributes,
                            buf + sizeof(buf) - esp_key_len, esp_key_len,
                            &key_id);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = esp_psa_verify_hash(key_id, psa_alg_md, hash, hash_len,
                             sig, sig_len);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
    ret = 0;

cleanup:
    status = esp_psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int esp_rsa_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           const unsigned char *sig, size_t sig_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    size_t rsa_len = esp_mbedtls_rsa_get_len(rsa);

#if SIZE_MAX > UINT_MAX
    if (md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    if (sig_len < rsa_len) {
        return MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }

    if ((ret = esp_mbedtls_rsa_pkcs1_verify(rsa, md_alg,
                                        (unsigned int) hash_len,
                                        hash, sig)) != 0) {
        return ret;
    }

    /* The buffer contains a valid signature followed by extra data.
     * We have a special error code for that so that so that callers can
     * use esp_mbedtls_pk_verify() to check "Does the buffer start with a
     * valid signature?" and not just "Does the buffer contain a valid
     * signature?". */
    if (sig_len > rsa_len) {
        return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return 0;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
int  esp_mbedtls_pk_psa_rsa_sign_ext(psa_algorithm_t alg,
                                 mbedtls_rsa_context *rsa_ctx,
                                 const unsigned char *hash, size_t hash_len,
                                 unsigned char *sig, size_t sig_size,
                                 size_t *sig_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    int esp_key_len;
    unsigned char *buf = NULL;
    unsigned char *p;

    buf = esp_mbedtls_calloc(1, MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES);
    if (buf == NULL) {
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }
    p = buf + MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES;

    *sig_len = esp_mbedtls_rsa_get_len(rsa_ctx);
    if (sig_size < *sig_len) {
        esp_mbedtls_free(buf);
        return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    esp_key_len = esp_mbedtls_rsa_write_key(rsa_ctx, buf, &p);
    if (esp_key_len <= 0) {
        esp_mbedtls_free(buf);
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);

    status = esp_psa_import_key(&attributes,
                            buf + MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES - esp_key_len, esp_key_len,
                            &key_id);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }
    status = esp_psa_sign_hash(key_id, alg, hash, hash_len,
                           sig, sig_size, sig_len);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    esp_mbedtls_free(buf);
    status = esp_psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }
    return ret;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int esp_rsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    ((void) f_rng);
    ((void) p_rng);

    psa_algorithm_t psa_md_alg;
    psa_md_alg = esp_mbedtls_md_psa_alg_from_type(md_alg);
    if (psa_md_alg == 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    psa_algorithm_t psa_alg;
    if (esp_mbedtls_rsa_get_padding_mode(esp_mbedtls_pk_rsa(*pk)) == MBEDTLS_RSA_PKCS_V21) {
        psa_alg = PSA_ALG_RSA_PSS(psa_md_alg);
    } else {
        psa_alg = PSA_ALG_RSA_PKCS1V15_SIGN(psa_md_alg);
    }

    return esp_mbedtls_pk_psa_rsa_sign_ext(psa_alg, pk->pk_ctx, hash, hash_len,
                                       sig, sig_size, sig_len);
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int esp_rsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                         const unsigned char *hash, size_t hash_len,
                         unsigned char *sig, size_t sig_size, size_t *sig_len,
                         int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;

#if SIZE_MAX > UINT_MAX
    if (md_alg == MBEDTLS_MD_NONE && UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    *sig_len = esp_mbedtls_rsa_get_len(rsa);
    if (sig_size < *sig_len) {
        return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    return esp_mbedtls_rsa_pkcs1_sign(rsa, f_rng, p_rng,
                                  md_alg, (unsigned int) hash_len,
                                  hash, sig);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int esp_rsa_decrypt_wrap(mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t psa_md_alg, decrypt_alg;
    psa_status_t status;
    int esp_key_len;
    unsigned char buf[MBEDTLS_PK_RSA_PRV_DER_MAX_BYTES];
    unsigned char *p = buf + sizeof(buf);

    ((void) f_rng);
    ((void) p_rng);

    if (ilen != esp_mbedtls_rsa_get_len(rsa)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    esp_key_len = esp_mbedtls_rsa_write_key(rsa, buf, &p);
    if (esp_key_len <= 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DECRYPT);
    if (esp_mbedtls_rsa_get_padding_mode(rsa) == MBEDTLS_RSA_PKCS_V21) {
        psa_md_alg = esp_mbedtls_md_psa_alg_from_type((mbedtls_md_type_t) esp_mbedtls_rsa_get_md_alg(rsa));
        decrypt_alg = PSA_ALG_RSA_OAEP(psa_md_alg);
    } else {
        decrypt_alg = PSA_ALG_RSA_PKCS1V15_CRYPT;
    }
    psa_set_key_algorithm(&attributes, decrypt_alg);

    status = esp_psa_import_key(&attributes,
                            buf + sizeof(buf) - esp_key_len, esp_key_len,
                            &key_id);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = esp_psa_asymmetric_decrypt(key_id, decrypt_alg,
                                    input, ilen,
                                    NULL, 0,
                                    output, osize, olen);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    esp_mbedtls_platform_zeroize(buf, sizeof(buf));
    status = esp_psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int esp_rsa_decrypt_wrap(mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;

    if (ilen != esp_mbedtls_rsa_get_len(rsa)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    return esp_mbedtls_rsa_pkcs1_decrypt(rsa, f_rng, p_rng,
                                     olen, input, output, osize);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static int esp_rsa_encrypt_wrap(mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t psa_md_alg, psa_encrypt_alg;
    psa_status_t status;
    int esp_key_len;
    unsigned char buf[MBEDTLS_PK_RSA_PUB_DER_MAX_BYTES];
    unsigned char *p = buf + sizeof(buf);

    ((void) f_rng);
    ((void) p_rng);

    if (esp_mbedtls_rsa_get_len(rsa) > osize) {
        return MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }

    esp_key_len = esp_mbedtls_rsa_write_pubkey(rsa, buf, &p);
    if (esp_key_len <= 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT);
    if (esp_mbedtls_rsa_get_padding_mode(rsa) == MBEDTLS_RSA_PKCS_V21) {
        psa_md_alg = esp_mbedtls_md_psa_alg_from_type((mbedtls_md_type_t) esp_mbedtls_rsa_get_md_alg(rsa));
        psa_encrypt_alg = PSA_ALG_RSA_OAEP(psa_md_alg);
    } else {
        psa_encrypt_alg = PSA_ALG_RSA_PKCS1V15_CRYPT;
    }
    psa_set_key_algorithm(&attributes, psa_encrypt_alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_PUBLIC_KEY);

    status = esp_psa_import_key(&attributes,
                            buf + sizeof(buf) - esp_key_len, esp_key_len,
                            &key_id);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    status = esp_psa_asymmetric_encrypt(key_id, psa_encrypt_alg,
                                    input, ilen,
                                    NULL, 0,
                                    output, osize, olen);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    status = esp_psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int esp_rsa_encrypt_wrap(mbedtls_pk_context *pk,
                            const unsigned char *input, size_t ilen,
                            unsigned char *output, size_t *olen, size_t osize,
                            int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;
    *olen = esp_mbedtls_rsa_get_len(rsa);

    if (*olen > osize) {
        return MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE;
    }

    return esp_mbedtls_rsa_pkcs1_encrypt(rsa, f_rng, p_rng,
                                     ilen, input, output);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

static int esp_rsa_check_pair_wrap(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
                               int (*f_rng)(void *, unsigned char *, size_t),
                               void *p_rng)
{
    (void) f_rng;
    (void) p_rng;
    return esp_mbedtls_rsa_check_pub_priv((const mbedtls_rsa_context *) pub->pk_ctx,
                                      (const mbedtls_rsa_context *) prv->pk_ctx);
}

static void *esp_rsa_alloc_wrap(void)
{
    void *ctx = esp_mbedtls_calloc(1, sizeof(mbedtls_rsa_context));

    if (ctx != NULL) {
        esp_mbedtls_rsa_init((mbedtls_rsa_context *) ctx);
    }

    return ctx;
}

static void esp_rsa_free_wrap(void *ctx)
{
    esp_mbedtls_rsa_free((mbedtls_rsa_context *) ctx);
    esp_mbedtls_free(ctx);
}

static void esp_rsa_debug(mbedtls_pk_context *pk, mbedtls_pk_debug_item *items)
{
#if defined(MBEDTLS_RSA_ALT)
    /* Not supported */
    (void) pk;
    (void) items;
#else
    mbedtls_rsa_context *rsa = (mbedtls_rsa_context *) pk->pk_ctx;

    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.N";
    items->value = &(rsa->N);

    items++;

    items->type = MBEDTLS_PK_DEBUG_MPI;
    items->name = "rsa.E";
    items->value = &(rsa->E);
#endif
}

const mbedtls_pk_info_t esp_mbedtls_rsa_info = {
    .type = MBEDTLS_PK_RSA,
    .name = "RSA",
    .get_bitlen = esp_rsa_get_bitlen,
    .can_do = esp_rsa_can_do,
    .verify_func = esp_rsa_verify_wrap,
    .sign_func = esp_rsa_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = esp_rsa_decrypt_wrap,
    .encrypt_func = esp_rsa_encrypt_wrap,
    .check_pair_func = esp_rsa_check_pair_wrap,
    .ctx_alloc_func = esp_rsa_alloc_wrap,
    .ctx_free_func = esp_rsa_free_wrap,
    .debug_func = esp_rsa_debug,
};
#endif /* MBEDTLS_RSA_C */

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
/*
 * Generic EC key
 */
static int esp_eckey_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_ECKEY ||
           type == MBEDTLS_PK_ECKEY_DH ||
           type == MBEDTLS_PK_ECDSA;
}

static size_t esp_eckey_get_bitlen(mbedtls_pk_context *pk)
{
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    return pk->ec_bits;
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
    mbedtls_ecp_keypair *ecp = (mbedtls_ecp_keypair *) pk->pk_ctx;
    return ecp->grp.pbits;
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
}

#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
/* Common helper for ECDSA verify using PSA functions. */
static int esp_ecdsa_verify_psa(unsigned char *key, size_t esp_key_len,
                            psa_ecc_family_t curve, size_t curve_bits,
                            const unsigned char *hash, size_t hash_len,
                            const unsigned char *sig, size_t sig_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t psa_sig_md = PSA_ALG_ECDSA_ANY;
    size_t signature_len = PSA_ECDSA_SIGNATURE_SIZE(curve_bits);
    size_t converted_sig_len;
    unsigned char extracted_sig[PSA_VENDOR_ECDSA_SIGNATURE_MAX_SIZE];
    unsigned char *p;
    psa_status_t status;

    if (curve == 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, psa_sig_md);

    status = esp_psa_import_key(&attributes, key, esp_key_len, &key_id);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    if (signature_len > sizeof(extracted_sig)) {
        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        goto cleanup;
    }

    p = (unsigned char *) sig;
    ret = esp_mbedtls_ecdsa_der_to_raw(curve_bits, p, sig_len, extracted_sig,
                                   sizeof(extracted_sig), &converted_sig_len);
    if (ret != 0) {
        goto cleanup;
    }

    if (converted_sig_len != signature_len) {
        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        goto cleanup;
    }

    status = esp_psa_verify_hash(key_id, psa_sig_md, hash, hash_len,
                             extracted_sig, signature_len);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = 0;

cleanup:
    status = esp_psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}

static int esp_ecdsa_opaque_verify_wrap(mbedtls_pk_context *pk,
                                    mbedtls_md_type_t md_alg,
                                    const unsigned char *hash, size_t hash_len,
                                    const unsigned char *sig, size_t sig_len)
{
    (void) md_alg;
    unsigned char key[MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
    size_t esp_key_len;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_ecc_family_t curve;
    size_t curve_bits;
    psa_status_t status;

    status = esp_psa_get_key_attributes(pk->priv_id, &key_attr);
    if (status != PSA_SUCCESS) {
        return PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }
    curve = PSA_KEY_TYPE_ECC_GET_FAMILY(psa_get_key_type(&key_attr));
    curve_bits = psa_get_key_bits(&key_attr);
    esp_psa_reset_key_attributes(&key_attr);

    status = esp_psa_export_public_key(pk->priv_id, key, sizeof(key), &esp_key_len);
    if (status != PSA_SUCCESS) {
        return PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }

    return esp_ecdsa_verify_psa(key, esp_key_len, curve, curve_bits,
                            hash, hash_len, sig, sig_len);
}

#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
static int esp_ecdsa_verify_wrap(mbedtls_pk_context *pk,
                             mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    (void) md_alg;
    psa_ecc_family_t curve = pk->ec_family;
    size_t curve_bits = pk->ec_bits;

    return esp_ecdsa_verify_psa(pk->pub_raw, pk->pub_raw_len, curve, curve_bits,
                            hash, hash_len, sig, sig_len);
}
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int esp_ecdsa_verify_wrap(mbedtls_pk_context *pk,
                             mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    (void) md_alg;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_keypair *ctx = pk->pk_ctx;
    unsigned char key[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t esp_key_len;
    size_t curve_bits;
    psa_ecc_family_t curve = esp_mbedtls_ecc_group_to_psa(ctx->grp.id, &curve_bits);

    ret = esp_mbedtls_ecp_point_write_binary(&ctx->grp, &ctx->Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &esp_key_len, key, sizeof(key));
    if (ret != 0) {
        return ret;
    }

    return esp_ecdsa_verify_psa(key, esp_key_len, curve, curve_bits,
                            hash, hash_len, sig, sig_len);
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int esp_ecdsa_verify_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             const unsigned char *sig, size_t sig_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) md_alg);

    ret = esp_mbedtls_ecdsa_read_signature((mbedtls_ecdsa_context *) pk->pk_ctx,
                                       hash, hash_len, sig, sig_len);

    if (ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH) {
        return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return ret;
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */

#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
#if defined(MBEDTLS_USE_PSA_CRYPTO)
/* Common helper for ECDSA sign using PSA functions.
 * Instead of extracting key's properties in order to check which kind of ECDSA
 * signature it supports, we try both deterministic and non-deterministic.
 */
static int esp_ecdsa_sign_psa(mbedtls_svc_key_id_t key_id, mbedtls_md_type_t md_alg,
                          const unsigned char *hash, size_t hash_len,
                          unsigned char *sig, size_t sig_size, size_t *sig_len)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    psa_status_t status;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    size_t key_bits = 0;

    status = esp_psa_get_key_attributes(key_id, &key_attr);
    if (status != PSA_SUCCESS) {
        return PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }
    key_bits = psa_get_key_bits(&key_attr);
    esp_psa_reset_key_attributes(&key_attr);

    status = esp_psa_sign_hash(key_id,
                           PSA_ALG_DETERMINISTIC_ECDSA(esp_mbedtls_md_psa_alg_from_type(md_alg)),
                           hash, hash_len, sig, sig_size, sig_len);
    if (status == PSA_SUCCESS) {
        goto done;
    } else if (status != PSA_ERROR_NOT_PERMITTED) {
        return PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }

    status = esp_psa_sign_hash(key_id,
                           PSA_ALG_ECDSA(esp_mbedtls_md_psa_alg_from_type(md_alg)),
                           hash, hash_len, sig, sig_size, sig_len);
    if (status != PSA_SUCCESS) {
        return PSA_PK_ECDSA_TO_MBEDTLS_ERR(status);
    }

done:
    ret = esp_mbedtls_ecdsa_raw_to_der(key_bits, sig, *sig_len, sig, sig_size, sig_len);

    return ret;
}

static int esp_ecdsa_opaque_sign_wrap(mbedtls_pk_context *pk,
                                  mbedtls_md_type_t md_alg,
                                  const unsigned char *hash, size_t hash_len,
                                  unsigned char *sig, size_t sig_size,
                                  size_t *sig_len,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
    ((void) f_rng);
    ((void) p_rng);

    return esp_ecdsa_sign_psa(pk->priv_id, md_alg, hash, hash_len, sig, sig_size,
                          sig_len);
}

#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
/* When PK_USE_PSA_EC_DATA is defined opaque and non-opaque keys end up
 * using the same function. */
#define esp_ecdsa_sign_wrap     esp_ecdsa_opaque_sign_wrap
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int esp_ecdsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char *sig, size_t sig_size, size_t *sig_len,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_status_t status;
    mbedtls_ecp_keypair *ctx = pk->pk_ctx;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    unsigned char buf[MBEDTLS_PSA_MAX_EC_KEY_PAIR_LENGTH];
    size_t curve_bits;
    psa_ecc_family_t curve =
        esp_mbedtls_ecc_group_to_psa(ctx->grp.id, &curve_bits);
    size_t esp_key_len = PSA_BITS_TO_BYTES(curve_bits);
    psa_algorithm_t psa_hash = esp_mbedtls_md_psa_alg_from_type(md_alg);
    psa_algorithm_t psa_sig_md = MBEDTLS_PK_PSA_ALG_ECDSA_MAYBE_DET(psa_hash);
    ((void) f_rng);
    ((void) p_rng);

    if (curve == 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if (esp_key_len > sizeof(buf)) {
        return MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    }
    ret = esp_mbedtls_mpi_write_binary(&ctx->d, buf, esp_key_len);
    if (ret != 0) {
        goto cleanup;
    }

    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, psa_sig_md);

    status = esp_psa_import_key(&attributes, buf, esp_key_len, &key_id);
    if (status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
        goto cleanup;
    }

    ret = esp_ecdsa_sign_psa(key_id, md_alg, hash, hash_len, sig, sig_size, sig_len);

cleanup:
    esp_mbedtls_platform_zeroize(buf, sizeof(buf));
    status = esp_psa_destroy_key(key_id);
    if (ret == 0 && status != PSA_SUCCESS) {
        ret = PSA_PK_TO_MBEDTLS_ERR(status);
    }

    return ret;
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int esp_ecdsa_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                           const unsigned char *hash, size_t hash_len,
                           unsigned char *sig, size_t sig_size, size_t *sig_len,
                           int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    return esp_mbedtls_ecdsa_write_signature((mbedtls_ecdsa_context *) pk->pk_ctx,
                                         md_alg, hash, hash_len,
                                         sig, sig_size, sig_len,
                                         f_rng, p_rng);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
/* Forward declarations */
static int esp_ecdsa_verify_rs_wrap(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx);

static int esp_ecdsa_sign_rs_wrap(mbedtls_pk_context *ctx, mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx);

/*
 * Restart context for ECDSA operations with ECKEY context
 *
 * We need to store an actual ECDSA context, as we need to pass the same to
 * the underlying ecdsa function, so we can't create it on the fly every time.
 */
typedef struct {
    mbedtls_ecdsa_restart_ctx ecdsa_rs;
    mbedtls_ecdsa_context ecdsa_ctx;
} eckey_restart_ctx;

static void *esp_eckey_rs_alloc(void)
{
    eckey_restart_ctx *rs_ctx;

    void *ctx = esp_mbedtls_calloc(1, sizeof(eckey_restart_ctx));

    if (ctx != NULL) {
        rs_ctx = ctx;
        esp_mbedtls_ecdsa_restart_init(&rs_ctx->ecdsa_rs);
        esp_mbedtls_ecdsa_init(&rs_ctx->ecdsa_ctx);
    }

    return ctx;
}

static void esp_eckey_rs_free(void *ctx)
{
    eckey_restart_ctx *rs_ctx;

    if (ctx == NULL) {
        return;
    }

    rs_ctx = ctx;
    esp_mbedtls_ecdsa_restart_free(&rs_ctx->ecdsa_rs);
    esp_mbedtls_ecdsa_free(&rs_ctx->ecdsa_ctx);

    esp_mbedtls_free(ctx);
}

static int esp_eckey_verify_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if (rs == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* set up our own sub-context if needed (that is, on first run) */
    if (rs->ecdsa_ctx.grp.pbits == 0) {
        MBEDTLS_MPI_CHK(esp_mbedtls_ecdsa_from_keypair(&rs->ecdsa_ctx, pk->pk_ctx));
    }

    MBEDTLS_MPI_CHK(esp_ecdsa_verify_rs_wrap(pk,
                                         md_alg, hash, hash_len,
                                         sig, sig_len, &rs->ecdsa_rs));

cleanup:
    return ret;
}

static int esp_eckey_sign_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    eckey_restart_ctx *rs = rs_ctx;

    /* Should never happen */
    if (rs == NULL) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* set up our own sub-context if needed (that is, on first run) */
    if (rs->ecdsa_ctx.grp.pbits == 0) {
        MBEDTLS_MPI_CHK(esp_mbedtls_ecdsa_from_keypair(&rs->ecdsa_ctx, pk->pk_ctx));
    }

    MBEDTLS_MPI_CHK(esp_ecdsa_sign_rs_wrap(pk, md_alg,
                                       hash, hash_len, sig, sig_size, sig_len,
                                       f_rng, p_rng, &rs->ecdsa_rs));

cleanup:
    return ret;
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
static int esp_eckey_check_pair_psa(mbedtls_pk_context *pub, mbedtls_pk_context *prv)
{
    psa_status_t status;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint8_t prv_key_buf[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t prv_key_len;
    mbedtls_svc_key_id_t key_id = prv->priv_id;

    status = esp_psa_export_public_key(key_id, prv_key_buf, sizeof(prv_key_buf),
                                   &prv_key_len);
    ret = PSA_PK_TO_MBEDTLS_ERR(status);
    if (ret != 0) {
        return ret;
    }

    if (memcmp(prv_key_buf, pub->pub_raw, pub->pub_raw_len) != 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    return 0;
}
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int esp_eckey_check_pair_psa(mbedtls_pk_context *pub, mbedtls_pk_context *prv)
{
    psa_status_t status;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint8_t prv_key_buf[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t prv_key_len;
    psa_status_t destruction_status;
    mbedtls_svc_key_id_t key_id = MBEDTLS_SVC_KEY_ID_INIT;
    psa_key_attributes_t key_attr = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t pub_key_buf[MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH];
    size_t pub_key_len;
    size_t curve_bits;
    const psa_ecc_family_t curve =
        esp_mbedtls_ecc_group_to_psa(esp_mbedtls_pk_ec_ro(*prv)->grp.id, &curve_bits);
    const size_t curve_bytes = PSA_BITS_TO_BYTES(curve_bits);

    if (curve == 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    psa_set_key_type(&key_attr, PSA_KEY_TYPE_ECC_KEY_PAIR(curve));
    psa_set_key_usage_flags(&key_attr, PSA_KEY_USAGE_EXPORT);

    ret = esp_mbedtls_mpi_write_binary(&esp_mbedtls_pk_ec_ro(*prv)->d,
                                   prv_key_buf, curve_bytes);
    if (ret != 0) {
        esp_mbedtls_platform_zeroize(prv_key_buf, sizeof(prv_key_buf));
        return ret;
    }

    status = esp_psa_import_key(&key_attr, prv_key_buf, curve_bytes, &key_id);
    esp_mbedtls_platform_zeroize(prv_key_buf, sizeof(prv_key_buf));
    ret = PSA_PK_TO_MBEDTLS_ERR(status);
    if (ret != 0) {
        return ret;
    }

    // From now on prv_key_buf is used to store the public key of prv.
    status = esp_psa_export_public_key(key_id, prv_key_buf, sizeof(prv_key_buf),
                                   &prv_key_len);
    ret = PSA_PK_TO_MBEDTLS_ERR(status);
    destruction_status = esp_psa_destroy_key(key_id);
    if (ret != 0) {
        return ret;
    } else if (destruction_status != PSA_SUCCESS) {
        return PSA_PK_TO_MBEDTLS_ERR(destruction_status);
    }

    ret = esp_mbedtls_ecp_point_write_binary(&esp_mbedtls_pk_ec_rw(*pub)->grp,
                                         &esp_mbedtls_pk_ec_rw(*pub)->Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pub_key_len, pub_key_buf,
                                         sizeof(pub_key_buf));
    if (ret != 0) {
        return ret;
    }

    if (memcmp(prv_key_buf, pub_key_buf, curve_bytes) != 0) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    return 0;
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */

static int esp_eckey_check_pair_wrap(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng)
{
    (void) f_rng;
    (void) p_rng;
    return esp_eckey_check_pair_psa(pub, prv);
}
#else /* MBEDTLS_USE_PSA_CRYPTO */
static int esp_eckey_check_pair_wrap(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
                                 int (*f_rng)(void *, unsigned char *, size_t),
                                 void *p_rng)
{
    return esp_mbedtls_ecp_check_pub_priv((const mbedtls_ecp_keypair *) pub->pk_ctx,
                                      (const mbedtls_ecp_keypair *) prv->pk_ctx,
                                      f_rng, p_rng);
}
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
/* When PK_USE_PSA_EC_DATA is defined opaque and non-opaque keys end up
 * using the same function. */
#define esp_ecdsa_opaque_check_pair_wrap    esp_eckey_check_pair_wrap
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
static int esp_ecdsa_opaque_check_pair_wrap(mbedtls_pk_context *pub,
                                        mbedtls_pk_context *prv,
                                        int (*f_rng)(void *, unsigned char *, size_t),
                                        void *p_rng)
{
    psa_status_t status;
    uint8_t exp_pub_key[MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
    size_t exp_pub_key_len = 0;
    uint8_t pub_key[MBEDTLS_PK_MAX_EC_PUBKEY_RAW_LEN];
    size_t pub_key_len = 0;
    int ret;
    (void) f_rng;
    (void) p_rng;

    status = esp_psa_export_public_key(prv->priv_id, exp_pub_key, sizeof(exp_pub_key),
                                   &exp_pub_key_len);
    if (status != PSA_SUCCESS) {
        ret = esp_psa_pk_status_to_mbedtls(status);
        return ret;
    }
    ret = esp_mbedtls_ecp_point_write_binary(&(esp_mbedtls_pk_ec_ro(*pub)->grp),
                                         &(esp_mbedtls_pk_ec_ro(*pub)->Q),
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &pub_key_len, pub_key, sizeof(pub_key));
    if (ret != 0) {
        return ret;
    }
    if ((exp_pub_key_len != pub_key_len) ||
        memcmp(exp_pub_key, pub_key, exp_pub_key_len)) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    return 0;
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if !defined(MBEDTLS_PK_USE_PSA_EC_DATA)
static void *esp_eckey_alloc_wrap(void)
{
    void *ctx = esp_mbedtls_calloc(1, sizeof(mbedtls_ecp_keypair));

    if (ctx != NULL) {
        esp_mbedtls_ecp_keypair_init(ctx);
    }

    return ctx;
}

static void esp_eckey_free_wrap(void *ctx)
{
    esp_mbedtls_ecp_keypair_free((mbedtls_ecp_keypair *) ctx);
    esp_mbedtls_free(ctx);
}
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */

static void esp_eckey_debug(mbedtls_pk_context *pk, mbedtls_pk_debug_item *items)
{
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    items->type = MBEDTLS_PK_DEBUG_PSA_EC;
    items->name = "eckey.Q";
    items->value = pk;
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
    mbedtls_ecp_keypair *ecp = (mbedtls_ecp_keypair *) pk->pk_ctx;
    items->type = MBEDTLS_PK_DEBUG_ECP;
    items->name = "eckey.Q";
    items->value = &(ecp->Q);
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
}

const mbedtls_pk_info_t esp_mbedtls_eckey_info = {
    .type = MBEDTLS_PK_ECKEY,
    .name = "EC",
    .get_bitlen = esp_eckey_get_bitlen,
    .can_do = esp_eckey_can_do,
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
    .verify_func = esp_ecdsa_verify_wrap,   /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
    .sign_func = esp_ecdsa_sign_wrap,   /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = esp_eckey_verify_rs_wrap,
    .sign_rs_func = esp_eckey_sign_rs_wrap,
    .rs_alloc_func = esp_eckey_rs_alloc,
    .rs_free_func = esp_eckey_rs_free,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = esp_eckey_check_pair_wrap,
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .ctx_alloc_func = esp_eckey_alloc_wrap,
    .ctx_free_func = esp_eckey_free_wrap,
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .debug_func = esp_eckey_debug,
};

/*
 * EC key restricted to ECDH
 */
static int esp_eckeydh_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_ECKEY ||
           type == MBEDTLS_PK_ECKEY_DH;
}

const mbedtls_pk_info_t esp_mbedtls_eckeydh_info = {
    .type = MBEDTLS_PK_ECKEY_DH,
    .name = "EC_DH",
    .get_bitlen = esp_eckey_get_bitlen,         /* Same underlying key structure */
    .can_do = esp_eckeydh_can_do,
    .verify_func = NULL,
    .sign_func = NULL,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = esp_eckey_check_pair_wrap,
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .ctx_alloc_func = esp_eckey_alloc_wrap,   /* Same underlying key structure */
    .ctx_free_func = esp_eckey_free_wrap,    /* Same underlying key structure */
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .debug_func = esp_eckey_debug,            /* Same underlying key structure */
};

#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
static int esp_ecdsa_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_ECDSA;
}

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
static int esp_ecdsa_verify_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                const unsigned char *sig, size_t sig_len,
                                void *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) md_alg);

    ret = esp_mbedtls_ecdsa_read_signature_restartable(
        (mbedtls_ecdsa_context *) pk->pk_ctx,
        hash, hash_len, sig, sig_len,
        (mbedtls_ecdsa_restart_ctx *) rs_ctx);

    if (ret == MBEDTLS_ERR_ECP_SIG_LEN_MISMATCH) {
        return MBEDTLS_ERR_PK_SIG_LEN_MISMATCH;
    }

    return ret;
}

static int esp_ecdsa_sign_rs_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                              const unsigned char *hash, size_t hash_len,
                              unsigned char *sig, size_t sig_size, size_t *sig_len,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng,
                              void *rs_ctx)
{
    return esp_mbedtls_ecdsa_write_signature_restartable(
        (mbedtls_ecdsa_context *) pk->pk_ctx,
        md_alg, hash, hash_len, sig, sig_size, sig_len, f_rng, p_rng,
        (mbedtls_ecdsa_restart_ctx *) rs_ctx);

}

static void *esp_ecdsa_rs_alloc(void)
{
    void *ctx = esp_mbedtls_calloc(1, sizeof(mbedtls_ecdsa_restart_ctx));

    if (ctx != NULL) {
        esp_mbedtls_ecdsa_restart_init(ctx);
    }

    return ctx;
}

static void esp_ecdsa_rs_free(void *ctx)
{
    esp_mbedtls_ecdsa_restart_free(ctx);
    esp_mbedtls_free(ctx);
}
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */

const mbedtls_pk_info_t esp_mbedtls_ecdsa_info = {
    .type = MBEDTLS_PK_ECDSA,
    .name = "ECDSA",
    .get_bitlen = esp_eckey_get_bitlen,     /* Compatible key structures */
    .can_do = esp_ecdsa_can_do,
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
    .verify_func = esp_ecdsa_verify_wrap,   /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
    .sign_func = esp_ecdsa_sign_wrap,   /* Compatible key structures */
#else /* MBEDTLS_PK_CAN_ECDSA_SIGN */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = esp_ecdsa_verify_rs_wrap,
    .sign_rs_func = esp_ecdsa_sign_rs_wrap,
    .rs_alloc_func = esp_ecdsa_rs_alloc,
    .rs_free_func = esp_ecdsa_rs_free,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = esp_eckey_check_pair_wrap,   /* Compatible key structures */
#if defined(MBEDTLS_PK_USE_PSA_EC_DATA)
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
#else /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .ctx_alloc_func = esp_eckey_alloc_wrap,   /* Compatible key structures */
    .ctx_free_func = esp_eckey_free_wrap,   /* Compatible key structures */
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA */
    .debug_func = esp_eckey_debug,        /* Compatible key structures */
};
#endif /* MBEDTLS_PK_CAN_ECDSA_SOME */
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

#if defined(MBEDTLS_PK_RSA_ALT_SUPPORT)
/*
 * Support for alternative RSA-private implementations
 */

static int esp_rsa_alt_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_RSA;
}

static size_t esp_rsa_alt_get_bitlen(mbedtls_pk_context *pk)
{
    const mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

    return 8 * rsa_alt->key_len_func(rsa_alt->key);
}

static int esp_rsa_alt_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                             const unsigned char *hash, size_t hash_len,
                             unsigned char *sig, size_t sig_size, size_t *sig_len,
                             int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

#if SIZE_MAX > UINT_MAX
    if (UINT_MAX < hash_len) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
#endif

    *sig_len = rsa_alt->key_len_func(rsa_alt->key);
    if (*sig_len > MBEDTLS_PK_SIGNATURE_MAX_SIZE) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }
    if (*sig_len > sig_size) {
        return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
    }

    return rsa_alt->sign_func(rsa_alt->key, f_rng, p_rng,
                              md_alg, (unsigned int) hash_len, hash, sig);
}

static int esp_rsa_alt_decrypt_wrap(mbedtls_pk_context *pk,
                                const unsigned char *input, size_t ilen,
                                unsigned char *output, size_t *olen, size_t osize,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    mbedtls_rsa_alt_context *rsa_alt = pk->pk_ctx;

    ((void) f_rng);
    ((void) p_rng);

    if (ilen != rsa_alt->key_len_func(rsa_alt->key)) {
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    return rsa_alt->decrypt_func(rsa_alt->key,
                                 olen, input, output, osize);
}

#if defined(MBEDTLS_RSA_C)
static int esp_rsa_alt_check_pair(mbedtls_pk_context *pub, mbedtls_pk_context *prv,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    unsigned char sig[MBEDTLS_MPI_MAX_SIZE];
    unsigned char hash[32];
    size_t sig_len = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    if (esp_rsa_alt_get_bitlen(prv) != esp_rsa_get_bitlen(pub)) {
        return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    memset(hash, 0x2a, sizeof(hash));

    if ((ret = esp_rsa_alt_sign_wrap(prv, MBEDTLS_MD_NONE,
                                 hash, sizeof(hash),
                                 sig, sizeof(sig), &sig_len,
                                 f_rng, p_rng)) != 0) {
        return ret;
    }

    if (esp_rsa_verify_wrap(pub, MBEDTLS_MD_NONE,
                        hash, sizeof(hash), sig, sig_len) != 0) {
        return MBEDTLS_ERR_RSA_KEY_CHECK_FAILED;
    }

    return 0;
}
#endif /* MBEDTLS_RSA_C */

static void *esp_rsa_alt_alloc_wrap(void)
{
    void *ctx = esp_mbedtls_calloc(1, sizeof(mbedtls_rsa_alt_context));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(mbedtls_rsa_alt_context));
    }

    return ctx;
}

static void esp_rsa_alt_free_wrap(void *ctx)
{
    esp_mbedtls_zeroize_and_free(ctx, sizeof(mbedtls_rsa_alt_context));
}

const mbedtls_pk_info_t esp_mbedtls_rsa_alt_info = {
    .type = MBEDTLS_PK_RSA_ALT,
    .name = "RSA-alt",
    .get_bitlen = esp_rsa_alt_get_bitlen,
    .can_do = esp_rsa_alt_can_do,
    .verify_func = NULL,
    .sign_func = esp_rsa_alt_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = esp_rsa_alt_decrypt_wrap,
    .encrypt_func = NULL,
#if defined(MBEDTLS_RSA_C)
    .check_pair_func = esp_rsa_alt_check_pair,
#else
    .check_pair_func = NULL,
#endif
    .ctx_alloc_func = esp_rsa_alt_alloc_wrap,
    .ctx_free_func = esp_rsa_alt_free_wrap,
    .debug_func = NULL,
};
#endif /* MBEDTLS_PK_RSA_ALT_SUPPORT */

#if defined(MBEDTLS_USE_PSA_CRYPTO)
static size_t esp_opaque_get_bitlen(mbedtls_pk_context *pk)
{
    size_t bits;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;

    if (PSA_SUCCESS != esp_psa_get_key_attributes(pk->priv_id, &attributes)) {
        return 0;
    }

    bits = psa_get_key_bits(&attributes);
    esp_psa_reset_key_attributes(&attributes);
    return bits;
}

#if defined(MBEDTLS_PK_HAVE_ECC_KEYS)
static int esp_ecdsa_opaque_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_ECKEY ||
           type == MBEDTLS_PK_ECDSA;
}

const mbedtls_pk_info_t esp_mbedtls_ecdsa_opaque_info = {
    .type = MBEDTLS_PK_OPAQUE,
    .name = "Opaque",
    .get_bitlen = esp_opaque_get_bitlen,
    .can_do = esp_ecdsa_opaque_can_do,
#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY)
    .verify_func = esp_ecdsa_opaque_verify_wrap,
#else /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
    .verify_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_VERIFY */
#if defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
    .sign_func = esp_ecdsa_opaque_sign_wrap,
#else /* MBEDTLS_PK_CAN_ECDSA_SIGN */
    .sign_func = NULL,
#endif /* MBEDTLS_PK_CAN_ECDSA_SIGN */
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
    .decrypt_func = NULL,
    .encrypt_func = NULL,
    .check_pair_func = esp_ecdsa_opaque_check_pair_wrap,
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
    .debug_func = NULL,
};
#endif /* MBEDTLS_PK_HAVE_ECC_KEYS */

static int esp_rsa_opaque_can_do(mbedtls_pk_type_t type)
{
    return type == MBEDTLS_PK_RSA ||
           type == MBEDTLS_PK_RSASSA_PSS;
}

#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
static int esp_rsa_opaque_decrypt(mbedtls_pk_context *pk,
                              const unsigned char *input, size_t ilen,
                              unsigned char *output, size_t *olen, size_t osize,
                              int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg;
    psa_key_type_t type;
    psa_status_t status;

    /* PSA has its own RNG */
    (void) f_rng;
    (void) p_rng;

    status = esp_psa_get_key_attributes(pk->priv_id, &attributes);
    if (status != PSA_SUCCESS) {
        return PSA_PK_TO_MBEDTLS_ERR(status);
    }

    type = psa_get_key_type(&attributes);
    alg = psa_get_key_algorithm(&attributes);
    esp_psa_reset_key_attributes(&attributes);

    if (!PSA_KEY_TYPE_IS_RSA(type)) {
        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    status = esp_psa_asymmetric_decrypt(pk->priv_id, alg, input, ilen, NULL, 0, output, osize, olen);
    if (status != PSA_SUCCESS) {
        return PSA_PK_RSA_TO_MBEDTLS_ERR(status);
    }

    return 0;
}
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */

static int esp_rsa_opaque_sign_wrap(mbedtls_pk_context *pk, mbedtls_md_type_t md_alg,
                                const unsigned char *hash, size_t hash_len,
                                unsigned char *sig, size_t sig_size, size_t *sig_len,
                                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
#if defined(MBEDTLS_RSA_C)
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_algorithm_t alg;
    psa_key_type_t type;
    psa_status_t status;

    /* PSA has its own RNG */
    (void) f_rng;
    (void) p_rng;

    status = esp_psa_get_key_attributes(pk->priv_id, &attributes);
    if (status != PSA_SUCCESS) {
        return PSA_PK_TO_MBEDTLS_ERR(status);
    }

    type = psa_get_key_type(&attributes);
    alg = psa_get_key_algorithm(&attributes);
    esp_psa_reset_key_attributes(&attributes);

    if (PSA_KEY_TYPE_IS_RSA(type)) {
        alg = (alg & ~PSA_ALG_HASH_MASK) | esp_mbedtls_md_psa_alg_from_type(md_alg);
    } else {
        return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
    }

    status = esp_psa_sign_hash(pk->priv_id, alg, hash, hash_len, sig, sig_size, sig_len);
    if (status != PSA_SUCCESS) {
        if (PSA_KEY_TYPE_IS_RSA(type)) {
            return PSA_PK_RSA_TO_MBEDTLS_ERR(status);
        } else {
            return PSA_PK_TO_MBEDTLS_ERR(status);
        }
    }

    return 0;
#else /* !MBEDTLS_RSA_C */
    ((void) pk);
    ((void) md_alg);
    ((void) hash);
    ((void) hash_len);
    ((void) sig);
    ((void) sig_size);
    ((void) sig_len);
    ((void) f_rng);
    ((void) p_rng);
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
#endif /* !MBEDTLS_RSA_C */
}

const mbedtls_pk_info_t esp_mbedtls_rsa_opaque_info = {
    .type = MBEDTLS_PK_OPAQUE,
    .name = "Opaque",
    .get_bitlen = esp_opaque_get_bitlen,
    .can_do = esp_rsa_opaque_can_do,
    .verify_func = NULL,
    .sign_func = esp_rsa_opaque_sign_wrap,
#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECP_RESTARTABLE)
    .verify_rs_func = NULL,
    .sign_rs_func = NULL,
    .rs_alloc_func = NULL,
    .rs_free_func = NULL,
#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECP_RESTARTABLE */
#if defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC)
    .decrypt_func = esp_rsa_opaque_decrypt,
#else /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
    .decrypt_func = NULL,
#endif /* PSA_WANT_KEY_TYPE_RSA_KEY_PAIR_BASIC */
    .encrypt_func = NULL,
    .check_pair_func = NULL,
    .ctx_alloc_func = NULL,
    .ctx_free_func = NULL,
    .debug_func = NULL,
};

#endif /* MBEDTLS_USE_PSA_CRYPTO */

#endif /* MBEDTLS_PK_C */
