/**
 * \file cipher_wrap.c
 *
 * \brief Generic cipher wrapper for Mbed TLS
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_CIPHER_C)

#include "cipher_wrap.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_CHACHAPOLY_C)
#include "mbedtls/chachapoly.h"
#endif

#if defined(MBEDTLS_AES_C)
#include "mbedtls/aes.h"
#endif

#if defined(MBEDTLS_CAMELLIA_C)
#include "mbedtls/camellia.h"
#endif

#if defined(MBEDTLS_ARIA_C)
#include "mbedtls/aria.h"
#endif

#if defined(MBEDTLS_DES_C)
#include "mbedtls/des.h"
#endif

#if defined(MBEDTLS_CHACHA20_C)
#include "mbedtls/chacha20.h"
#endif

#if defined(MBEDTLS_GCM_C)
#include "mbedtls/gcm.h"
#endif

#if defined(MBEDTLS_CCM_C)
#include "mbedtls/ccm.h"
#endif

#if defined(MBEDTLS_NIST_KW_C)
#include "mbedtls/nist_kw.h"
#endif

#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
#include <string.h>
#endif

#include "mbedtls/platform.h"

enum mbedtls_cipher_base_index {
#if defined(MBEDTLS_AES_C)
    MBEDTLS_CIPHER_BASE_INDEX_AES,
#endif
#if defined(MBEDTLS_ARIA_C)
    MBEDTLS_CIPHER_BASE_INDEX_ARIA,
#endif
#if defined(MBEDTLS_CAMELLIA_C)
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA,
#endif
#if defined(MBEDTLS_CIPHER_HAVE_CCM_AES_VIA_LEGACY_OR_USE_PSA)
    MBEDTLS_CIPHER_BASE_INDEX_CCM_AES,
#endif
#if defined(MBEDTLS_CCM_C) && defined(MBEDTLS_ARIA_C)
    MBEDTLS_CIPHER_BASE_INDEX_CCM_ARIA,
#endif
#if defined(MBEDTLS_CCM_C) && defined(MBEDTLS_CAMELLIA_C)
    MBEDTLS_CIPHER_BASE_INDEX_CCM_CAMELLIA,
#endif
#if defined(MBEDTLS_CHACHA20_C)
    MBEDTLS_CIPHER_BASE_INDEX_CHACHA20_BASE,
#endif
#if defined(MBEDTLS_CHACHAPOLY_C)
    MBEDTLS_CIPHER_BASE_INDEX_CHACHAPOLY_BASE,
#endif
#if defined(MBEDTLS_DES_C)
    MBEDTLS_CIPHER_BASE_INDEX_DES_EDE3,
#endif
#if defined(MBEDTLS_DES_C)
    MBEDTLS_CIPHER_BASE_INDEX_DES_EDE,
#endif
#if defined(MBEDTLS_DES_C)
    MBEDTLS_CIPHER_BASE_INDEX_DES,
#endif
#if defined(MBEDTLS_CIPHER_HAVE_GCM_AES_VIA_LEGACY_OR_USE_PSA)
    MBEDTLS_CIPHER_BASE_INDEX_GCM_AES,
#endif
#if defined(MBEDTLS_GCM_C) && defined(MBEDTLS_ARIA_C)
    MBEDTLS_CIPHER_BASE_INDEX_GCM_ARIA,
#endif
#if defined(MBEDTLS_GCM_C) && defined(MBEDTLS_CAMELLIA_C)
    MBEDTLS_CIPHER_BASE_INDEX_GCM_CAMELLIA,
#endif
#if defined(MBEDTLS_NIST_KW_C)
    MBEDTLS_CIPHER_BASE_INDEX_KW_AES,
#endif
#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
    MBEDTLS_CIPHER_BASE_INDEX_NULL_BASE,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS) && defined(MBEDTLS_AES_C)
    MBEDTLS_CIPHER_BASE_INDEX_XTS_AES,
#endif
    /* Prevent compile failure due to empty enum */
    MBEDTLS_CIPHER_BASE_PREVENT_EMPTY_ENUM
};

#if defined(MBEDTLS_GCM_C) && \
    (defined(MBEDTLS_CIPHER_HAVE_GCM_AES_VIA_LEGACY_OR_USE_PSA) || \
    defined(MBEDTLS_ARIA_C) || defined(MBEDTLS_CAMELLIA_C))
/* shared by all GCM ciphers */
static void *esp_gcm_ctx_alloc(void)
{
    void *ctx = esp_mbedtls_calloc(1, sizeof(mbedtls_gcm_context));

    if (ctx != NULL) {
        esp_mbedtls_gcm_init((mbedtls_gcm_context *) ctx);
    }

    return ctx;
}

static void esp_gcm_ctx_free(void *ctx)
{
    esp_mbedtls_gcm_free(ctx);
    esp_mbedtls_free(ctx);
}
#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_CCM_C) && \
    (defined(MBEDTLS_CIPHER_HAVE_CCM_AES_VIA_LEGACY_OR_USE_PSA) || \
    defined(MBEDTLS_ARIA_C) || defined(MBEDTLS_CAMELLIA_C))
/* shared by all CCM ciphers */
static void *esp_ccm_ctx_alloc(void)
{
    void *ctx = esp_mbedtls_calloc(1, sizeof(mbedtls_ccm_context));

    if (ctx != NULL) {
        esp_mbedtls_ccm_init((mbedtls_ccm_context *) ctx);
    }

    return ctx;
}

static void esp_ccm_ctx_free(void *ctx)
{
    esp_mbedtls_ccm_free(ctx);
    esp_mbedtls_free(ctx);
}
#endif /* MBEDTLS_CCM_C */

#if defined(MBEDTLS_AES_C)

static int esp_aes_crypt_ecb_wrap(void *ctx, mbedtls_operation_t operation,
                              const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_aes_crypt_ecb((mbedtls_aes_context *) ctx, operation, input, output);
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static int esp_aes_crypt_cbc_wrap(void *ctx, mbedtls_operation_t operation, size_t length,
                              unsigned char *iv, const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_aes_crypt_cbc((mbedtls_aes_context *) ctx, operation, length, iv, input,
                                 output);
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
static int esp_aes_crypt_cfb128_wrap(void *ctx, mbedtls_operation_t operation,
                                 size_t length, size_t *iv_off, unsigned char *iv,
                                 const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_aes_crypt_cfb128((mbedtls_aes_context *) ctx, operation, length, iv_off, iv,
                                    input, output);
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
static int esp_aes_crypt_ofb_wrap(void *ctx, size_t length, size_t *iv_off,
                              unsigned char *iv, const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_aes_crypt_ofb((mbedtls_aes_context *) ctx, length, iv_off,
                                 iv, input, output);
}
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
static int esp_aes_crypt_ctr_wrap(void *ctx, size_t length, size_t *nc_off,
                              unsigned char *nonce_counter, unsigned char *stream_block,
                              const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_aes_crypt_ctr((mbedtls_aes_context *) ctx, length, nc_off, nonce_counter,
                                 stream_block, input, output);
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_CIPHER_MODE_XTS)
static int esp_aes_crypt_xts_wrap(void *ctx, mbedtls_operation_t operation,
                              size_t length,
                              const unsigned char data_unit[16],
                              const unsigned char *input,
                              unsigned char *output)
{
    mbedtls_aes_xts_context *xts_ctx = ctx;
    int mode;

    switch (operation) {
        case MBEDTLS_ENCRYPT:
            mode = MBEDTLS_AES_ENCRYPT;
            break;
        case MBEDTLS_DECRYPT:
            mode = MBEDTLS_AES_DECRYPT;
            break;
        default:
            return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    return esp_mbedtls_aes_crypt_xts(xts_ctx, mode, length,
                                 data_unit, input, output);
}
#endif /* MBEDTLS_CIPHER_MODE_XTS */

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
static int esp_aes_setkey_dec_wrap(void *ctx, const unsigned char *key,
                               unsigned int key_bitlen)
{
    return esp_mbedtls_aes_setkey_dec((mbedtls_aes_context *) ctx, key, key_bitlen);
}
#endif

static int esp_aes_setkey_enc_wrap(void *ctx, const unsigned char *key,
                               unsigned int key_bitlen)
{
    return esp_mbedtls_aes_setkey_enc((mbedtls_aes_context *) ctx, key, key_bitlen);
}

static void *esp_aes_ctx_alloc(void)
{
    mbedtls_aes_context *aes = esp_mbedtls_calloc(1, sizeof(mbedtls_aes_context));

    if (aes == NULL) {
        return NULL;
    }

    esp_mbedtls_aes_init(aes);

    return aes;
}

static void esp_aes_ctx_free(void *ctx)
{
    esp_mbedtls_aes_free((mbedtls_aes_context *) ctx);
    esp_mbedtls_free(ctx);
}

static const mbedtls_cipher_base_t esp_aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    esp_aes_crypt_ecb_wrap,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    esp_aes_crypt_cbc_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    esp_aes_crypt_cfb128_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    esp_aes_crypt_ofb_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    esp_aes_crypt_ctr_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_aes_setkey_enc_wrap,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_aes_setkey_dec_wrap,
#endif
    esp_aes_ctx_alloc,
    esp_aes_ctx_free
};

static const mbedtls_cipher_info_t esp_aes_128_ecb_info = {
    "AES-128-ECB",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_AES_128_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const mbedtls_cipher_info_t esp_aes_192_ecb_info = {
    "AES-192-ECB",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_AES_192_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};

static const mbedtls_cipher_info_t esp_aes_256_ecb_info = {
    "AES-256-ECB",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_AES_256_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};
#endif

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static const mbedtls_cipher_info_t esp_aes_128_cbc_info = {
    "AES-128-CBC",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_AES_128_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const mbedtls_cipher_info_t esp_aes_192_cbc_info = {
    "AES-192-CBC",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_AES_192_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};

static const mbedtls_cipher_info_t esp_aes_256_cbc_info = {
    "AES-256-CBC",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_AES_256_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};
#endif
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
static const mbedtls_cipher_info_t esp_aes_128_cfb128_info = {
    "AES-128-CFB128",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CFB,
    MBEDTLS_CIPHER_AES_128_CFB128,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const mbedtls_cipher_info_t esp_aes_192_cfb128_info = {
    "AES-192-CFB128",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CFB,
    MBEDTLS_CIPHER_AES_192_CFB128,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};

static const mbedtls_cipher_info_t esp_aes_256_cfb128_info = {
    "AES-256-CFB128",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CFB,
    MBEDTLS_CIPHER_AES_256_CFB128,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};
#endif
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_OFB)
static const mbedtls_cipher_info_t esp_aes_128_ofb_info = {
    "AES-128-OFB",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_OFB,
    MBEDTLS_CIPHER_AES_128_OFB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const mbedtls_cipher_info_t esp_aes_192_ofb_info = {
    "AES-192-OFB",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_OFB,
    MBEDTLS_CIPHER_AES_192_OFB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};

static const mbedtls_cipher_info_t esp_aes_256_ofb_info = {
    "AES-256-OFB",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_OFB,
    MBEDTLS_CIPHER_AES_256_OFB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};
#endif
#endif /* MBEDTLS_CIPHER_MODE_OFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
static const mbedtls_cipher_info_t esp_aes_128_ctr_info = {
    "AES-128-CTR",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CTR,
    MBEDTLS_CIPHER_AES_128_CTR,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const mbedtls_cipher_info_t esp_aes_192_ctr_info = {
    "AES-192-CTR",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CTR,
    MBEDTLS_CIPHER_AES_192_CTR,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};

static const mbedtls_cipher_info_t esp_aes_256_ctr_info = {
    "AES-256-CTR",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CTR,
    MBEDTLS_CIPHER_AES_256_CTR,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_AES
};
#endif
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_CIPHER_MODE_XTS)
static int esp_xts_aes_setkey_enc_wrap(void *ctx, const unsigned char *key,
                                   unsigned int key_bitlen)
{
    mbedtls_aes_xts_context *xts_ctx = ctx;
    return esp_mbedtls_aes_xts_setkey_enc(xts_ctx, key, key_bitlen);
}

static int esp_xts_aes_setkey_dec_wrap(void *ctx, const unsigned char *key,
                                   unsigned int key_bitlen)
{
    mbedtls_aes_xts_context *xts_ctx = ctx;
    return esp_mbedtls_aes_xts_setkey_dec(xts_ctx, key, key_bitlen);
}

static void *esp_xts_aes_ctx_alloc(void)
{
    mbedtls_aes_xts_context *xts_ctx = esp_mbedtls_calloc(1, sizeof(*xts_ctx));

    if (xts_ctx != NULL) {
        esp_mbedtls_aes_xts_init(xts_ctx);
    }

    return xts_ctx;
}

static void esp_xts_aes_ctx_free(void *ctx)
{
    mbedtls_aes_xts_context *xts_ctx = ctx;

    if (xts_ctx == NULL) {
        return;
    }

    esp_mbedtls_aes_xts_free(xts_ctx);
    esp_mbedtls_free(xts_ctx);
}

static const mbedtls_cipher_base_t esp_xts_aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    esp_aes_crypt_xts_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_xts_aes_setkey_enc_wrap,
    esp_xts_aes_setkey_dec_wrap,
    esp_xts_aes_ctx_alloc,
    esp_xts_aes_ctx_free
};

static const mbedtls_cipher_info_t esp_aes_128_xts_info = {
    "AES-128-XTS",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_XTS,
    MBEDTLS_CIPHER_AES_128_XTS,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_XTS_AES
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const mbedtls_cipher_info_t esp_aes_256_xts_info = {
    "AES-256-XTS",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    512 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_XTS,
    MBEDTLS_CIPHER_AES_256_XTS,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_XTS_AES
};
#endif
#endif /* MBEDTLS_CIPHER_MODE_XTS */
#endif /* MBEDTLS_AES_C */

#if defined(MBEDTLS_GCM_C) && defined(MBEDTLS_CCM_GCM_CAN_AES)
static int esp_gcm_aes_setkey_wrap(void *ctx, const unsigned char *key,
                               unsigned int key_bitlen)
{
    return esp_mbedtls_gcm_setkey((mbedtls_gcm_context *) ctx, MBEDTLS_CIPHER_ID_AES,
                              key, key_bitlen);
}
#endif /* MBEDTLS_GCM_C && MBEDTLS_CCM_GCM_CAN_AES */

#if defined(MBEDTLS_CIPHER_HAVE_GCM_AES_VIA_LEGACY_OR_USE_PSA)
static const mbedtls_cipher_base_t esp_gcm_aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
#if defined(MBEDTLS_GCM_C)
    esp_gcm_aes_setkey_wrap,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_gcm_aes_setkey_wrap,
#endif
    esp_gcm_ctx_alloc,
    esp_gcm_ctx_free,
#else
    NULL,
    NULL,
    NULL,
    NULL,
#endif /* MBEDTLS_GCM_C */
};
#endif /* MBEDTLS_CIPHER_HAVE_GCM_AES_VIA_LEGACY_OR_USE_PSA */

#if defined(MBEDTLS_CIPHER_HAVE_GCM_AES_VIA_LEGACY_OR_USE_PSA)
static const mbedtls_cipher_info_t esp_aes_128_gcm_info = {
    "AES-128-GCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_GCM,
    MBEDTLS_CIPHER_AES_128_GCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_GCM_AES
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const mbedtls_cipher_info_t esp_aes_192_gcm_info = {
    "AES-192-GCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_GCM,
    MBEDTLS_CIPHER_AES_192_GCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_GCM_AES
};

static const mbedtls_cipher_info_t esp_aes_256_gcm_info = {
    "AES-256-GCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_GCM,
    MBEDTLS_CIPHER_AES_256_GCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_GCM_AES
};
#endif
#endif /* MBEDTLS_CIPHER_HAVE_GCM_AES_VIA_LEGACY_OR_USE_PSA */

#if defined(MBEDTLS_CCM_C) && defined(MBEDTLS_CCM_GCM_CAN_AES)
static int esp_ccm_aes_setkey_wrap(void *ctx, const unsigned char *key,
                               unsigned int key_bitlen)
{
    return esp_mbedtls_ccm_setkey((mbedtls_ccm_context *) ctx, MBEDTLS_CIPHER_ID_AES,
                              key, key_bitlen);
}
#endif /* MBEDTLS_CCM_C && MBEDTLS_CCM_GCM_CAN_AES */

#if defined(MBEDTLS_CIPHER_HAVE_CCM_AES_VIA_LEGACY_OR_USE_PSA)
static const mbedtls_cipher_base_t esp_ccm_aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
#if defined(MBEDTLS_CCM_C)
    esp_ccm_aes_setkey_wrap,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_ccm_aes_setkey_wrap,
#endif
    esp_ccm_ctx_alloc,
    esp_ccm_ctx_free,
#else
    NULL,
    NULL,
    NULL,
    NULL,
#endif
};
#endif /* MBEDTLS_CIPHER_HAVE_CCM_AES_VIA_LEGACY_OR_USE_PSA */

#if defined(MBEDTLS_CIPHER_HAVE_CCM_AES_VIA_LEGACY_OR_USE_PSA)
static const mbedtls_cipher_info_t esp_aes_128_ccm_info = {
    "AES-128-CCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM,
    MBEDTLS_CIPHER_AES_128_CCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_AES
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const mbedtls_cipher_info_t esp_aes_192_ccm_info = {
    "AES-192-CCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM,
    MBEDTLS_CIPHER_AES_192_CCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_AES
};

static const mbedtls_cipher_info_t esp_aes_256_ccm_info = {
    "AES-256-CCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM,
    MBEDTLS_CIPHER_AES_256_CCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_AES
};
#endif
#endif /* MBEDTLS_CIPHER_HAVE_CCM_AES_VIA_LEGACY_OR_USE_PSA */

#if defined(MBEDTLS_CIPHER_HAVE_CCM_STAR_NO_TAG_AES_VIA_LEGACY_OR_USE_PSA)
static const mbedtls_cipher_info_t esp_aes_128_ccm_star_no_tag_info = {
    "AES-128-CCM*-NO-TAG",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_AES_128_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_AES
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const mbedtls_cipher_info_t esp_aes_192_ccm_star_no_tag_info = {
    "AES-192-CCM*-NO-TAG",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_AES_192_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_AES
};

static const mbedtls_cipher_info_t esp_aes_256_ccm_star_no_tag_info = {
    "AES-256-CCM*-NO-TAG",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_AES_256_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_AES
};
#endif
#endif /* MBEDTLS_CIPHER_HAVE_CCM_STAR_NO_TAG_AES_VIA_LEGACY_OR_USE_PSA */


#if defined(MBEDTLS_CAMELLIA_C)

static int esp_camellia_crypt_ecb_wrap(void *ctx, mbedtls_operation_t operation,
                                   const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_camellia_crypt_ecb((mbedtls_camellia_context *) ctx, operation, input,
                                      output);
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static int esp_camellia_crypt_cbc_wrap(void *ctx, mbedtls_operation_t operation,
                                   size_t length, unsigned char *iv,
                                   const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_camellia_crypt_cbc((mbedtls_camellia_context *) ctx, operation, length, iv,
                                      input, output);
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
static int esp_camellia_crypt_cfb128_wrap(void *ctx, mbedtls_operation_t operation,
                                      size_t length, size_t *iv_off, unsigned char *iv,
                                      const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_camellia_crypt_cfb128((mbedtls_camellia_context *) ctx, operation, length,
                                         iv_off, iv, input, output);
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
static int esp_camellia_crypt_ctr_wrap(void *ctx, size_t length, size_t *nc_off,
                                   unsigned char *nonce_counter, unsigned char *stream_block,
                                   const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_camellia_crypt_ctr((mbedtls_camellia_context *) ctx, length, nc_off,
                                      nonce_counter, stream_block, input, output);
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
static int esp_camellia_setkey_dec_wrap(void *ctx, const unsigned char *key,
                                    unsigned int key_bitlen)
{
    return esp_mbedtls_camellia_setkey_dec((mbedtls_camellia_context *) ctx, key, key_bitlen);
}
#endif

static int esp_camellia_setkey_enc_wrap(void *ctx, const unsigned char *key,
                                    unsigned int key_bitlen)
{
    return esp_mbedtls_camellia_setkey_enc((mbedtls_camellia_context *) ctx, key, key_bitlen);
}

static void *esp_camellia_ctx_alloc(void)
{
    mbedtls_camellia_context *ctx;
    ctx = esp_mbedtls_calloc(1, sizeof(mbedtls_camellia_context));

    if (ctx == NULL) {
        return NULL;
    }

    esp_mbedtls_camellia_init(ctx);

    return ctx;
}

static void esp_camellia_ctx_free(void *ctx)
{
    esp_mbedtls_camellia_free((mbedtls_camellia_context *) ctx);
    esp_mbedtls_free(ctx);
}

static const mbedtls_cipher_base_t esp_camellia_info = {
    MBEDTLS_CIPHER_ID_CAMELLIA,
    esp_camellia_crypt_ecb_wrap,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    esp_camellia_crypt_cbc_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    esp_camellia_crypt_cfb128_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    esp_camellia_crypt_ctr_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_camellia_setkey_enc_wrap,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_camellia_setkey_dec_wrap,
#endif
    esp_camellia_ctx_alloc,
    esp_camellia_ctx_free
};

static const mbedtls_cipher_info_t esp_camellia_128_ecb_info = {
    "CAMELLIA-128-ECB",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_CAMELLIA_128_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_192_ecb_info = {
    "CAMELLIA-192-ECB",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_CAMELLIA_192_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_256_ecb_info = {
    "CAMELLIA-256-ECB",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_CAMELLIA_256_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static const mbedtls_cipher_info_t esp_camellia_128_cbc_info = {
    "CAMELLIA-128-CBC",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_CAMELLIA_128_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_192_cbc_info = {
    "CAMELLIA-192-CBC",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_CAMELLIA_192_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_256_cbc_info = {
    "CAMELLIA-256-CBC",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_CAMELLIA_256_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
static const mbedtls_cipher_info_t esp_camellia_128_cfb128_info = {
    "CAMELLIA-128-CFB128",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CFB,
    MBEDTLS_CIPHER_CAMELLIA_128_CFB128,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_192_cfb128_info = {
    "CAMELLIA-192-CFB128",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CFB,
    MBEDTLS_CIPHER_CAMELLIA_192_CFB128,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_256_cfb128_info = {
    "CAMELLIA-256-CFB128",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CFB,
    MBEDTLS_CIPHER_CAMELLIA_256_CFB128,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
static const mbedtls_cipher_info_t esp_camellia_128_ctr_info = {
    "CAMELLIA-128-CTR",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CTR,
    MBEDTLS_CIPHER_CAMELLIA_128_CTR,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_192_ctr_info = {
    "CAMELLIA-192-CTR",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CTR,
    MBEDTLS_CIPHER_CAMELLIA_192_CTR,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_256_ctr_info = {
    "CAMELLIA-256-CTR",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CTR,
    MBEDTLS_CIPHER_CAMELLIA_256_CTR,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA
};
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_GCM_C)
static int esp_gcm_camellia_setkey_wrap(void *ctx, const unsigned char *key,
                                    unsigned int key_bitlen)
{
    return esp_mbedtls_gcm_setkey((mbedtls_gcm_context *) ctx, MBEDTLS_CIPHER_ID_CAMELLIA,
                              key, key_bitlen);
}

static const mbedtls_cipher_base_t esp_gcm_camellia_info = {
    MBEDTLS_CIPHER_ID_CAMELLIA,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_gcm_camellia_setkey_wrap,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_gcm_camellia_setkey_wrap,
#endif
    esp_gcm_ctx_alloc,
    esp_gcm_ctx_free,
};

static const mbedtls_cipher_info_t esp_camellia_128_gcm_info = {
    "CAMELLIA-128-GCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_GCM,
    MBEDTLS_CIPHER_CAMELLIA_128_GCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_GCM_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_192_gcm_info = {
    "CAMELLIA-192-GCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_GCM,
    MBEDTLS_CIPHER_CAMELLIA_192_GCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_GCM_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_256_gcm_info = {
    "CAMELLIA-256-GCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_GCM,
    MBEDTLS_CIPHER_CAMELLIA_256_GCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_GCM_CAMELLIA
};
#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_CCM_C)
static int esp_ccm_camellia_setkey_wrap(void *ctx, const unsigned char *key,
                                    unsigned int key_bitlen)
{
    return esp_mbedtls_ccm_setkey((mbedtls_ccm_context *) ctx, MBEDTLS_CIPHER_ID_CAMELLIA,
                              key, key_bitlen);
}

static const mbedtls_cipher_base_t esp_ccm_camellia_info = {
    MBEDTLS_CIPHER_ID_CAMELLIA,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_ccm_camellia_setkey_wrap,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_ccm_camellia_setkey_wrap,
#endif
    esp_ccm_ctx_alloc,
    esp_ccm_ctx_free,
};

static const mbedtls_cipher_info_t esp_camellia_128_ccm_info = {
    "CAMELLIA-128-CCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM,
    MBEDTLS_CIPHER_CAMELLIA_128_CCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_192_ccm_info = {
    "CAMELLIA-192-CCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM,
    MBEDTLS_CIPHER_CAMELLIA_192_CCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_256_ccm_info = {
    "CAMELLIA-256-CCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM,
    MBEDTLS_CIPHER_CAMELLIA_256_CCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_128_ccm_star_no_tag_info = {
    "CAMELLIA-128-CCM*-NO-TAG",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_CAMELLIA_128_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_192_ccm_star_no_tag_info = {
    "CAMELLIA-192-CCM*-NO-TAG",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_CAMELLIA_192_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_CAMELLIA
};

static const mbedtls_cipher_info_t esp_camellia_256_ccm_star_no_tag_info = {
    "CAMELLIA-256-CCM*-NO-TAG",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_CAMELLIA_256_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_CAMELLIA
};
#endif /* MBEDTLS_CCM_C */

#endif /* MBEDTLS_CAMELLIA_C */

#if defined(MBEDTLS_ARIA_C)

static int esp_aria_crypt_ecb_wrap(void *ctx, mbedtls_operation_t operation,
                               const unsigned char *input, unsigned char *output)
{
    (void) operation;
    return esp_mbedtls_aria_crypt_ecb((mbedtls_aria_context *) ctx, input,
                                  output);
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static int esp_aria_crypt_cbc_wrap(void *ctx, mbedtls_operation_t operation,
                               size_t length, unsigned char *iv,
                               const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_aria_crypt_cbc((mbedtls_aria_context *) ctx, operation, length, iv,
                                  input, output);
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
static int esp_aria_crypt_cfb128_wrap(void *ctx, mbedtls_operation_t operation,
                                  size_t length, size_t *iv_off, unsigned char *iv,
                                  const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_aria_crypt_cfb128((mbedtls_aria_context *) ctx, operation, length,
                                     iv_off, iv, input, output);
}
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
static int esp_aria_crypt_ctr_wrap(void *ctx, size_t length, size_t *nc_off,
                               unsigned char *nonce_counter, unsigned char *stream_block,
                               const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_aria_crypt_ctr((mbedtls_aria_context *) ctx, length, nc_off,
                                  nonce_counter, stream_block, input, output);
}
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
static int esp_aria_setkey_dec_wrap(void *ctx, const unsigned char *key,
                                unsigned int key_bitlen)
{
    return esp_mbedtls_aria_setkey_dec((mbedtls_aria_context *) ctx, key, key_bitlen);
}
#endif

static int esp_aria_setkey_enc_wrap(void *ctx, const unsigned char *key,
                                unsigned int key_bitlen)
{
    return esp_mbedtls_aria_setkey_enc((mbedtls_aria_context *) ctx, key, key_bitlen);
}

static void *esp_aria_ctx_alloc(void)
{
    mbedtls_aria_context *ctx;
    ctx = esp_mbedtls_calloc(1, sizeof(mbedtls_aria_context));

    if (ctx == NULL) {
        return NULL;
    }

    esp_mbedtls_aria_init(ctx);

    return ctx;
}

static void esp_aria_ctx_free(void *ctx)
{
    esp_mbedtls_aria_free((mbedtls_aria_context *) ctx);
    esp_mbedtls_free(ctx);
}

static const mbedtls_cipher_base_t esp_aria_info = {
    MBEDTLS_CIPHER_ID_ARIA,
    esp_aria_crypt_ecb_wrap,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    esp_aria_crypt_cbc_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    esp_aria_crypt_cfb128_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    esp_aria_crypt_ctr_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_aria_setkey_enc_wrap,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_aria_setkey_dec_wrap,
#endif
    esp_aria_ctx_alloc,
    esp_aria_ctx_free
};

static const mbedtls_cipher_info_t esp_aria_128_ecb_info = {
    "ARIA-128-ECB",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_ARIA_128_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};

static const mbedtls_cipher_info_t esp_aria_192_ecb_info = {
    "ARIA-192-ECB",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_ARIA_192_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};

static const mbedtls_cipher_info_t esp_aria_256_ecb_info = {
    "ARIA-256-ECB",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_ARIA_256_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static const mbedtls_cipher_info_t esp_aria_128_cbc_info = {
    "ARIA-128-CBC",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_ARIA_128_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};

static const mbedtls_cipher_info_t esp_aria_192_cbc_info = {
    "ARIA-192-CBC",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_ARIA_192_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};

static const mbedtls_cipher_info_t esp_aria_256_cbc_info = {
    "ARIA-256-CBC",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_ARIA_256_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
static const mbedtls_cipher_info_t esp_aria_128_cfb128_info = {
    "ARIA-128-CFB128",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CFB,
    MBEDTLS_CIPHER_ARIA_128_CFB128,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};

static const mbedtls_cipher_info_t esp_aria_192_cfb128_info = {
    "ARIA-192-CFB128",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CFB,
    MBEDTLS_CIPHER_ARIA_192_CFB128,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};

static const mbedtls_cipher_info_t esp_aria_256_cfb128_info = {
    "ARIA-256-CFB128",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CFB,
    MBEDTLS_CIPHER_ARIA_256_CFB128,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
static const mbedtls_cipher_info_t esp_aria_128_ctr_info = {
    "ARIA-128-CTR",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CTR,
    MBEDTLS_CIPHER_ARIA_128_CTR,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};

static const mbedtls_cipher_info_t esp_aria_192_ctr_info = {
    "ARIA-192-CTR",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CTR,
    MBEDTLS_CIPHER_ARIA_192_CTR,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};

static const mbedtls_cipher_info_t esp_aria_256_ctr_info = {
    "ARIA-256-CTR",
    16,
    16 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CTR,
    MBEDTLS_CIPHER_ARIA_256_CTR,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_ARIA
};
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#if defined(MBEDTLS_GCM_C)
static int esp_gcm_aria_setkey_wrap(void *ctx, const unsigned char *key,
                                unsigned int key_bitlen)
{
    return esp_mbedtls_gcm_setkey((mbedtls_gcm_context *) ctx, MBEDTLS_CIPHER_ID_ARIA,
                              key, key_bitlen);
}

static const mbedtls_cipher_base_t esp_gcm_aria_info = {
    MBEDTLS_CIPHER_ID_ARIA,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_gcm_aria_setkey_wrap,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_gcm_aria_setkey_wrap,
#endif
    esp_gcm_ctx_alloc,
    esp_gcm_ctx_free,
};

static const mbedtls_cipher_info_t esp_aria_128_gcm_info = {
    "ARIA-128-GCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_GCM,
    MBEDTLS_CIPHER_ARIA_128_GCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_GCM_ARIA
};

static const mbedtls_cipher_info_t esp_aria_192_gcm_info = {
    "ARIA-192-GCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_GCM,
    MBEDTLS_CIPHER_ARIA_192_GCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_GCM_ARIA
};

static const mbedtls_cipher_info_t esp_aria_256_gcm_info = {
    "ARIA-256-GCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_GCM,
    MBEDTLS_CIPHER_ARIA_256_GCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_GCM_ARIA
};
#endif /* MBEDTLS_GCM_C */

#if defined(MBEDTLS_CCM_C)
static int esp_ccm_aria_setkey_wrap(void *ctx, const unsigned char *key,
                                unsigned int key_bitlen)
{
    return esp_mbedtls_ccm_setkey((mbedtls_ccm_context *) ctx, MBEDTLS_CIPHER_ID_ARIA,
                              key, key_bitlen);
}

static const mbedtls_cipher_base_t esp_ccm_aria_info = {
    MBEDTLS_CIPHER_ID_ARIA,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_ccm_aria_setkey_wrap,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_ccm_aria_setkey_wrap,
#endif
    esp_ccm_ctx_alloc,
    esp_ccm_ctx_free,
};

static const mbedtls_cipher_info_t esp_aria_128_ccm_info = {
    "ARIA-128-CCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM,
    MBEDTLS_CIPHER_ARIA_128_CCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_ARIA
};

static const mbedtls_cipher_info_t esp_aria_192_ccm_info = {
    "ARIA-192-CCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM,
    MBEDTLS_CIPHER_ARIA_192_CCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_ARIA
};

static const mbedtls_cipher_info_t esp_aria_256_ccm_info = {
    "ARIA-256-CCM",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM,
    MBEDTLS_CIPHER_ARIA_256_CCM,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_ARIA
};

static const mbedtls_cipher_info_t esp_aria_128_ccm_star_no_tag_info = {
    "ARIA-128-CCM*-NO-TAG",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_ARIA_128_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_ARIA
};

static const mbedtls_cipher_info_t esp_aria_192_ccm_star_no_tag_info = {
    "ARIA-192-CCM*-NO-TAG",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_ARIA_192_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_ARIA
};

static const mbedtls_cipher_info_t esp_aria_256_ccm_star_no_tag_info = {
    "ARIA-256-CCM*-NO-TAG",
    16,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_ARIA_256_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_VARIABLE_IV_LEN,
    MBEDTLS_CIPHER_BASE_INDEX_CCM_ARIA
};
#endif /* MBEDTLS_CCM_C */

#endif /* MBEDTLS_ARIA_C */

#if defined(MBEDTLS_DES_C)

static int esp_des_crypt_ecb_wrap(void *ctx, mbedtls_operation_t operation,
                              const unsigned char *input, unsigned char *output)
{
    ((void) operation);
    return esp_mbedtls_des_crypt_ecb((mbedtls_des_context *) ctx, input, output);
}

static int esp_des3_crypt_ecb_wrap(void *ctx, mbedtls_operation_t operation,
                               const unsigned char *input, unsigned char *output)
{
    ((void) operation);
    return esp_mbedtls_des3_crypt_ecb((mbedtls_des3_context *) ctx, input, output);
}

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static int esp_des_crypt_cbc_wrap(void *ctx, mbedtls_operation_t operation, size_t length,
                              unsigned char *iv, const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_des_crypt_cbc((mbedtls_des_context *) ctx, operation, length, iv, input,
                                 output);
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static int esp_des3_crypt_cbc_wrap(void *ctx, mbedtls_operation_t operation, size_t length,
                               unsigned char *iv, const unsigned char *input, unsigned char *output)
{
    return esp_mbedtls_des3_crypt_cbc((mbedtls_des3_context *) ctx, operation, length, iv, input,
                                  output);
}
#endif /* MBEDTLS_CIPHER_MODE_CBC */

static int esp_des_setkey_dec_wrap(void *ctx, const unsigned char *key,
                               unsigned int key_bitlen)
{
    ((void) key_bitlen);

    return esp_mbedtls_des_setkey_dec((mbedtls_des_context *) ctx, key);
}

static int esp_des_setkey_enc_wrap(void *ctx, const unsigned char *key,
                               unsigned int key_bitlen)
{
    ((void) key_bitlen);

    return esp_mbedtls_des_setkey_enc((mbedtls_des_context *) ctx, key);
}

static int esp_des3_set2key_dec_wrap(void *ctx, const unsigned char *key,
                                 unsigned int key_bitlen)
{
    ((void) key_bitlen);

    return esp_mbedtls_des3_set2key_dec((mbedtls_des3_context *) ctx, key);
}

static int esp_des3_set2key_enc_wrap(void *ctx, const unsigned char *key,
                                 unsigned int key_bitlen)
{
    ((void) key_bitlen);

    return esp_mbedtls_des3_set2key_enc((mbedtls_des3_context *) ctx, key);
}

static int esp_des3_set3key_dec_wrap(void *ctx, const unsigned char *key,
                                 unsigned int key_bitlen)
{
    ((void) key_bitlen);

    return esp_mbedtls_des3_set3key_dec((mbedtls_des3_context *) ctx, key);
}

static int esp_des3_set3key_enc_wrap(void *ctx, const unsigned char *key,
                                 unsigned int key_bitlen)
{
    ((void) key_bitlen);

    return esp_mbedtls_des3_set3key_enc((mbedtls_des3_context *) ctx, key);
}

static void *esp_des_ctx_alloc(void)
{
    mbedtls_des_context *des = esp_mbedtls_calloc(1, sizeof(mbedtls_des_context));

    if (des == NULL) {
        return NULL;
    }

    esp_mbedtls_des_init(des);

    return des;
}

static void esp_des_ctx_free(void *ctx)
{
    esp_mbedtls_des_free((mbedtls_des_context *) ctx);
    esp_mbedtls_free(ctx);
}

static void *esp_des3_ctx_alloc(void)
{
    mbedtls_des3_context *des3;
    des3 = esp_mbedtls_calloc(1, sizeof(mbedtls_des3_context));

    if (des3 == NULL) {
        return NULL;
    }

    esp_mbedtls_des3_init(des3);

    return des3;
}

static void esp_des3_ctx_free(void *ctx)
{
    esp_mbedtls_des3_free((mbedtls_des3_context *) ctx);
    esp_mbedtls_free(ctx);
}

static const mbedtls_cipher_base_t esp_des_info = {
    MBEDTLS_CIPHER_ID_DES,
    esp_des_crypt_ecb_wrap,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    esp_des_crypt_cbc_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_des_setkey_enc_wrap,
    esp_des_setkey_dec_wrap,
    esp_des_ctx_alloc,
    esp_des_ctx_free
};

static const mbedtls_cipher_info_t esp_des_ecb_info = {
    "DES-ECB",
    8,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    MBEDTLS_KEY_LENGTH_DES >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_DES_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_DES
};

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static const mbedtls_cipher_info_t esp_des_cbc_info = {
    "DES-CBC",
    8,
    8 >> MBEDTLS_IV_SIZE_SHIFT,
    MBEDTLS_KEY_LENGTH_DES >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_DES_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_DES
};
#endif /* MBEDTLS_CIPHER_MODE_CBC */

static const mbedtls_cipher_base_t esp_des_ede_info = {
    MBEDTLS_CIPHER_ID_DES,
    esp_des3_crypt_ecb_wrap,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    esp_des3_crypt_cbc_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_des3_set2key_enc_wrap,
    esp_des3_set2key_dec_wrap,
    esp_des3_ctx_alloc,
    esp_des3_ctx_free
};

static const mbedtls_cipher_info_t esp_des_ede_ecb_info = {
    "DES-EDE-ECB",
    8,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    MBEDTLS_KEY_LENGTH_DES_EDE >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_DES_EDE_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_DES_EDE
};

#if defined(MBEDTLS_CIPHER_MODE_CBC)
static const mbedtls_cipher_info_t esp_des_ede_cbc_info = {
    "DES-EDE-CBC",
    8,
    8 >> MBEDTLS_IV_SIZE_SHIFT,
    MBEDTLS_KEY_LENGTH_DES_EDE >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_DES_EDE_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_DES_EDE
};
#endif /* MBEDTLS_CIPHER_MODE_CBC */

static const mbedtls_cipher_base_t esp_des_ede3_info = {
    MBEDTLS_CIPHER_ID_3DES,
    esp_des3_crypt_ecb_wrap,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    esp_des3_crypt_cbc_wrap,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_des3_set3key_enc_wrap,
    esp_des3_set3key_dec_wrap,
    esp_des3_ctx_alloc,
    esp_des3_ctx_free
};

static const mbedtls_cipher_info_t esp_des_ede3_ecb_info = {
    "DES-EDE3-ECB",
    8,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    MBEDTLS_KEY_LENGTH_DES_EDE3 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_ECB,
    MBEDTLS_CIPHER_DES_EDE3_ECB,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_DES_EDE3
};
#if defined(MBEDTLS_CIPHER_MODE_CBC)
static const mbedtls_cipher_info_t esp_des_ede3_cbc_info = {
    "DES-EDE3-CBC",
    8,
    8 >> MBEDTLS_IV_SIZE_SHIFT,
    MBEDTLS_KEY_LENGTH_DES_EDE3 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CBC,
    MBEDTLS_CIPHER_DES_EDE3_CBC,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_DES_EDE3
};
#endif /* MBEDTLS_CIPHER_MODE_CBC */
#endif /* MBEDTLS_DES_C */

#if defined(MBEDTLS_CHACHA20_C)

static int esp_chacha20_setkey_wrap(void *ctx, const unsigned char *key,
                                unsigned int key_bitlen)
{
    if (key_bitlen != 256U) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (0 != esp_mbedtls_chacha20_setkey((mbedtls_chacha20_context *) ctx, key)) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    return 0;
}

static int esp_chacha20_stream_wrap(void *ctx,  size_t length,
                                const unsigned char *input,
                                unsigned char *output)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = esp_mbedtls_chacha20_update(ctx, length, input, output);
    if (ret == MBEDTLS_ERR_CHACHA20_BAD_INPUT_DATA) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    return ret;
}

static void *esp_chacha20_ctx_alloc(void)
{
    mbedtls_chacha20_context *ctx;
    ctx = esp_mbedtls_calloc(1, sizeof(mbedtls_chacha20_context));

    if (ctx == NULL) {
        return NULL;
    }

    esp_mbedtls_chacha20_init(ctx);

    return ctx;
}

static void esp_chacha20_ctx_free(void *ctx)
{
    esp_mbedtls_chacha20_free((mbedtls_chacha20_context *) ctx);
    esp_mbedtls_free(ctx);
}

static const mbedtls_cipher_base_t esp_chacha20_base_info = {
    MBEDTLS_CIPHER_ID_CHACHA20,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    esp_chacha20_stream_wrap,
#endif
    esp_chacha20_setkey_wrap,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_chacha20_setkey_wrap,
#endif
    esp_chacha20_ctx_alloc,
    esp_chacha20_ctx_free
};
static const mbedtls_cipher_info_t esp_chacha20_info = {
    "CHACHA20",
    1,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_STREAM,
    MBEDTLS_CIPHER_CHACHA20,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CHACHA20_BASE
};
#endif /* MBEDTLS_CHACHA20_C */

#if defined(MBEDTLS_CHACHAPOLY_C)

static int esp_chachapoly_setkey_wrap(void *ctx,
                                  const unsigned char *key,
                                  unsigned int key_bitlen)
{
    if (key_bitlen != 256U) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    if (0 != esp_mbedtls_chachapoly_setkey((mbedtls_chachapoly_context *) ctx, key)) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    return 0;
}

static void *esp_chachapoly_ctx_alloc(void)
{
    mbedtls_chachapoly_context *ctx;
    ctx = esp_mbedtls_calloc(1, sizeof(mbedtls_chachapoly_context));

    if (ctx == NULL) {
        return NULL;
    }

    esp_mbedtls_chachapoly_init(ctx);

    return ctx;
}

static void esp_chachapoly_ctx_free(void *ctx)
{
    esp_mbedtls_chachapoly_free((mbedtls_chachapoly_context *) ctx);
    esp_mbedtls_free(ctx);
}

static const mbedtls_cipher_base_t esp_chachapoly_base_info = {
    MBEDTLS_CIPHER_ID_CHACHA20,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_chachapoly_setkey_wrap,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_chachapoly_setkey_wrap,
#endif
    esp_chachapoly_ctx_alloc,
    esp_chachapoly_ctx_free
};
static const mbedtls_cipher_info_t esp_chachapoly_info = {
    "CHACHA20-POLY1305",
    1,
    12 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_CHACHAPOLY,
    MBEDTLS_CIPHER_CHACHA20_POLY1305,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_CHACHAPOLY_BASE
};
#endif /* MBEDTLS_CHACHAPOLY_C */

#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
static int esp_null_crypt_stream(void *ctx, size_t length,
                             const unsigned char *input,
                             unsigned char *output)
{
    ((void) ctx);
    memmove(output, input, length);
    return 0;
}

static int esp_null_setkey(void *ctx, const unsigned char *key,
                       unsigned int key_bitlen)
{
    ((void) ctx);
    ((void) key);
    ((void) key_bitlen);

    return 0;
}

static void *esp_null_ctx_alloc(void)
{
    return (void *) 1;
}

static void esp_null_ctx_free(void *ctx)
{
    ((void) ctx);
}

static const mbedtls_cipher_base_t esp_null_base_info = {
    MBEDTLS_CIPHER_ID_NULL,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    esp_null_crypt_stream,
#endif
    esp_null_setkey,
#if !defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
    esp_null_setkey,
#endif
    esp_null_ctx_alloc,
    esp_null_ctx_free
};

static const mbedtls_cipher_info_t esp_null_cipher_info = {
    "NULL",
    1,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    0 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_STREAM,
    MBEDTLS_CIPHER_NULL,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_NULL_BASE
};
#endif /* defined(MBEDTLS_CIPHER_NULL_CIPHER) */

#if defined(MBEDTLS_NIST_KW_C)
static void *esp_kw_ctx_alloc(void)
{
    void *ctx = esp_mbedtls_calloc(1, sizeof(mbedtls_nist_kw_context));

    if (ctx != NULL) {
        esp_mbedtls_nist_kw_init((mbedtls_nist_kw_context *) ctx);
    }

    return ctx;
}

static void esp_kw_ctx_free(void *ctx)
{
    esp_mbedtls_nist_kw_free(ctx);
    esp_mbedtls_free(ctx);
}

static int esp_kw_aes_setkey_wrap(void *ctx, const unsigned char *key,
                              unsigned int key_bitlen)
{
    return esp_mbedtls_nist_kw_setkey((mbedtls_nist_kw_context *) ctx,
                                  MBEDTLS_CIPHER_ID_AES, key, key_bitlen, 1);
}

static int esp_kw_aes_setkey_unwrap(void *ctx, const unsigned char *key,
                                unsigned int key_bitlen)
{
    return esp_mbedtls_nist_kw_setkey((mbedtls_nist_kw_context *) ctx,
                                  MBEDTLS_CIPHER_ID_AES, key, key_bitlen, 0);
}

static const mbedtls_cipher_base_t esp_kw_aes_info = {
    MBEDTLS_CIPHER_ID_AES,
    NULL,
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    NULL,
#endif
#if defined(MBEDTLS_CIPHER_MODE_STREAM)
    NULL,
#endif
    esp_kw_aes_setkey_wrap,
    esp_kw_aes_setkey_unwrap,
    esp_kw_ctx_alloc,
    esp_kw_ctx_free,
};

static const mbedtls_cipher_info_t esp_aes_128_nist_kw_info = {
    "AES-128-KW",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_KW,
    MBEDTLS_CIPHER_AES_128_KW,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_KW_AES
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const mbedtls_cipher_info_t esp_aes_192_nist_kw_info = {
    "AES-192-KW",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_KW,
    MBEDTLS_CIPHER_AES_192_KW,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_KW_AES
};

static const mbedtls_cipher_info_t esp_aes_256_nist_kw_info = {
    "AES-256-KW",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_KW,
    MBEDTLS_CIPHER_AES_256_KW,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_KW_AES
};
#endif

static const mbedtls_cipher_info_t esp_aes_128_nist_kwp_info = {
    "AES-128-KWP",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    128 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_KWP,
    MBEDTLS_CIPHER_AES_128_KWP,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_KW_AES
};

#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
static const mbedtls_cipher_info_t esp_aes_192_nist_kwp_info = {
    "AES-192-KWP",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    192 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_KWP,
    MBEDTLS_CIPHER_AES_192_KWP,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_KW_AES
};

static const mbedtls_cipher_info_t esp_aes_256_nist_kwp_info = {
    "AES-256-KWP",
    16,
    0 >> MBEDTLS_IV_SIZE_SHIFT,
    256 >> MBEDTLS_KEY_BITLEN_SHIFT,
    MBEDTLS_MODE_KWP,
    MBEDTLS_CIPHER_AES_256_KWP,
    0,
    MBEDTLS_CIPHER_BASE_INDEX_KW_AES
};
#endif
#endif /* MBEDTLS_NIST_KW_C */

const mbedtls_cipher_definition_t esp_mbedtls_cipher_definitions[] =
{
#if defined(MBEDTLS_AES_C)
    { MBEDTLS_CIPHER_AES_128_ECB,          &esp_aes_128_ecb_info },
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    { MBEDTLS_CIPHER_AES_192_ECB,          &esp_aes_192_ecb_info },
    { MBEDTLS_CIPHER_AES_256_ECB,          &esp_aes_256_ecb_info },
#endif
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    { MBEDTLS_CIPHER_AES_128_CBC,          &esp_aes_128_cbc_info },
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    { MBEDTLS_CIPHER_AES_192_CBC,          &esp_aes_192_cbc_info },
    { MBEDTLS_CIPHER_AES_256_CBC,          &esp_aes_256_cbc_info },
#endif
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    { MBEDTLS_CIPHER_AES_128_CFB128,       &esp_aes_128_cfb128_info },
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    { MBEDTLS_CIPHER_AES_192_CFB128,       &esp_aes_192_cfb128_info },
    { MBEDTLS_CIPHER_AES_256_CFB128,       &esp_aes_256_cfb128_info },
#endif
#endif
#if defined(MBEDTLS_CIPHER_MODE_OFB)
    { MBEDTLS_CIPHER_AES_128_OFB,          &esp_aes_128_ofb_info },
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    { MBEDTLS_CIPHER_AES_192_OFB,          &esp_aes_192_ofb_info },
    { MBEDTLS_CIPHER_AES_256_OFB,          &esp_aes_256_ofb_info },
#endif
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    { MBEDTLS_CIPHER_AES_128_CTR,          &esp_aes_128_ctr_info },
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    { MBEDTLS_CIPHER_AES_192_CTR,          &esp_aes_192_ctr_info },
    { MBEDTLS_CIPHER_AES_256_CTR,          &esp_aes_256_ctr_info },
#endif
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS)
    { MBEDTLS_CIPHER_AES_128_XTS,          &esp_aes_128_xts_info },
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    { MBEDTLS_CIPHER_AES_256_XTS,          &esp_aes_256_xts_info },
#endif
#endif
#endif /* MBEDTLS_AES_C */
#if defined(MBEDTLS_CIPHER_HAVE_GCM_AES_VIA_LEGACY_OR_USE_PSA)
    { MBEDTLS_CIPHER_AES_128_GCM,          &esp_aes_128_gcm_info },
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    { MBEDTLS_CIPHER_AES_192_GCM,          &esp_aes_192_gcm_info },
    { MBEDTLS_CIPHER_AES_256_GCM,          &esp_aes_256_gcm_info },
#endif
#endif
#if defined(MBEDTLS_CIPHER_HAVE_CCM_AES_VIA_LEGACY_OR_USE_PSA)
    { MBEDTLS_CIPHER_AES_128_CCM,          &esp_aes_128_ccm_info },
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    { MBEDTLS_CIPHER_AES_192_CCM,          &esp_aes_192_ccm_info },
    { MBEDTLS_CIPHER_AES_256_CCM,          &esp_aes_256_ccm_info },
#endif
#endif
#if defined(MBEDTLS_CIPHER_HAVE_CCM_STAR_NO_TAG_AES_VIA_LEGACY_OR_USE_PSA)
    { MBEDTLS_CIPHER_AES_128_CCM_STAR_NO_TAG,          &esp_aes_128_ccm_star_no_tag_info },
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    { MBEDTLS_CIPHER_AES_192_CCM_STAR_NO_TAG,          &esp_aes_192_ccm_star_no_tag_info },
    { MBEDTLS_CIPHER_AES_256_CCM_STAR_NO_TAG,          &esp_aes_256_ccm_star_no_tag_info },
#endif
#endif

#if defined(MBEDTLS_CAMELLIA_C)
    { MBEDTLS_CIPHER_CAMELLIA_128_ECB,     &esp_camellia_128_ecb_info },
    { MBEDTLS_CIPHER_CAMELLIA_192_ECB,     &esp_camellia_192_ecb_info },
    { MBEDTLS_CIPHER_CAMELLIA_256_ECB,     &esp_camellia_256_ecb_info },
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    { MBEDTLS_CIPHER_CAMELLIA_128_CBC,     &esp_camellia_128_cbc_info },
    { MBEDTLS_CIPHER_CAMELLIA_192_CBC,     &esp_camellia_192_cbc_info },
    { MBEDTLS_CIPHER_CAMELLIA_256_CBC,     &esp_camellia_256_cbc_info },
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    { MBEDTLS_CIPHER_CAMELLIA_128_CFB128,  &esp_camellia_128_cfb128_info },
    { MBEDTLS_CIPHER_CAMELLIA_192_CFB128,  &esp_camellia_192_cfb128_info },
    { MBEDTLS_CIPHER_CAMELLIA_256_CFB128,  &esp_camellia_256_cfb128_info },
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    { MBEDTLS_CIPHER_CAMELLIA_128_CTR,     &esp_camellia_128_ctr_info },
    { MBEDTLS_CIPHER_CAMELLIA_192_CTR,     &esp_camellia_192_ctr_info },
    { MBEDTLS_CIPHER_CAMELLIA_256_CTR,     &esp_camellia_256_ctr_info },
#endif
#if defined(MBEDTLS_GCM_C)
    { MBEDTLS_CIPHER_CAMELLIA_128_GCM,     &esp_camellia_128_gcm_info },
    { MBEDTLS_CIPHER_CAMELLIA_192_GCM,     &esp_camellia_192_gcm_info },
    { MBEDTLS_CIPHER_CAMELLIA_256_GCM,     &esp_camellia_256_gcm_info },
#endif
#if defined(MBEDTLS_CCM_C)
    { MBEDTLS_CIPHER_CAMELLIA_128_CCM,     &esp_camellia_128_ccm_info },
    { MBEDTLS_CIPHER_CAMELLIA_192_CCM,     &esp_camellia_192_ccm_info },
    { MBEDTLS_CIPHER_CAMELLIA_256_CCM,     &esp_camellia_256_ccm_info },
    { MBEDTLS_CIPHER_CAMELLIA_128_CCM_STAR_NO_TAG,     &esp_camellia_128_ccm_star_no_tag_info },
    { MBEDTLS_CIPHER_CAMELLIA_192_CCM_STAR_NO_TAG,     &esp_camellia_192_ccm_star_no_tag_info },
    { MBEDTLS_CIPHER_CAMELLIA_256_CCM_STAR_NO_TAG,     &esp_camellia_256_ccm_star_no_tag_info },
#endif
#endif /* MBEDTLS_CAMELLIA_C */

#if defined(MBEDTLS_ARIA_C)
    { MBEDTLS_CIPHER_ARIA_128_ECB,     &esp_aria_128_ecb_info },
    { MBEDTLS_CIPHER_ARIA_192_ECB,     &esp_aria_192_ecb_info },
    { MBEDTLS_CIPHER_ARIA_256_ECB,     &esp_aria_256_ecb_info },
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    { MBEDTLS_CIPHER_ARIA_128_CBC,     &esp_aria_128_cbc_info },
    { MBEDTLS_CIPHER_ARIA_192_CBC,     &esp_aria_192_cbc_info },
    { MBEDTLS_CIPHER_ARIA_256_CBC,     &esp_aria_256_cbc_info },
#endif
#if defined(MBEDTLS_CIPHER_MODE_CFB)
    { MBEDTLS_CIPHER_ARIA_128_CFB128,  &esp_aria_128_cfb128_info },
    { MBEDTLS_CIPHER_ARIA_192_CFB128,  &esp_aria_192_cfb128_info },
    { MBEDTLS_CIPHER_ARIA_256_CFB128,  &esp_aria_256_cfb128_info },
#endif
#if defined(MBEDTLS_CIPHER_MODE_CTR)
    { MBEDTLS_CIPHER_ARIA_128_CTR,     &esp_aria_128_ctr_info },
    { MBEDTLS_CIPHER_ARIA_192_CTR,     &esp_aria_192_ctr_info },
    { MBEDTLS_CIPHER_ARIA_256_CTR,     &esp_aria_256_ctr_info },
#endif
#if defined(MBEDTLS_GCM_C)
    { MBEDTLS_CIPHER_ARIA_128_GCM,     &esp_aria_128_gcm_info },
    { MBEDTLS_CIPHER_ARIA_192_GCM,     &esp_aria_192_gcm_info },
    { MBEDTLS_CIPHER_ARIA_256_GCM,     &esp_aria_256_gcm_info },
#endif
#if defined(MBEDTLS_CCM_C)
    { MBEDTLS_CIPHER_ARIA_128_CCM,     &esp_aria_128_ccm_info },
    { MBEDTLS_CIPHER_ARIA_192_CCM,     &esp_aria_192_ccm_info },
    { MBEDTLS_CIPHER_ARIA_256_CCM,     &esp_aria_256_ccm_info },
    { MBEDTLS_CIPHER_ARIA_128_CCM_STAR_NO_TAG,     &esp_aria_128_ccm_star_no_tag_info },
    { MBEDTLS_CIPHER_ARIA_192_CCM_STAR_NO_TAG,     &esp_aria_192_ccm_star_no_tag_info },
    { MBEDTLS_CIPHER_ARIA_256_CCM_STAR_NO_TAG,     &esp_aria_256_ccm_star_no_tag_info },
#endif
#endif /* MBEDTLS_ARIA_C */

#if defined(MBEDTLS_DES_C)
    { MBEDTLS_CIPHER_DES_ECB,              &esp_des_ecb_info },
    { MBEDTLS_CIPHER_DES_EDE_ECB,          &esp_des_ede_ecb_info },
    { MBEDTLS_CIPHER_DES_EDE3_ECB,         &esp_des_ede3_ecb_info },
#if defined(MBEDTLS_CIPHER_MODE_CBC)
    { MBEDTLS_CIPHER_DES_CBC,              &esp_des_cbc_info },
    { MBEDTLS_CIPHER_DES_EDE_CBC,          &esp_des_ede_cbc_info },
    { MBEDTLS_CIPHER_DES_EDE3_CBC,         &esp_des_ede3_cbc_info },
#endif
#endif /* MBEDTLS_DES_C */

#if defined(MBEDTLS_CHACHA20_C)
    { MBEDTLS_CIPHER_CHACHA20,             &esp_chacha20_info },
#endif

#if defined(MBEDTLS_CHACHAPOLY_C)
    { MBEDTLS_CIPHER_CHACHA20_POLY1305,    &esp_chachapoly_info },
#endif

#if defined(MBEDTLS_NIST_KW_C)
    { MBEDTLS_CIPHER_AES_128_KW,          &esp_aes_128_nist_kw_info },
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    { MBEDTLS_CIPHER_AES_192_KW,          &esp_aes_192_nist_kw_info },
    { MBEDTLS_CIPHER_AES_256_KW,          &esp_aes_256_nist_kw_info },
#endif
    { MBEDTLS_CIPHER_AES_128_KWP,         &esp_aes_128_nist_kwp_info },
#if !defined(MBEDTLS_AES_ONLY_128_BIT_KEY_LENGTH)
    { MBEDTLS_CIPHER_AES_192_KWP,         &esp_aes_192_nist_kwp_info },
    { MBEDTLS_CIPHER_AES_256_KWP,         &esp_aes_256_nist_kwp_info },
#endif
#endif

#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
    { MBEDTLS_CIPHER_NULL,                 &esp_null_cipher_info },
#endif /* MBEDTLS_CIPHER_NULL_CIPHER */

    { MBEDTLS_CIPHER_NONE, NULL }
};

#define NUM_CIPHERS (sizeof(esp_mbedtls_cipher_definitions) /      \
                     sizeof(esp_mbedtls_cipher_definitions[0]))
int esp_mbedtls_cipher_supported[NUM_CIPHERS];

const mbedtls_cipher_base_t *esp_mbedtls_cipher_base_lookup_table[] = {
#if defined(MBEDTLS_AES_C)
    [MBEDTLS_CIPHER_BASE_INDEX_AES] = &esp_aes_info,
#endif
#if defined(MBEDTLS_ARIA_C)
    [MBEDTLS_CIPHER_BASE_INDEX_ARIA] = &esp_aria_info,
#endif
#if defined(MBEDTLS_CAMELLIA_C)
    [MBEDTLS_CIPHER_BASE_INDEX_CAMELLIA] = &esp_camellia_info,
#endif
#if defined(MBEDTLS_CIPHER_HAVE_CCM_AES_VIA_LEGACY_OR_USE_PSA)
    [MBEDTLS_CIPHER_BASE_INDEX_CCM_AES] = &esp_ccm_aes_info,
#endif
#if defined(MBEDTLS_CCM_C) && defined(MBEDTLS_ARIA_C)
    [MBEDTLS_CIPHER_BASE_INDEX_CCM_ARIA] = &esp_ccm_aria_info,
#endif
#if defined(MBEDTLS_CCM_C) && defined(MBEDTLS_CAMELLIA_C)
    [MBEDTLS_CIPHER_BASE_INDEX_CCM_CAMELLIA] = &esp_ccm_camellia_info,
#endif
#if defined(MBEDTLS_CHACHA20_C)
    [MBEDTLS_CIPHER_BASE_INDEX_CHACHA20_BASE] = &esp_chacha20_base_info,
#endif
#if defined(MBEDTLS_CHACHAPOLY_C)
    [MBEDTLS_CIPHER_BASE_INDEX_CHACHAPOLY_BASE] = &esp_chachapoly_base_info,
#endif
#if defined(MBEDTLS_DES_C)
    [MBEDTLS_CIPHER_BASE_INDEX_DES_EDE3] = &esp_des_ede3_info,
#endif
#if defined(MBEDTLS_DES_C)
    [MBEDTLS_CIPHER_BASE_INDEX_DES_EDE] = &esp_des_ede_info,
#endif
#if defined(MBEDTLS_DES_C)
    [MBEDTLS_CIPHER_BASE_INDEX_DES] = &esp_des_info,
#endif
#if defined(MBEDTLS_CIPHER_HAVE_GCM_AES_VIA_LEGACY_OR_USE_PSA)
    [MBEDTLS_CIPHER_BASE_INDEX_GCM_AES] = &esp_gcm_aes_info,
#endif
#if defined(MBEDTLS_GCM_C) && defined(MBEDTLS_ARIA_C)
    [MBEDTLS_CIPHER_BASE_INDEX_GCM_ARIA] = &esp_gcm_aria_info,
#endif
#if defined(MBEDTLS_GCM_C) && defined(MBEDTLS_CAMELLIA_C)
    [MBEDTLS_CIPHER_BASE_INDEX_GCM_CAMELLIA] = &esp_gcm_camellia_info,
#endif
#if defined(MBEDTLS_NIST_KW_C)
    [MBEDTLS_CIPHER_BASE_INDEX_KW_AES] = &esp_kw_aes_info,
#endif
#if defined(MBEDTLS_CIPHER_NULL_CIPHER)
    [MBEDTLS_CIPHER_BASE_INDEX_NULL_BASE] = &esp_null_base_info,
#endif
#if defined(MBEDTLS_CIPHER_MODE_XTS) && defined(MBEDTLS_AES_C)
    [MBEDTLS_CIPHER_BASE_INDEX_XTS_AES] = &esp_xts_aes_info
#endif
};

#endif /* MBEDTLS_CIPHER_C */
