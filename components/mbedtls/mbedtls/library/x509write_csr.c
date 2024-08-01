/*
 *  X.509 Certificate Signing Request writing
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
/*
 * References:
 * - CSRs: PKCS#10 v1.7 aka RFC 2986
 * - attributes: PKCS#9 v2.0 aka RFC 2985
 */

#include "common.h"

#if defined(MBEDTLS_X509_CSR_WRITE_C)

#include "x509_internal.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/error.h"
#include "mbedtls/oid.h"
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#include "psa/crypto.h"
#include "psa_util_internal.h"
#include "mbedtls/psa_util.h"
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#include <string.h>
#include <stdlib.h>

#if defined(MBEDTLS_PEM_WRITE_C)
#include "mbedtls/pem.h"
#endif

#include "mbedtls/platform.h"

void esp_mbedtls_x509write_csr_init(mbedtls_x509write_csr *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_x509write_csr));
}

void esp_mbedtls_x509write_csr_free(mbedtls_x509write_csr *ctx)
{
    esp_mbedtls_asn1_free_named_data_list(&ctx->subject);
    esp_mbedtls_asn1_free_named_data_list(&ctx->extensions);

    esp_mbedtls_platform_zeroize(ctx, sizeof(mbedtls_x509write_csr));
}

void esp_mbedtls_x509write_csr_set_md_alg(mbedtls_x509write_csr *ctx, mbedtls_md_type_t md_alg)
{
    ctx->md_alg = md_alg;
}

void esp_mbedtls_x509write_csr_set_key(mbedtls_x509write_csr *ctx, mbedtls_pk_context *key)
{
    ctx->key = key;
}

int esp_mbedtls_x509write_csr_set_subject_name(mbedtls_x509write_csr *ctx,
                                           const char *subject_name)
{
    return esp_mbedtls_x509_string_to_names(&ctx->subject, subject_name);
}

int esp_mbedtls_x509write_csr_set_extension(mbedtls_x509write_csr *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        const unsigned char *val, size_t val_len)
{
    return esp_mbedtls_x509_set_extension(&ctx->extensions, oid, oid_len,
                                      critical, val, val_len);
}

int esp_mbedtls_x509write_csr_set_subject_alternative_name(mbedtls_x509write_csr *ctx,
                                                       const mbedtls_x509_san_list *san_list)
{
    return esp_mbedtls_x509_write_set_san_common(&ctx->extensions, san_list);
}

int esp_mbedtls_x509write_csr_set_key_usage(mbedtls_x509write_csr *ctx, unsigned char key_usage)
{
    unsigned char buf[4] = { 0 };
    unsigned char *c;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    c = buf + 4;

    ret = esp_mbedtls_asn1_write_named_bitstring(&c, buf, &key_usage, 8);
    if (ret < 3 || ret > 4) {
        return ret;
    }

    ret = esp_mbedtls_x509write_csr_set_extension(ctx, MBEDTLS_OID_KEY_USAGE,
                                              MBEDTLS_OID_SIZE(MBEDTLS_OID_KEY_USAGE),
                                              0, c, (size_t) ret);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

int esp_mbedtls_x509write_csr_set_ns_cert_type(mbedtls_x509write_csr *ctx,
                                           unsigned char ns_cert_type)
{
    unsigned char buf[4] = { 0 };
    unsigned char *c;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    c = buf + 4;

    ret = esp_mbedtls_asn1_write_named_bitstring(&c, buf, &ns_cert_type, 8);
    if (ret < 3 || ret > 4) {
        return ret;
    }

    ret = esp_mbedtls_x509write_csr_set_extension(ctx, MBEDTLS_OID_NS_CERT_TYPE,
                                              MBEDTLS_OID_SIZE(MBEDTLS_OID_NS_CERT_TYPE),
                                              0, c, (size_t) ret);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static int esp_x509write_csr_der_internal(mbedtls_x509write_csr *ctx,
                                      unsigned char *buf,
                                      size_t size,
                                      unsigned char *sig, size_t sig_size,
                                      int (*f_rng)(void *, unsigned char *, size_t),
                                      void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const char *sig_oid;
    size_t sig_oid_len = 0;
    unsigned char *c, *c2;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    size_t pub_len = 0, sig_and_oid_len = 0, sig_len;
    size_t len = 0;
    mbedtls_pk_type_t pk_alg;
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    size_t hash_len;
    psa_algorithm_t hash_alg = esp_mbedtls_md_psa_alg_from_type(ctx->md_alg);
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    /* Write the CSR backwards starting from the end of buf */
    c = buf + size;

    MBEDTLS_ASN1_CHK_ADD(len, esp_mbedtls_x509_write_extensions(&c, buf,
                                                            ctx->extensions));

    if (len) {
        MBEDTLS_ASN1_CHK_ADD(len, esp_mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             esp_mbedtls_asn1_write_tag(
                                 &c, buf,
                                 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

        MBEDTLS_ASN1_CHK_ADD(len, esp_mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             esp_mbedtls_asn1_write_tag(
                                 &c, buf,
                                 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET));

        MBEDTLS_ASN1_CHK_ADD(len,
                             esp_mbedtls_asn1_write_oid(
                                 &c, buf, MBEDTLS_OID_PKCS9_CSR_EXT_REQ,
                                 MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS9_CSR_EXT_REQ)));

        MBEDTLS_ASN1_CHK_ADD(len, esp_mbedtls_asn1_write_len(&c, buf, len));
        MBEDTLS_ASN1_CHK_ADD(len,
                             esp_mbedtls_asn1_write_tag(
                                 &c, buf,
                                 MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
    }

    MBEDTLS_ASN1_CHK_ADD(len, esp_mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         esp_mbedtls_asn1_write_tag(
                             &c, buf,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC));

    MBEDTLS_ASN1_CHK_ADD(pub_len, esp_mbedtls_pk_write_pubkey_der(ctx->key,
                                                              buf, (size_t) (c - buf)));
    c -= pub_len;
    len += pub_len;

    /*
     *  Subject  ::=  Name
     */
    MBEDTLS_ASN1_CHK_ADD(len, esp_mbedtls_x509_write_names(&c, buf,
                                                       ctx->subject));

    /*
     *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     */
    MBEDTLS_ASN1_CHK_ADD(len, esp_mbedtls_asn1_write_int(&c, buf, 0));

    MBEDTLS_ASN1_CHK_ADD(len, esp_mbedtls_asn1_write_len(&c, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         esp_mbedtls_asn1_write_tag(
                             &c, buf,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    /*
     * Sign the written CSR data into the sig buffer
     * Note: hash errors can happen only after an internal error
     */
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    if (esp_psa_hash_compute(hash_alg,
                         c,
                         len,
                         hash,
                         sizeof(hash),
                         &hash_len) != PSA_SUCCESS) {
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
    }
#else /* MBEDTLS_USE_PSA_CRYPTO */
    ret = esp_mbedtls_md(esp_mbedtls_md_info_from_type(ctx->md_alg), c, len, hash);
    if (ret != 0) {
        return ret;
    }
#endif
    if ((ret = esp_mbedtls_pk_sign(ctx->key, ctx->md_alg, hash, 0,
                               sig, sig_size, &sig_len,
                               f_rng, p_rng)) != 0) {
        return ret;
    }

    if (esp_mbedtls_pk_can_do(ctx->key, MBEDTLS_PK_RSA)) {
        pk_alg = MBEDTLS_PK_RSA;
    } else if (esp_mbedtls_pk_can_do(ctx->key, MBEDTLS_PK_ECDSA)) {
        pk_alg = MBEDTLS_PK_ECDSA;
    } else {
        return MBEDTLS_ERR_X509_INVALID_ALG;
    }

    if ((ret = esp_mbedtls_oid_get_oid_by_sig_alg(pk_alg, ctx->md_alg,
                                              &sig_oid, &sig_oid_len)) != 0) {
        return ret;
    }

    /*
     * Move the written CSR data to the start of buf to create space for
     * writing the signature into buf.
     */
    memmove(buf, c, len);

    /*
     * Write sig and its OID into buf backwards from the end of buf.
     * Note: esp_mbedtls_x509_write_sig will check for c2 - ( buf + len ) < sig_len
     * and return MBEDTLS_ERR_ASN1_BUF_TOO_SMALL if needed.
     */
    c2 = buf + size;
    MBEDTLS_ASN1_CHK_ADD(sig_and_oid_len,
                         esp_mbedtls_x509_write_sig(&c2, buf + len, sig_oid, sig_oid_len,
                                                sig, sig_len, pk_alg));

    /*
     * Compact the space between the CSR data and signature by moving the
     * CSR data to the start of the signature.
     */
    c2 -= len;
    memmove(c2, buf, len);

    /* ASN encode the total size and tag the CSR data with it. */
    len += sig_and_oid_len;
    MBEDTLS_ASN1_CHK_ADD(len, esp_mbedtls_asn1_write_len(&c2, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         esp_mbedtls_asn1_write_tag(
                             &c2, buf,
                             MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

    /* Zero the unused bytes at the start of buf */
    memset(buf, 0, (size_t) (c2 - buf));

    return (int) len;
}

int esp_mbedtls_x509write_csr_der(mbedtls_x509write_csr *ctx, unsigned char *buf,
                              size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret;
    unsigned char *sig;

    if ((sig = esp_mbedtls_calloc(1, MBEDTLS_PK_SIGNATURE_MAX_SIZE)) == NULL) {
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    ret = esp_x509write_csr_der_internal(ctx, buf, size,
                                     sig, MBEDTLS_PK_SIGNATURE_MAX_SIZE,
                                     f_rng, p_rng);

    esp_mbedtls_free(sig);

    return ret;
}

#define PEM_BEGIN_CSR           "-----BEGIN CERTIFICATE REQUEST-----\n"
#define PEM_END_CSR             "-----END CERTIFICATE REQUEST-----\n"

#if defined(MBEDTLS_PEM_WRITE_C)
int esp_mbedtls_x509write_csr_pem(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen = 0;

    if ((ret = esp_mbedtls_x509write_csr_der(ctx, buf, size,
                                         f_rng, p_rng)) < 0) {
        return ret;
    }

    if ((ret = esp_mbedtls_pem_write_buffer(PEM_BEGIN_CSR, PEM_END_CSR,
                                        buf + size - ret,
                                        ret, buf, size, &olen)) != 0) {
        return ret;
    }

    return 0;
}
#endif /* MBEDTLS_PEM_WRITE_C */

#endif /* MBEDTLS_X509_CSR_WRITE_C */
