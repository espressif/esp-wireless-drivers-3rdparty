/*
 *  Elliptic curve Diffie-Hellman
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

/*
 * References:
 *
 * SEC1 https://www.secg.org/sec1-v2.pdf
 * RFC 4492
 */

#include "common.h"

#if defined(MBEDTLS_ECDH_C)

#include "mbedtls/ecdh.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
typedef mbedtls_ecdh_context mbedtls_ecdh_context_mbed;
#endif

static mbedtls_ecp_group_id esp_mbedtls_ecdh_grp_id(
    const mbedtls_ecdh_context *ctx)
{
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ctx->grp.id;
#else
    return ctx->grp_id;
#endif
}

int esp_mbedtls_ecdh_can_do(mbedtls_ecp_group_id gid)
{
    /* At this time, all groups support ECDH. */
    (void) gid;
    return 1;
}

#if !defined(MBEDTLS_ECDH_GEN_PUBLIC_ALT)
/*
 * Generate public key (restartable version)
 *
 * Note: this internal function relies on its caller preserving the value of
 * the output parameter 'd' across continuation calls. This would not be
 * acceptable for a public function but is OK here as we control call sites.
 */
static int esp_ecdh_gen_public_restartable(mbedtls_ecp_group *grp,
                                       mbedtls_mpi *d, mbedtls_ecp_point *Q,
                                       int (*f_rng)(void *, unsigned char *, size_t),
                                       void *p_rng,
                                       mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    int restarting = 0;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    restarting = (rs_ctx != NULL && rs_ctx->rsm != NULL);
#endif
    /* If multiplication is in progress, we already generated a privkey */
    if (!restarting) {
        MBEDTLS_MPI_CHK(esp_mbedtls_ecp_gen_privkey(grp, d, f_rng, p_rng));
    }

    MBEDTLS_MPI_CHK(esp_mbedtls_ecp_mul_restartable(grp, Q, d, &grp->G,
                                                f_rng, p_rng, rs_ctx));

cleanup:
    return ret;
}

/*
 * Generate public key
 */
int esp_mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q,
                            int (*f_rng)(void *, unsigned char *, size_t),
                            void *p_rng)
{
    return esp_ecdh_gen_public_restartable(grp, d, Q, f_rng, p_rng, NULL);
}
#endif /* !MBEDTLS_ECDH_GEN_PUBLIC_ALT */

#if !defined(MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
/*
 * Compute shared secret (SEC1 3.3.1)
 */
static int esp_ecdh_compute_shared_restartable(mbedtls_ecp_group *grp,
                                           mbedtls_mpi *z,
                                           const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                           int (*f_rng)(void *, unsigned char *, size_t),
                                           void *p_rng,
                                           mbedtls_ecp_restart_ctx *rs_ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_point P;

    esp_mbedtls_ecp_point_init(&P);

    MBEDTLS_MPI_CHK(esp_mbedtls_ecp_mul_restartable(grp, &P, d, Q,
                                                f_rng, p_rng, rs_ctx));

    if (esp_mbedtls_ecp_is_zero(&P)) {
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_copy(z, &P.X));

cleanup:
    esp_mbedtls_ecp_point_free(&P);

    return ret;
}

/*
 * Compute shared secret (SEC1 3.3.1)
 */
int esp_mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng)
{
    return esp_ecdh_compute_shared_restartable(grp, z, Q, d,
                                           f_rng, p_rng, NULL);
}
#endif /* !MBEDTLS_ECDH_COMPUTE_SHARED_ALT */

static void esp_ecdh_init_internal(mbedtls_ecdh_context_mbed *ctx)
{
    esp_mbedtls_ecp_group_init(&ctx->grp);
    esp_mbedtls_mpi_init(&ctx->d);
    esp_mbedtls_ecp_point_init(&ctx->Q);
    esp_mbedtls_ecp_point_init(&ctx->Qp);
    esp_mbedtls_mpi_init(&ctx->z);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    esp_mbedtls_ecp_restart_init(&ctx->rs);
#endif
}

mbedtls_ecp_group_id esp_mbedtls_ecdh_get_grp_id(mbedtls_ecdh_context *ctx)
{
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return ctx->MBEDTLS_PRIVATE(grp).id;
#else
    return ctx->MBEDTLS_PRIVATE(grp_id);
#endif
}

/*
 * Initialize context
 */
void esp_mbedtls_ecdh_init(mbedtls_ecdh_context *ctx)
{
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    esp_ecdh_init_internal(ctx);
    esp_mbedtls_ecp_point_init(&ctx->Vi);
    esp_mbedtls_ecp_point_init(&ctx->Vf);
    esp_mbedtls_mpi_init(&ctx->_d);
#else
    memset(ctx, 0, sizeof(mbedtls_ecdh_context));

    ctx->var = MBEDTLS_ECDH_VARIANT_NONE;
#endif
    ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    ctx->restart_enabled = 0;
#endif
}

static int esp_ecdh_setup_internal(mbedtls_ecdh_context_mbed *ctx,
                               mbedtls_ecp_group_id grp_id)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    ret = esp_mbedtls_ecp_group_load(&ctx->grp, grp_id);
    if (ret != 0) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    return 0;
}

/*
 * Setup context
 */
int esp_mbedtls_ecdh_setup(mbedtls_ecdh_context *ctx, mbedtls_ecp_group_id grp_id)
{
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return esp_ecdh_setup_internal(ctx, grp_id);
#else
    switch (grp_id) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECP_DP_CURVE25519:
            ctx->point_format = MBEDTLS_ECP_PF_COMPRESSED;
            ctx->var = MBEDTLS_ECDH_VARIANT_EVEREST;
            ctx->grp_id = grp_id;
            return mbedtls_everest_setup(&ctx->ctx.everest_ecdh, grp_id);
#endif
        default:
            ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;
            ctx->var = MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0;
            ctx->grp_id = grp_id;
            esp_ecdh_init_internal(&ctx->ctx.mbed_ecdh);
            return esp_ecdh_setup_internal(&ctx->ctx.mbed_ecdh, grp_id);
    }
#endif
}

static void esp_ecdh_free_internal(mbedtls_ecdh_context_mbed *ctx)
{
    esp_mbedtls_ecp_group_free(&ctx->grp);
    esp_mbedtls_mpi_free(&ctx->d);
    esp_mbedtls_ecp_point_free(&ctx->Q);
    esp_mbedtls_ecp_point_free(&ctx->Qp);
    esp_mbedtls_mpi_free(&ctx->z);

#if defined(MBEDTLS_ECP_RESTARTABLE)
    esp_mbedtls_ecp_restart_free(&ctx->rs);
#endif
}

#if defined(MBEDTLS_ECP_RESTARTABLE)
/*
 * Enable restartable operations for context
 */
void esp_mbedtls_ecdh_enable_restart(mbedtls_ecdh_context *ctx)
{
    ctx->restart_enabled = 1;
}
#endif

/*
 * Free context
 */
void esp_mbedtls_ecdh_free(mbedtls_ecdh_context *ctx)
{
    if (ctx == NULL) {
        return;
    }

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    esp_mbedtls_ecp_point_free(&ctx->Vi);
    esp_mbedtls_ecp_point_free(&ctx->Vf);
    esp_mbedtls_mpi_free(&ctx->_d);
    esp_ecdh_free_internal(ctx);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            mbedtls_everest_free(&ctx->ctx.everest_ecdh);
            break;
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            esp_ecdh_free_internal(&ctx->ctx.mbed_ecdh);
            break;
        default:
            break;
    }

    ctx->point_format = MBEDTLS_ECP_PF_UNCOMPRESSED;
    ctx->var = MBEDTLS_ECDH_VARIANT_NONE;
    ctx->grp_id = MBEDTLS_ECP_DP_NONE;
#endif
}

static int esp_ecdh_make_params_internal(mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen, int point_format,
                                     unsigned char *buf, size_t blen,
                                     int (*f_rng)(void *,
                                                  unsigned char *,
                                                  size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t grp_len, pt_len;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if (ctx->grp.pbits == 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (restart_enabled) {
        rs_ctx = &ctx->rs;
    }
#else
    (void) restart_enabled;
#endif


#if defined(MBEDTLS_ECP_RESTARTABLE)
    if ((ret = esp_ecdh_gen_public_restartable(&ctx->grp, &ctx->d, &ctx->Q,
                                           f_rng, p_rng, rs_ctx)) != 0) {
        return ret;
    }
#else
    if ((ret = esp_mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q,
                                       f_rng, p_rng)) != 0) {
        return ret;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    if ((ret = esp_mbedtls_ecp_tls_write_group(&ctx->grp, &grp_len, buf,
                                           blen)) != 0) {
        return ret;
    }

    buf += grp_len;
    blen -= grp_len;

    if ((ret = esp_mbedtls_ecp_tls_write_point(&ctx->grp, &ctx->Q, point_format,
                                           &pt_len, buf, blen)) != 0) {
        return ret;
    }

    *olen = grp_len + pt_len;
    return 0;
}

/*
 * Setup and write the ServerKeyExchange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int esp_mbedtls_ecdh_make_params(mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int restart_enabled = 0;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#else
    (void) restart_enabled;
#endif

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return esp_ecdh_make_params_internal(ctx, olen, ctx->point_format, buf, blen,
                                     f_rng, p_rng, restart_enabled);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return mbedtls_everest_make_params(&ctx->ctx.everest_ecdh, olen,
                                               buf, blen, f_rng, p_rng);
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return esp_ecdh_make_params_internal(&ctx->ctx.mbed_ecdh, olen,
                                             ctx->point_format, buf, blen,
                                             f_rng, p_rng,
                                             restart_enabled);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int esp_ecdh_read_params_internal(mbedtls_ecdh_context_mbed *ctx,
                                     const unsigned char **buf,
                                     const unsigned char *end)
{
    return esp_mbedtls_ecp_tls_read_point(&ctx->grp, &ctx->Qp, buf,
                                      (size_t) (end - *buf));
}

/*
 * Read the ServerKeyExchange parameters (RFC 4492)
 *      struct {
 *          ECParameters    curve_params;
 *          ECPoint         public;
 *      } ServerECDHParams;
 */
int esp_mbedtls_ecdh_read_params(mbedtls_ecdh_context *ctx,
                             const unsigned char **buf,
                             const unsigned char *end)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_ecp_group_id grp_id;
    if ((ret = esp_mbedtls_ecp_tls_read_group_id(&grp_id, buf, (size_t) (end - *buf)))
        != 0) {
        return ret;
    }

    if ((ret = esp_mbedtls_ecdh_setup(ctx, grp_id)) != 0) {
        return ret;
    }

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return esp_ecdh_read_params_internal(ctx, buf, end);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return mbedtls_everest_read_params(&ctx->ctx.everest_ecdh,
                                               buf, end);
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return esp_ecdh_read_params_internal(&ctx->ctx.mbed_ecdh,
                                             buf, end);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int esp_ecdh_get_params_internal(mbedtls_ecdh_context_mbed *ctx,
                                    const mbedtls_ecp_keypair *key,
                                    mbedtls_ecdh_side side)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    /* If it's not our key, just import the public part as Qp */
    if (side == MBEDTLS_ECDH_THEIRS) {
        return esp_mbedtls_ecp_copy(&ctx->Qp, &key->Q);
    }

    /* Our key: import public (as Q) and private parts */
    if (side != MBEDTLS_ECDH_OURS) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if ((ret = esp_mbedtls_ecp_copy(&ctx->Q, &key->Q)) != 0 ||
        (ret = esp_mbedtls_mpi_copy(&ctx->d, &key->d)) != 0) {
        return ret;
    }

    return 0;
}

/*
 * Get parameters from a keypair
 */
int esp_mbedtls_ecdh_get_params(mbedtls_ecdh_context *ctx,
                            const mbedtls_ecp_keypair *key,
                            mbedtls_ecdh_side side)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    if (side != MBEDTLS_ECDH_OURS && side != MBEDTLS_ECDH_THEIRS) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (esp_mbedtls_ecdh_grp_id(ctx) == MBEDTLS_ECP_DP_NONE) {
        /* This is the first call to get_params(). Set up the context
         * for use with the group. */
        if ((ret = esp_mbedtls_ecdh_setup(ctx, key->grp.id)) != 0) {
            return ret;
        }
    } else {
        /* This is not the first call to get_params(). Check that the
         * current key's group is the same as the context's, which was set
         * from the first key's group. */
        if (esp_mbedtls_ecdh_grp_id(ctx) != key->grp.id) {
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
        }
    }

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return esp_ecdh_get_params_internal(ctx, key, side);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
        {
            mbedtls_everest_ecdh_side s = side == MBEDTLS_ECDH_OURS ?
                                          MBEDTLS_EVEREST_ECDH_OURS :
                                          MBEDTLS_EVEREST_ECDH_THEIRS;
            return mbedtls_everest_get_params(&ctx->ctx.everest_ecdh,
                                              key, s);
        }
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return esp_ecdh_get_params_internal(&ctx->ctx.mbed_ecdh,
                                            key, side);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int esp_ecdh_make_public_internal(mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen, int point_format,
                                     unsigned char *buf, size_t blen,
                                     int (*f_rng)(void *,
                                                  unsigned char *,
                                                  size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if (ctx->grp.pbits == 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (restart_enabled) {
        rs_ctx = &ctx->rs;
    }
#else
    (void) restart_enabled;
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if ((ret = esp_ecdh_gen_public_restartable(&ctx->grp, &ctx->d, &ctx->Q,
                                           f_rng, p_rng, rs_ctx)) != 0) {
        return ret;
    }
#else
    if ((ret = esp_mbedtls_ecdh_gen_public(&ctx->grp, &ctx->d, &ctx->Q,
                                       f_rng, p_rng)) != 0) {
        return ret;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    return esp_mbedtls_ecp_tls_write_point(&ctx->grp, &ctx->Q, point_format, olen,
                                       buf, blen);
}

/*
 * Setup and export the client public value
 */
int esp_mbedtls_ecdh_make_public(mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int restart_enabled = 0;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#endif

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return esp_ecdh_make_public_internal(ctx, olen, ctx->point_format, buf, blen,
                                     f_rng, p_rng, restart_enabled);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return mbedtls_everest_make_public(&ctx->ctx.everest_ecdh, olen,
                                               buf, blen, f_rng, p_rng);
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return esp_ecdh_make_public_internal(&ctx->ctx.mbed_ecdh, olen,
                                             ctx->point_format, buf, blen,
                                             f_rng, p_rng,
                                             restart_enabled);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int esp_ecdh_read_public_internal(mbedtls_ecdh_context_mbed *ctx,
                                     const unsigned char *buf, size_t blen)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const unsigned char *p = buf;

    if ((ret = esp_mbedtls_ecp_tls_read_point(&ctx->grp, &ctx->Qp, &p,
                                          blen)) != 0) {
        return ret;
    }

    if ((size_t) (p - buf) != blen) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    return 0;
}

/*
 * Parse and import the client's public value
 */
int esp_mbedtls_ecdh_read_public(mbedtls_ecdh_context *ctx,
                             const unsigned char *buf, size_t blen)
{
#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return esp_ecdh_read_public_internal(ctx, buf, blen);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return mbedtls_everest_read_public(&ctx->ctx.everest_ecdh,
                                               buf, blen);
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return esp_ecdh_read_public_internal(&ctx->ctx.mbed_ecdh,
                                             buf, blen);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}

static int esp_ecdh_calc_secret_internal(mbedtls_ecdh_context_mbed *ctx,
                                     size_t *olen, unsigned char *buf,
                                     size_t blen,
                                     int (*f_rng)(void *,
                                                  unsigned char *,
                                                  size_t),
                                     void *p_rng,
                                     int restart_enabled)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    mbedtls_ecp_restart_ctx *rs_ctx = NULL;
#endif

    if (ctx == NULL || ctx->grp.pbits == 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if (restart_enabled) {
        rs_ctx = &ctx->rs;
    }
#else
    (void) restart_enabled;
#endif

#if defined(MBEDTLS_ECP_RESTARTABLE)
    if ((ret = esp_ecdh_compute_shared_restartable(&ctx->grp, &ctx->z, &ctx->Qp,
                                               &ctx->d, f_rng, p_rng,
                                               rs_ctx)) != 0) {
        return ret;
    }
#else
    if ((ret = esp_mbedtls_ecdh_compute_shared(&ctx->grp, &ctx->z, &ctx->Qp,
                                           &ctx->d, f_rng, p_rng)) != 0) {
        return ret;
    }
#endif /* MBEDTLS_ECP_RESTARTABLE */

    if (esp_mbedtls_mpi_size(&ctx->z) > blen) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    *olen = ctx->grp.pbits / 8 + ((ctx->grp.pbits % 8) != 0);

    if (esp_mbedtls_ecp_get_type(&ctx->grp) == MBEDTLS_ECP_TYPE_MONTGOMERY) {
        return esp_mbedtls_mpi_write_binary_le(&ctx->z, buf, *olen);
    }

    return esp_mbedtls_mpi_write_binary(&ctx->z, buf, *olen);
}

/*
 * Derive and export the shared secret
 */
int esp_mbedtls_ecdh_calc_secret(mbedtls_ecdh_context *ctx, size_t *olen,
                             unsigned char *buf, size_t blen,
                             int (*f_rng)(void *, unsigned char *, size_t),
                             void *p_rng)
{
    int restart_enabled = 0;
#if defined(MBEDTLS_ECP_RESTARTABLE)
    restart_enabled = ctx->restart_enabled;
#endif

#if defined(MBEDTLS_ECDH_LEGACY_CONTEXT)
    return esp_ecdh_calc_secret_internal(ctx, olen, buf, blen, f_rng, p_rng,
                                     restart_enabled);
#else
    switch (ctx->var) {
#if defined(MBEDTLS_ECDH_VARIANT_EVEREST_ENABLED)
        case MBEDTLS_ECDH_VARIANT_EVEREST:
            return mbedtls_everest_calc_secret(&ctx->ctx.everest_ecdh, olen,
                                               buf, blen, f_rng, p_rng);
#endif
        case MBEDTLS_ECDH_VARIANT_MBEDTLS_2_0:
            return esp_ecdh_calc_secret_internal(&ctx->ctx.mbed_ecdh, olen, buf,
                                             blen, f_rng, p_rng,
                                             restart_enabled);
        default:
            return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
#endif
}
#endif /* MBEDTLS_ECDH_C */
