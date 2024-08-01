/*
 *  Diffie-Hellman-Merkle key exchange (client side)
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"
/* md.h is included this early since MD_CAN_XXX macros are defined there. */
#include "mbedtls/md.h"

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_DHM_C) && \
    defined(MBEDTLS_ENTROPY_C) && defined(MBEDTLS_NET_C) && \
    defined(MBEDTLS_RSA_C) && defined(MBEDTLS_SHA256_C) && \
    defined(MBEDTLS_FS_IO) && defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/net_sockets.h"
#include "mbedtls/aes.h"
#include "mbedtls/dhm.h"
#include "mbedtls/rsa.h"
#include "mbedtls/sha256.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <stdio.h>
#include <string.h>
#endif

#define SERVER_NAME "localhost"
#define SERVER_PORT "11999"

#if !defined(MBEDTLS_AES_C) || !defined(MBEDTLS_DHM_C) ||     \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_NET_C) ||  \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_SHA256_C) ||    \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_CTR_DRBG_C)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_AES_C and/or MBEDTLS_DHM_C and/or MBEDTLS_ENTROPY_C "
                   "and/or MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
                   "MBEDTLS_MD_CAN_SHA256 and/or MBEDTLS_FS_IO and/or "
                   "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_SHA1_C not defined.\n");
    esp_mbedtls_exit(0);
}

#elif defined(MBEDTLS_BLOCK_CIPHER_NO_DECRYPT)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_BLOCK_CIPHER_NO_DECRYPT defined.\n");
    esp_mbedtls_exit(0);
}
#else


int main(void)
{
    FILE *f;

    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    unsigned int mdlen;
    size_t n, buflen;
    mbedtls_net_context server_fd;

    unsigned char *p, *end;
    unsigned char buf[2048];
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    mbedtls_mpi N, E;
    const char *pers = "dh_client";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_rsa_context rsa;
    mbedtls_dhm_context dhm;
    mbedtls_aes_context aes;

    esp_mbedtls_net_init(&server_fd);
    esp_mbedtls_dhm_init(&dhm);
    esp_mbedtls_aes_init(&aes);
    esp_mbedtls_ctr_drbg_init(&ctr_drbg);
    esp_mbedtls_mpi_init(&N);
    esp_mbedtls_mpi_init(&E);

    /*
     * 1. Setup the RNG
     */
    esp_mbedtls_printf("\n  . Seeding the random number generator");
    fflush(stdout);

    esp_mbedtls_entropy_init(&entropy);
    if ((ret = esp_mbedtls_ctr_drbg_seed(&ctr_drbg, esp_mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    /*
     * 2. Read the server's public RSA key
     */
    esp_mbedtls_printf("\n  . Reading public key from rsa_pub.txt");
    fflush(stdout);

    if ((f = fopen("rsa_pub.txt", "rb")) == NULL) {
        esp_mbedtls_printf(" failed\n  ! Could not open rsa_pub.txt\n" \
                       "  ! Please run rsa_genkey first\n\n");
        goto exit;
    }

    esp_mbedtls_rsa_init(&rsa);
    if ((ret = esp_mbedtls_mpi_read_file(&N, 16, f)) != 0 ||
        (ret = esp_mbedtls_mpi_read_file(&E, 16, f)) != 0 ||
        (ret = esp_mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E) != 0)) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_mpi_read_file returned %d\n\n", ret);
        fclose(f);
        goto exit;
    }
    fclose(f);

    /*
     * 3. Initiate the connection
     */
    esp_mbedtls_printf("\n  . Connecting to tcp/%s/%s", SERVER_NAME,
                   SERVER_PORT);
    fflush(stdout);

    if ((ret = esp_mbedtls_net_connect(&server_fd, SERVER_NAME,
                                   SERVER_PORT, MBEDTLS_NET_PROTO_TCP)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    /*
     * 4a. First get the buffer length
     */
    esp_mbedtls_printf("\n  . Receiving the server's DH parameters");
    fflush(stdout);

    memset(buf, 0, sizeof(buf));

    if ((ret = esp_mbedtls_net_recv(&server_fd, buf, 2)) != 2) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_net_recv returned %d\n\n", ret);
        goto exit;
    }

    n = buflen = (buf[0] << 8) | buf[1];
    if (buflen < 1 || buflen > sizeof(buf)) {
        esp_mbedtls_printf(" failed\n  ! Got an invalid buffer length\n\n");
        goto exit;
    }

    /*
     * 4b. Get the DHM parameters: P, G and Ys = G^Xs mod P
     */
    memset(buf, 0, sizeof(buf));

    if ((ret = esp_mbedtls_net_recv(&server_fd, buf, n)) != (int) n) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_net_recv returned %d\n\n", ret);
        goto exit;
    }

    p = buf, end = buf + buflen;

    if ((ret = esp_mbedtls_dhm_read_params(&dhm, &p, end)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_dhm_read_params returned %d\n\n", ret);
        goto exit;
    }

    n = esp_mbedtls_dhm_get_len(&dhm);
    if (n < 64 || n > 512) {
        esp_mbedtls_printf(" failed\n  ! Invalid DHM modulus size\n\n");
        goto exit;
    }

    /*
     * 5. Check that the server's RSA signature matches
     *    the SHA-256 hash of (P,G,Ys)
     */
    esp_mbedtls_printf("\n  . Verifying the server's RSA signature");
    fflush(stdout);

    p += 2;

    if ((n = (size_t) (end - p)) != esp_mbedtls_rsa_get_len(&rsa)) {
        esp_mbedtls_printf(" failed\n  ! Invalid RSA signature size\n\n");
        goto exit;
    }

    mdlen = (unsigned int) esp_mbedtls_md_get_size(esp_mbedtls_md_info_from_type(MBEDTLS_MD_SHA256));
    if (mdlen == 0) {
        esp_mbedtls_printf(" failed\n  ! Invalid digest type\n\n");
        goto exit;
    }

    if ((ret = esp_mbedtls_sha256(buf, (int) (p - 2 - buf), hash, 0)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_sha256 returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = esp_mbedtls_rsa_pkcs1_verify(&rsa, MBEDTLS_MD_SHA256,
                                        mdlen, hash, p)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_rsa_pkcs1_verify returned %d\n\n", ret);
        goto exit;
    }

    /*
     * 6. Send our public value: Yc = G ^ Xc mod P
     */
    esp_mbedtls_printf("\n  . Sending own public value to server");
    fflush(stdout);

    n = esp_mbedtls_dhm_get_len(&dhm);
    if ((ret = esp_mbedtls_dhm_make_public(&dhm, (int) n, buf, n,
                                       esp_mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_dhm_make_public returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = esp_mbedtls_net_send(&server_fd, buf, n)) != (int) n) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_net_send returned %d\n\n", ret);
        goto exit;
    }

    /*
     * 7. Derive the shared secret: esp_K = Ys ^ Xc mod P
     */
    esp_mbedtls_printf("\n  . Shared secret: ");
    fflush(stdout);

    if ((ret = esp_mbedtls_dhm_calc_secret(&dhm, buf, sizeof(buf), &n,
                                       esp_mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_dhm_calc_secret returned %d\n\n", ret);
        goto exit;
    }

    for (n = 0; n < 16; n++) {
        esp_mbedtls_printf("%02x", buf[n]);
    }

    /*
     * 8. Setup the AES-256 decryption key
     *
     * This is an overly simplified example; best practice is
     * to hash the shared secret with a random value to derive
     * the keying material for the encryption/decryption keys,
     * IVs and MACs.
     */
    esp_mbedtls_printf("...\n  . Receiving and decrypting the ciphertext");
    fflush(stdout);

    ret = esp_mbedtls_aes_setkey_dec(&aes, buf, 256);
    if (ret != 0) {
        goto exit;
    }

    memset(buf, 0, sizeof(buf));

    if ((ret = esp_mbedtls_net_recv(&server_fd, buf, 16)) != 16) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_net_recv returned %d\n\n", ret);
        goto exit;
    }

    ret = esp_mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, buf, buf);
    if (ret != 0) {
        goto exit;
    }
    buf[16] = '\0';
    esp_mbedtls_printf("\n  . Plaintext is \"%s\"\n\n", (char *) buf);

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

    esp_mbedtls_net_free(&server_fd);

    esp_mbedtls_aes_free(&aes);
    esp_mbedtls_rsa_free(&rsa);
    esp_mbedtls_dhm_free(&dhm);
    esp_mbedtls_ctr_drbg_free(&ctr_drbg);
    esp_mbedtls_entropy_free(&entropy);
    esp_mbedtls_mpi_free(&N);
    esp_mbedtls_mpi_free(&E);

    esp_mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_AES_C && MBEDTLS_DHM_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_NET_C && MBEDTLS_RSA_C && MBEDTLS_MD_CAN_SHA256 &&
          MBEDTLS_FS_IO && MBEDTLS_CTR_DRBG_C */
