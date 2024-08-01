/*
 *  SSL server demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_PEM_PARSE_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_SSL_TLS_C) ||  \
    !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_NET_C) ||      \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_CTR_DRBG_C) ||     \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C "
                   "and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
                   "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
                   "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
                   "and/or MBEDTLS_PEM_PARSE_C not defined.\n");
    esp_mbedtls_exit(0);
}
#else

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "test/certs.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>Mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0


static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void) level);

    esp_mbedtls_fprintf((FILE *) ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *) ctx);
}

int main(void)
{
    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[1024];
    const char *pers = "ssl_server";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

    esp_mbedtls_net_init(&listen_fd);
    esp_mbedtls_net_init(&client_fd);
    esp_mbedtls_ssl_init(&ssl);
    esp_mbedtls_ssl_config_init(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    esp_mbedtls_ssl_cache_init(&cache);
#endif
    esp_mbedtls_x509_crt_init(&srvcert);
    esp_mbedtls_pk_init(&pkey);
    esp_mbedtls_entropy_init(&entropy);
    esp_mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = esp_psa_crypto_init();
    if (status != PSA_SUCCESS) {
        esp_mbedtls_fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n",
                        (int) status);
        ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_DEBUG_C)
    esp_mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 1. Seed the RNG
     */
    esp_mbedtls_printf("  . Seeding the random number generator...");
    fflush(stdout);

    if ((ret = esp_mbedtls_ctr_drbg_seed(&ctr_drbg, esp_mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n");

    /*
     * 2. Load the certificates and private RSA key
     */
    esp_mbedtls_printf("\n  . Loading the server cert. and key...");
    fflush(stdout);

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use esp_mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as esp_mbedtls_pk_parse_keyfile().
     */
    ret = esp_mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                                 mbedtls_test_srv_crt_len);
    if (ret != 0) {
        esp_mbedtls_printf(" failed\n  !  esp_mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret = esp_mbedtls_x509_crt_parse(&srvcert, (const unsigned char *) mbedtls_test_cas_pem,
                                 mbedtls_test_cas_pem_len);
    if (ret != 0) {
        esp_mbedtls_printf(" failed\n  !  esp_mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    ret =  esp_mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_test_srv_key,
                                mbedtls_test_srv_key_len, NULL, 0,
                                esp_mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        esp_mbedtls_printf(" failed\n  !  esp_mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n");

    /*
     * 3. Setup the listening TCP socket
     */
    esp_mbedtls_printf("  . Bind on https://localhost:4433/ ...");
    fflush(stdout);

    if ((ret = esp_mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n");

    /*
     * 4. Setup stuff
     */
    esp_mbedtls_printf("  . Setting up the SSL data....");
    fflush(stdout);

    if ((ret = esp_mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    esp_mbedtls_ssl_conf_rng(&conf, esp_mbedtls_ctr_drbg_random, &ctr_drbg);
    esp_mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

#if defined(MBEDTLS_SSL_CACHE_C)
    esp_mbedtls_ssl_conf_session_cache(&conf, &cache,
                                   esp_mbedtls_ssl_cache_get,
                                   esp_mbedtls_ssl_cache_set);
#endif

    esp_mbedtls_ssl_conf_ca_chain(&conf, srvcert.next, NULL);
    if ((ret = esp_mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = esp_mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n");

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        esp_mbedtls_strerror(ret, error_buf, 100);
        esp_mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    esp_mbedtls_net_free(&client_fd);

    esp_mbedtls_ssl_session_reset(&ssl);

    /*
     * 3. Wait until a client connects
     */
    esp_mbedtls_printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    if ((ret = esp_mbedtls_net_accept(&listen_fd, &client_fd,
                                  NULL, 0, NULL)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    esp_mbedtls_ssl_set_bio(&ssl, &client_fd, esp_mbedtls_net_send, esp_mbedtls_net_recv, NULL);

    esp_mbedtls_printf(" ok\n");

    /*
     * 5. Handshake
     */
    esp_mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = esp_mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    esp_mbedtls_printf(" ok\n");

    /*
     * 6. Read the HTTP Request
     */
    esp_mbedtls_printf("  < Read from client:");
    fflush(stdout);

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = esp_mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret <= 0) {
            switch (ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    esp_mbedtls_printf(" connection was closed gracefully\n");
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    esp_mbedtls_printf(" connection was reset by peer\n");
                    break;

                default:
                    esp_mbedtls_printf(" esp_mbedtls_ssl_read returned -0x%x\n", (unsigned int) -ret);
                    break;
            }

            break;
        }

        len = ret;
        esp_mbedtls_printf(" %d bytes read\n\n%s", len, (char *) buf);

        if (ret > 0) {
            break;
        }
    } while (1);

    /*
     * 7. Write the 200 Response
     */
    esp_mbedtls_printf("  > Write to client:");
    fflush(stdout);

    len = sprintf((char *) buf, HTTP_RESPONSE,
                  esp_mbedtls_ssl_get_ciphersuite(&ssl));

    while ((ret = esp_mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            esp_mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    esp_mbedtls_printf(" %d bytes written\n\n%s\n", len, (char *) buf);

    esp_mbedtls_printf("  . Closing the connection...");

    while ((ret = esp_mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset;
        }
    }

    esp_mbedtls_printf(" ok\n");

    ret = 0;
    goto reset;

exit:

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        esp_mbedtls_strerror(ret, error_buf, 100);
        esp_mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    esp_mbedtls_net_free(&client_fd);
    esp_mbedtls_net_free(&listen_fd);
    esp_mbedtls_x509_crt_free(&srvcert);
    esp_mbedtls_pk_free(&pkey);
    esp_mbedtls_ssl_free(&ssl);
    esp_mbedtls_ssl_config_free(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    esp_mbedtls_ssl_cache_free(&cache);
#endif
    esp_mbedtls_ctr_drbg_free(&ctr_drbg);
    esp_mbedtls_entropy_free(&entropy);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    esp_mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    esp_mbedtls_exit(ret);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
          MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C
          && MBEDTLS_FS_IO && MBEDTLS_PEM_PARSE_C */
