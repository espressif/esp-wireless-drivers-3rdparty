/*
 *  SSL server demonstration program using pthread for handling multiple
 *  clients.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if !defined(MBEDTLS_BIGNUM_C)  || !defined(MBEDTLS_ENTROPY_C) ||         \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_SRV_C) ||         \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_RSA_C) ||                 \
    !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_X509_CRT_PARSE_C) || \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_THREADING_C) ||           \
    !defined(MBEDTLS_THREADING_PTHREAD) || !defined(MBEDTLS_PEM_PARSE_C)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C "
                   "and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
                   "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
                   "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C and/or "
                   "MBEDTLS_THREADING_C and/or MBEDTLS_THREADING_PTHREAD "
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
#include "test/certs.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif


#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>Mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

#define MAX_NUM_THREADS 5

mbedtls_threading_mutex_t debug_mutex;

static void my_mutexed_debug(void *ctx, int level,
                             const char *file, int line,
                             const char *str)
{
    long int thread_id = (long int) pthread_self();

    esp_mbedtls_mutex_lock(&debug_mutex);

    ((void) level);
    esp_mbedtls_fprintf((FILE *) ctx, "%s:%04d: [ #%ld ] %s",
                    file, line, thread_id, str);
    fflush((FILE *) ctx);

    esp_mbedtls_mutex_unlock(&debug_mutex);
}

typedef struct {
    mbedtls_net_context client_fd;
    int thread_complete;
    const mbedtls_ssl_config *config;
} thread_info_t;

typedef struct {
    int active;
    thread_info_t   data;
    pthread_t       thread;
} pthread_info_t;

static thread_info_t    base_info;
static pthread_info_t   threads[MAX_NUM_THREADS];

static void *handle_ssl_connection(void *data)
{
    int ret, len;
    thread_info_t *thread_info = (thread_info_t *) data;
    mbedtls_net_context *client_fd = &thread_info->client_fd;
    long int thread_id = (long int) pthread_self();
    unsigned char buf[1024];
    mbedtls_ssl_context ssl;

    /* Make sure memory references are valid */
    esp_mbedtls_ssl_init(&ssl);

    esp_mbedtls_printf("  [ #%ld ]  Setting up SSL/TLS data\n", thread_id);

    /*
     * 4. Get the SSL context ready
     */
    if ((ret = esp_mbedtls_ssl_setup(&ssl, thread_info->config)) != 0) {
        esp_mbedtls_printf("  [ #%ld ]  failed: esp_mbedtls_ssl_setup returned -0x%04x\n",
                       thread_id, (unsigned int) -ret);
        goto thread_exit;
    }

    esp_mbedtls_ssl_set_bio(&ssl, client_fd, esp_mbedtls_net_send, esp_mbedtls_net_recv, NULL);

    /*
     * 5. Handshake
     */
    esp_mbedtls_printf("  [ #%ld ]  Performing the SSL/TLS handshake\n", thread_id);

    while ((ret = esp_mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            esp_mbedtls_printf("  [ #%ld ]  failed: esp_mbedtls_ssl_handshake returned -0x%04x\n",
                           thread_id, (unsigned int) -ret);
            goto thread_exit;
        }
    }

    esp_mbedtls_printf("  [ #%ld ]  ok\n", thread_id);

    /*
     * 6. Read the HTTP Request
     */
    esp_mbedtls_printf("  [ #%ld ]  < Read from client\n", thread_id);

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
                    esp_mbedtls_printf("  [ #%ld ]  connection was closed gracefully\n",
                                   thread_id);
                    goto thread_exit;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    esp_mbedtls_printf("  [ #%ld ]  connection was reset by peer\n",
                                   thread_id);
                    goto thread_exit;

                default:
                    esp_mbedtls_printf("  [ #%ld ]  esp_mbedtls_ssl_read returned -0x%04x\n",
                                   thread_id, (unsigned int) -ret);
                    goto thread_exit;
            }
        }

        len = ret;
        esp_mbedtls_printf("  [ #%ld ]  %d bytes read\n=====\n%s\n=====\n",
                       thread_id, len, (char *) buf);

        if (ret > 0) {
            break;
        }
    } while (1);

    /*
     * 7. Write the 200 Response
     */
    esp_mbedtls_printf("  [ #%ld ]  > Write to client:\n", thread_id);

    len = sprintf((char *) buf, HTTP_RESPONSE,
                  esp_mbedtls_ssl_get_ciphersuite(&ssl));

    while ((ret = esp_mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            esp_mbedtls_printf("  [ #%ld ]  failed: peer closed the connection\n",
                           thread_id);
            goto thread_exit;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            esp_mbedtls_printf("  [ #%ld ]  failed: esp_mbedtls_ssl_write returned -0x%04x\n",
                           thread_id, (unsigned int) ret);
            goto thread_exit;
        }
    }

    len = ret;
    esp_mbedtls_printf("  [ #%ld ]  %d bytes written\n=====\n%s\n=====\n",
                   thread_id, len, (char *) buf);

    esp_mbedtls_printf("  [ #%ld ]  . Closing the connection...", thread_id);

    while ((ret = esp_mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            esp_mbedtls_printf("  [ #%ld ]  failed: esp_mbedtls_ssl_close_notify returned -0x%04x\n",
                           thread_id, (unsigned int) ret);
            goto thread_exit;
        }
    }

    esp_mbedtls_printf(" ok\n");

    ret = 0;

thread_exit:

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        esp_mbedtls_strerror(ret, error_buf, 100);
        esp_mbedtls_printf("  [ #%ld ]  Last error was: -0x%04x - %s\n\n",
                       thread_id, (unsigned int) -ret, error_buf);
    }
#endif

    esp_mbedtls_net_free(client_fd);
    esp_mbedtls_ssl_free(&ssl);

    thread_info->thread_complete = 1;

    return NULL;
}

static int thread_create(mbedtls_net_context *client_fd)
{
    int ret, i;

    /*
     * Find in-active or finished thread slot
     */
    for (i = 0; i < MAX_NUM_THREADS; i++) {
        if (threads[i].active == 0) {
            break;
        }

        if (threads[i].data.thread_complete == 1) {
            esp_mbedtls_printf("  [ main ]  Cleaning up thread %d\n", i);
            pthread_join(threads[i].thread, NULL);
            memset(&threads[i], 0, sizeof(pthread_info_t));
            break;
        }
    }

    if (i == MAX_NUM_THREADS) {
        return -1;
    }

    /*
     * Fill thread-info for thread
     */
    memcpy(&threads[i].data, &base_info, sizeof(base_info));
    threads[i].active = 1;
    memcpy(&threads[i].data.client_fd, client_fd, sizeof(mbedtls_net_context));

    if ((ret = pthread_create(&threads[i].thread, NULL, handle_ssl_connection,
                              &threads[i].data)) != 0) {
        return ret;
    }

    return 0;
}

int main(void)
{
    int ret;
    mbedtls_net_context listen_fd, client_fd;
    const char pers[] = "ssl_pthread_server";

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cachain;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[100000];
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    esp_mbedtls_memory_buffer_alloc_init(alloc_buf, sizeof(alloc_buf));
#endif

#if defined(MBEDTLS_SSL_CACHE_C)
    esp_mbedtls_ssl_cache_init(&cache);
#endif

    esp_mbedtls_x509_crt_init(&srvcert);
    esp_mbedtls_x509_crt_init(&cachain);

    esp_mbedtls_ssl_config_init(&conf);
    esp_mbedtls_ctr_drbg_init(&ctr_drbg);
    memset(threads, 0, sizeof(threads));
    esp_mbedtls_net_init(&listen_fd);
    esp_mbedtls_net_init(&client_fd);

    esp_mbedtls_mutex_init(&debug_mutex);

    base_info.config = &conf;

    /*
     * We use only a single entropy source that is used in all the threads.
     */
    esp_mbedtls_entropy_init(&entropy);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = esp_psa_crypto_init();
    if (status != PSA_SUCCESS) {
        esp_mbedtls_fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n",
                        (int) status);
        ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    /*
     * 1a. Seed the random number generator
     */
    esp_mbedtls_printf("  . Seeding the random number generator...");

    if ((ret = esp_mbedtls_ctr_drbg_seed(&ctr_drbg, esp_mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        esp_mbedtls_printf(" failed: esp_mbedtls_ctr_drbg_seed returned -0x%04x\n",
                       (unsigned int) -ret);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n");

    /*
     * 1b. Load the certificates and private RSA key
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

    ret = esp_mbedtls_x509_crt_parse(&cachain, (const unsigned char *) mbedtls_test_cas_pem,
                                 mbedtls_test_cas_pem_len);
    if (ret != 0) {
        esp_mbedtls_printf(" failed\n  !  esp_mbedtls_x509_crt_parse returned %d\n\n", ret);
        goto exit;
    }

    esp_mbedtls_pk_init(&pkey);
    ret =  esp_mbedtls_pk_parse_key(&pkey, (const unsigned char *) mbedtls_test_srv_key,
                                mbedtls_test_srv_key_len, NULL, 0,
                                esp_mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        esp_mbedtls_printf(" failed\n  !  esp_mbedtls_pk_parse_key returned %d\n\n", ret);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n");

    /*
     * 1c. Prepare SSL configuration
     */
    esp_mbedtls_printf("  . Setting up the SSL data....");

    if ((ret = esp_mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        esp_mbedtls_printf(" failed: esp_mbedtls_ssl_config_defaults returned -0x%04x\n",
                       (unsigned int) -ret);
        goto exit;
    }

    esp_mbedtls_ssl_conf_rng(&conf, esp_mbedtls_ctr_drbg_random, &ctr_drbg);
    esp_mbedtls_ssl_conf_dbg(&conf, my_mutexed_debug, stdout);

    /* esp_mbedtls_ssl_cache_get() and esp_mbedtls_ssl_cache_set() are thread-safe if
     * MBEDTLS_THREADING_C is set.
     */
#if defined(MBEDTLS_SSL_CACHE_C)
    esp_mbedtls_ssl_conf_session_cache(&conf, &cache,
                                   esp_mbedtls_ssl_cache_get,
                                   esp_mbedtls_ssl_cache_set);
#endif

    esp_mbedtls_ssl_conf_ca_chain(&conf, &cachain, NULL);
    if ((ret = esp_mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n");

    /*
     * 2. Setup the listening TCP socket
     */
    esp_mbedtls_printf("  . Bind on https://localhost:4433/ ...");
    fflush(stdout);

    if ((ret = esp_mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP)) != 0) {
        esp_mbedtls_printf(" failed\n  ! esp_mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    esp_mbedtls_printf(" ok\n");

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        esp_mbedtls_strerror(ret, error_buf, 100);
        esp_mbedtls_printf("  [ main ]  Last error was: -0x%04x - %s\n", (unsigned int) -ret,
                       error_buf);
    }
#endif

    /*
     * 3. Wait until a client connects
     */
    esp_mbedtls_printf("  [ main ]  Waiting for a remote connection\n");

    if ((ret = esp_mbedtls_net_accept(&listen_fd, &client_fd,
                                  NULL, 0, NULL)) != 0) {
        esp_mbedtls_printf("  [ main ] failed: esp_mbedtls_net_accept returned -0x%04x\n",
                       (unsigned int) ret);
        goto exit;
    }

    esp_mbedtls_printf("  [ main ]  ok\n");
    esp_mbedtls_printf("  [ main ]  Creating a new thread\n");

    if ((ret = thread_create(&client_fd)) != 0) {
        esp_mbedtls_printf("  [ main ]  failed: thread_create returned %d\n", ret);
        esp_mbedtls_net_free(&client_fd);
        goto reset;
    }

    ret = 0;
    goto reset;

exit:
    esp_mbedtls_x509_crt_free(&srvcert);
    esp_mbedtls_pk_free(&pkey);
#if defined(MBEDTLS_SSL_CACHE_C)
    esp_mbedtls_ssl_cache_free(&cache);
#endif
    esp_mbedtls_ctr_drbg_free(&ctr_drbg);
    esp_mbedtls_entropy_free(&entropy);
    esp_mbedtls_ssl_config_free(&conf);
    esp_mbedtls_net_free(&listen_fd);
    esp_mbedtls_mutex_free(&debug_mutex);
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    esp_mbedtls_memory_buffer_alloc_free();
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    esp_mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    esp_mbedtls_exit(ret);
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C &&
          MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
          MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_THREADING_C &&
          MBEDTLS_THREADING_PTHREAD && MBEDTLS_PEM_PARSE_C */
