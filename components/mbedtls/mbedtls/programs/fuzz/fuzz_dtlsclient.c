#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "common.h"
#include "mbedtls/ssl.h"
#if defined(MBEDTLS_SSL_PROTO_DTLS)
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/timing.h"
#include "test/certs.h"

#if defined(MBEDTLS_SSL_CLI_C) && \
    defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C) && \
    defined(MBEDTLS_TIMING_C)
static int initialized = 0;
#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
static mbedtls_x509_crt cacert;
#endif

const char *pers = "fuzz_dtlsclient";
#endif
#endif // MBEDTLS_SSL_PROTO_DTLS



int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
#if defined(MBEDTLS_SSL_PROTO_DTLS) && \
    defined(MBEDTLS_SSL_CLI_C) && \
    defined(MBEDTLS_ENTROPY_C) && \
    defined(MBEDTLS_CTR_DRBG_C) && \
    defined(MBEDTLS_TIMING_C)
    int ret;
    size_t len;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_timing_delay_context timer;
    unsigned char buf[4096];
    fuzzBufferOffset_t biomemfuzz;

    if (initialized == 0) {
#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
        esp_mbedtls_x509_crt_init(&cacert);
        if (esp_mbedtls_x509_crt_parse(&cacert, (const unsigned char *) mbedtls_test_cas_pem,
                                   mbedtls_test_cas_pem_len) != 0) {
            return 1;
        }
#endif
        dummy_init();

        initialized = 1;
    }

    esp_mbedtls_ssl_init(&ssl);
    esp_mbedtls_ssl_config_init(&conf);
    esp_mbedtls_ctr_drbg_init(&ctr_drbg);
    esp_mbedtls_entropy_init(&entropy);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = esp_psa_crypto_init();
    if (status != PSA_SUCCESS) {
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    srand(1);
    if (esp_mbedtls_ctr_drbg_seed(&ctr_drbg, dummy_entropy, &entropy,
                              (const unsigned char *) pers, strlen(pers)) != 0) {
        goto exit;
    }

    if (esp_mbedtls_ssl_config_defaults(&conf,
                                    MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
        goto exit;
    }

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
    esp_mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
#endif
    esp_mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    esp_mbedtls_ssl_conf_rng(&conf, dummy_random, &ctr_drbg);

    if (esp_mbedtls_ssl_setup(&ssl, &conf) != 0) {
        goto exit;
    }

    esp_mbedtls_ssl_set_timer_cb(&ssl, &timer, esp_mbedtls_timing_set_delay,
                             esp_mbedtls_timing_get_delay);

#if defined(MBEDTLS_X509_CRT_PARSE_C) && defined(MBEDTLS_PEM_PARSE_C)
    if (esp_mbedtls_ssl_set_hostname(&ssl, "localhost") != 0) {
        goto exit;
    }
#endif

    biomemfuzz.Data = Data;
    biomemfuzz.Size = Size;
    biomemfuzz.Offset = 0;
    esp_mbedtls_ssl_set_bio(&ssl, &biomemfuzz, dummy_send, fuzz_recv, fuzz_recv_timeout);

    ret = esp_mbedtls_ssl_handshake(&ssl);
    if (ret == 0) {
        //keep reading data from server until the end
        do {
            len = sizeof(buf) - 1;
            ret = esp_mbedtls_ssl_read(&ssl, buf, len);

            if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                continue;
            } else if (ret <= 0) {
                //EOF or error
                break;
            }
        } while (1);
    }

exit:
    esp_mbedtls_entropy_free(&entropy);
    esp_mbedtls_ctr_drbg_free(&ctr_drbg);
    esp_mbedtls_ssl_config_free(&conf);
    esp_mbedtls_ssl_free(&ssl);
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    esp_mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#else
    (void) Data;
    (void) Size;
#endif
    return 0;
}
