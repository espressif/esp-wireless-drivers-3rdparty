/*
 *  Classic "Hello, world" demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if defined(MBEDTLS_MD5_C)
#include "mbedtls/md5.h"
#endif

#if !defined(MBEDTLS_MD5_C)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_MD5_C not defined.\n");
    esp_mbedtls_exit(0);
}
#else


int main(void)
{
    int i, ret;
    unsigned char digest[16];
    char str[] = "Hello, world!";

    esp_mbedtls_printf("\n  MD5('%s') = ", str);

    if ((ret = esp_mbedtls_md5((unsigned char *) str, 13, digest)) != 0) {
        esp_mbedtls_exit(MBEDTLS_EXIT_FAILURE);
    }

    for (i = 0; i < 16; i++) {
        esp_mbedtls_printf("%02x", digest[i]);
    }

    esp_mbedtls_printf("\n\n");

    esp_mbedtls_exit(MBEDTLS_EXIT_SUCCESS);
}
#endif /* MBEDTLS_MD5_C */
