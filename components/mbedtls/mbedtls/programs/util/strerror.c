/*
 *  Translate error code to error string
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if defined(MBEDTLS_ERROR_C) || defined(MBEDTLS_ERROR_STRERROR_DUMMY)
#include "mbedtls/error.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#endif

#define USAGE \
    "\n usage: strerror <errorcode>\n" \
    "\n where <errorcode> can be a decimal or hexadecimal (starts with 0x or -0x)\n"

#if !defined(MBEDTLS_ERROR_C) && !defined(MBEDTLS_ERROR_STRERROR_DUMMY)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_ERROR_C and/or MBEDTLS_ERROR_STRERROR_DUMMY not defined.\n");
    esp_mbedtls_exit(0);
}
#else
int main(int argc, char *argv[])
{
    long int val;
    char *end = argv[1];

    if (argc != 2) {
        esp_mbedtls_printf(USAGE);
        esp_mbedtls_exit(0);
    }

    val = strtol(argv[1], &end, 10);
    if (*end != '\0') {
        val = strtol(argv[1], &end, 16);
        if (*end != '\0') {
            esp_mbedtls_printf(USAGE);
            return 0;
        }
    }
    if (val > 0) {
        val = -val;
    }

    if (val != 0) {
        char error_buf[200];
        esp_mbedtls_strerror(val, error_buf, 200);
        esp_mbedtls_printf("Last error was: -0x%04x - %s\n\n", (unsigned int) -val, error_buf);
    }

    esp_mbedtls_exit(val);
}
#endif /* MBEDTLS_ERROR_C */
