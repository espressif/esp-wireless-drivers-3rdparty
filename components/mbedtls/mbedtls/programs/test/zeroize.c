/*
 * Zeroize application for debugger-driven testing
 *
 * This is a simple test application used for debugger-driven testing to check
 * whether calls to esp_mbedtls_platform_zeroize() are being eliminated by compiler
 * optimizations. This application is used by the GDB script at
 * tests/scripts/test_zeroize.gdb: the script sets a breakpoint at the last
 * return statement in the main() function of this program. The debugger
 * facilities are then used to manually inspect the memory and verify that the
 * call to esp_mbedtls_platform_zeroize() was not eliminated.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include <stdio.h>

#include "mbedtls/platform.h"

#include "mbedtls/platform_util.h"

#define BUFFER_LEN 1024

void usage(void)
{
    esp_mbedtls_printf("Zeroize is a simple program to assist with testing\n");
    esp_mbedtls_printf("the esp_mbedtls_platform_zeroize() function by using the\n");
    esp_mbedtls_printf("debugger. This program takes a file as input and\n");
    esp_mbedtls_printf("prints the first %d characters. Usage:\n\n", BUFFER_LEN);
    esp_mbedtls_printf("       zeroize <FILE>\n");
}

int main(int argc, char **argv)
{
    int exit_code = MBEDTLS_EXIT_FAILURE;
    FILE *fp;
    char buf[BUFFER_LEN];
    char *p = buf;
    char *end = p + BUFFER_LEN;
    int c;

    if (argc != 2) {
        esp_mbedtls_printf("This program takes exactly 1 argument\n");
        usage();
        esp_mbedtls_exit(exit_code);
    }

    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        esp_mbedtls_printf("Could not open file '%s'\n", argv[1]);
        esp_mbedtls_exit(exit_code);
    }

    while ((c = fgetc(fp)) != EOF && p < end - 1) {
        *p++ = (char) c;
    }
    *p = '\0';

    if (p - buf != 0) {
        esp_mbedtls_printf("%s\n", buf);
        exit_code = MBEDTLS_EXIT_SUCCESS;
    } else {
        esp_mbedtls_printf("The file is empty!\n");
    }

    fclose(fp);
    esp_mbedtls_platform_zeroize(buf, sizeof(buf));

    esp_mbedtls_exit(exit_code);   // GDB_BREAK_HERE -- don't remove this comment!
}
