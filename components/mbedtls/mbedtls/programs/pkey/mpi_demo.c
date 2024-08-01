/*
 *  Simple MPI demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "mbedtls/build_info.h"

#include "mbedtls/platform.h"

#if defined(MBEDTLS_BIGNUM_C) && defined(MBEDTLS_FS_IO)
#include "mbedtls/bignum.h"

#include <stdio.h>
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_FS_IO)
int main(void)
{
    esp_mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_FS_IO not defined.\n");
    esp_mbedtls_exit(0);
}
#else


int main(void)
{
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_mpi E, P, Q, N, H, D, X, Y, Z;

    esp_mbedtls_mpi_init(&E); esp_mbedtls_mpi_init(&P); esp_mbedtls_mpi_init(&Q); esp_mbedtls_mpi_init(&N);
    esp_mbedtls_mpi_init(&H); esp_mbedtls_mpi_init(&D); esp_mbedtls_mpi_init(&X); esp_mbedtls_mpi_init(&Y);
    esp_mbedtls_mpi_init(&Z);

    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_read_string(&P, 10, "2789"));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_read_string(&Q, 10, "3203"));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_read_string(&E, 10,  "257"));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_mul_mpi(&N, &P, &Q));

    esp_mbedtls_printf("\n  Public key:\n\n");
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_write_file("  N = ", &N, 10, NULL));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_write_file("  E = ", &E, 10, NULL));

    esp_mbedtls_printf("\n  Private key:\n\n");
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_write_file("  P = ", &P, 10, NULL));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_write_file("  Q = ", &Q, 10, NULL));

#if defined(MBEDTLS_GENPRIME)
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_sub_int(&P, &P, 1));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_sub_int(&Q, &Q, 1));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_mul_mpi(&H, &P, &Q));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_inv_mod(&D, &E, &H));

    esp_mbedtls_mpi_write_file("  D = E^-1 mod (P-1)*(Q-1) = ",
                           &D, 10, NULL);
#else
    esp_mbedtls_printf("\nTest skipped (MBEDTLS_GENPRIME not defined).\n\n");
#endif
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_read_string(&X, 10, "55555"));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_exp_mod(&Y, &X, &E, &N, NULL));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_exp_mod(&Z, &Y, &D, &N, NULL));

    esp_mbedtls_printf("\n  RSA operation:\n\n");
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_write_file("  X (plaintext)  = ", &X, 10, NULL));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_write_file("  Y (ciphertext) = X^E mod N = ", &Y, 10, NULL));
    MBEDTLS_MPI_CHK(esp_mbedtls_mpi_write_file("  Z (decrypted)  = Y^D mod N = ", &Z, 10, NULL));
    esp_mbedtls_printf("\n");

    exit_code = MBEDTLS_EXIT_SUCCESS;

cleanup:
    esp_mbedtls_mpi_free(&E); esp_mbedtls_mpi_free(&P); esp_mbedtls_mpi_free(&Q); esp_mbedtls_mpi_free(&N);
    esp_mbedtls_mpi_free(&H); esp_mbedtls_mpi_free(&D); esp_mbedtls_mpi_free(&X); esp_mbedtls_mpi_free(&Y);
    esp_mbedtls_mpi_free(&Z);

    if (exit_code != MBEDTLS_EXIT_SUCCESS) {
        esp_mbedtls_printf("\nAn error occurred.\n");
    }

    esp_mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_FS_IO */
