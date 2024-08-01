/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "esp_rom_uart.h"
#include "esp_rom_sys.h"

/****************************************************************************
 * Name: __wrap_bootloader_print_banner
 *
 * Description:
 *   Prints the bootloader banner.
 *   This implementation overrides the bootloader's print banner function
 *   from IDF.
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void __wrap_bootloader_print_banner(void)
{
    esp_rom_printf("*** Booting NuttX ***\n");
}
