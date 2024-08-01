/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

/* The following symbols are also defined in NuttX serial interface */

#define uart_dev_s      hal_uart_dev_s
#define uart_dev_t      hal_uart_dev_t

/* Now include the header from esp-hal-3rdparty */

#include_next "hal/uart_hal.h"

#undef uart_dev_s
#undef uart_dev_t
