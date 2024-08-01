/*
 * SPDX-FileCopyrightText: 2015-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "hal/clk_gate_ll.h"
#include "esp_attr.h"
#include "esp_private/periph_ctrl.h"
#include "soc/soc_caps.h"

#if SOC_MODEM_CLOCK_IS_INDEPENDENT
#include "esp_private/esp_modem_clock.h"
#endif

#ifdef __NuttX__
#include <nuttx/spinlock.h>
#else
#include "freertos/FreeRTOS.h"
#endif

#ifdef __NuttX__
#define ENTER_CRITICAL_SECTION(lock)    do { g_flags = spin_lock_irqsave(lock); } while(0)
#define LEAVE_CRITICAL_SECTION(lock)    spin_unlock_irqrestore((lock), g_flags)

static spinlock_t periph_spinlock;
static irqstate_t g_flags;
#else
#define ENTER_CRITICAL_SECTION(lock)    portENTER_CRITICAL_SAFE(lock)
#define LEAVE_CRITICAL_SECTION(lock)    portEXIT_CRITICAL_SAFE(lock)

static portMUX_TYPE periph_spinlock = portMUX_INITIALIZER_UNLOCKED;
#endif

static uint8_t ref_counts[PERIPH_MODULE_MAX] = {0};

void periph_module_enable(periph_module_t periph)
{
    assert(periph < PERIPH_MODULE_MAX);
    ENTER_CRITICAL_SECTION(&periph_spinlock);
    if (ref_counts[periph] == 0) {
        periph_ll_enable_clk_clear_rst(periph);
    }
    ref_counts[periph]++;
    LEAVE_CRITICAL_SECTION(&periph_spinlock);
}

void periph_module_disable(periph_module_t periph)
{
    assert(periph < PERIPH_MODULE_MAX);
    ENTER_CRITICAL_SECTION(&periph_spinlock);
    ref_counts[periph]--;
    if (ref_counts[periph] == 0) {
        periph_ll_disable_clk_set_rst(periph);
    }
    LEAVE_CRITICAL_SECTION(&periph_spinlock);
}

void periph_module_reset(periph_module_t periph)
{
    assert(periph < PERIPH_MODULE_MAX);
    ENTER_CRITICAL_SECTION(&periph_spinlock);
    periph_ll_reset(periph);
    LEAVE_CRITICAL_SECTION(&periph_spinlock);
}

#if !SOC_IEEE802154_BLE_ONLY
IRAM_ATTR void wifi_bt_common_module_enable(void)
{
#if SOC_MODEM_CLOCK_IS_INDEPENDENT
    modem_clock_module_enable(PERIPH_PHY_MODULE);
#else
    ENTER_CRITICAL_SECTION(&periph_spinlock);
    if (ref_counts[PERIPH_WIFI_BT_COMMON_MODULE] == 0) {
        periph_ll_wifi_bt_module_enable_clk();
    }
    ref_counts[PERIPH_WIFI_BT_COMMON_MODULE]++;
    LEAVE_CRITICAL_SECTION(&periph_spinlock);
#endif
}

IRAM_ATTR void wifi_bt_common_module_disable(void)
{
#if SOC_MODEM_CLOCK_IS_INDEPENDENT
    modem_clock_module_disable(PERIPH_PHY_MODULE);
#else
    ENTER_CRITICAL_SECTION(&periph_spinlock);
    ref_counts[PERIPH_WIFI_BT_COMMON_MODULE]--;
    if (ref_counts[PERIPH_WIFI_BT_COMMON_MODULE] == 0) {
        periph_ll_wifi_bt_module_disable_clk();
    }
    LEAVE_CRITICAL_SECTION(&periph_spinlock);
#endif
}
#endif

#if CONFIG_ESP_WIFI_ENABLED
void wifi_module_enable(void)
{
#if SOC_MODEM_CLOCK_IS_INDEPENDENT
    modem_clock_module_enable(PERIPH_WIFI_MODULE);
#else
    ENTER_CRITICAL_SECTION(&periph_spinlock);
    periph_ll_wifi_module_enable_clk_clear_rst();
    LEAVE_CRITICAL_SECTION(&periph_spinlock);
#endif
}

void wifi_module_disable(void)
{
#if SOC_MODEM_CLOCK_IS_INDEPENDENT
    modem_clock_module_disable(PERIPH_WIFI_MODULE);
#else
    ENTER_CRITICAL_SECTION(&periph_spinlock);
    periph_ll_wifi_module_disable_clk_set_rst();
    LEAVE_CRITICAL_SECTION(&periph_spinlock);
#endif
}
#endif // CONFIG_ESP_WIFI_ENABLED
