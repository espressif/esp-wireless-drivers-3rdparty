/*
 * SPDX-FileCopyrightText: 2020-2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#include "esp_attr.h"
#include <stdint.h>
#include "hal/regi2c_ctrl.h"
#include "hal/regi2c_ctrl_ll.h"
#include "esp_hw_log.h"

#ifdef __NuttX__
#include <nuttx/spinlock.h>
#else
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#endif

#ifdef __NuttX__
#define ENTER_CRITICAL_SECTION(lock)    do { g_flags = spin_lock_irqsave(lock); } while(0)
#define LEAVE_CRITICAL_SECTION(lock)    spin_unlock_irqrestore((lock), g_flags)

static spinlock_t mux;
static irqstate_t g_flags;
#else
#define ENTER_CRITICAL_SECTION(lock)    portENTER_CRITICAL_SAFE(lock)
#define LEAVE_CRITICAL_SECTION(lock)    portEXIT_CRITICAL_SAFE(lock)

static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
#endif

static DRAM_ATTR __attribute__((unused)) const char *TAG = "REGI2C";

uint8_t IRAM_ATTR regi2c_ctrl_read_reg(uint8_t block, uint8_t host_id, uint8_t reg_add)
{
    ENTER_CRITICAL_SECTION(&mux);
    uint8_t value = regi2c_read_reg_raw(block, host_id, reg_add);
    LEAVE_CRITICAL_SECTION(&mux);
    return value;
}

uint8_t IRAM_ATTR regi2c_ctrl_read_reg_mask(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t msb, uint8_t lsb)
{
    ENTER_CRITICAL_SECTION(&mux);
    uint8_t value = regi2c_read_reg_mask_raw(block, host_id, reg_add, msb, lsb);
    LEAVE_CRITICAL_SECTION(&mux);
    return value;
}

void IRAM_ATTR regi2c_ctrl_write_reg(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t data)
{
    ENTER_CRITICAL_SECTION(&mux);
    regi2c_write_reg_raw(block, host_id, reg_add, data);
    LEAVE_CRITICAL_SECTION(&mux);
}

void IRAM_ATTR regi2c_ctrl_write_reg_mask(uint8_t block, uint8_t host_id, uint8_t reg_add, uint8_t msb, uint8_t lsb, uint8_t data)
{
    ENTER_CRITICAL_SECTION(&mux);
    regi2c_write_reg_mask_raw(block, host_id, reg_add, msb, lsb, data);
    LEAVE_CRITICAL_SECTION(&mux);
}

void IRAM_ATTR regi2c_enter_critical(void)
{
    ENTER_CRITICAL_SECTION(&mux);
}

void IRAM_ATTR regi2c_exit_critical(void)
{
    LEAVE_CRITICAL_SECTION(&mux);
}

/**
 * Restore regi2c analog calibration related configuration registers.
 * This is a workaround, and is fixed on later chips
 */
#if REGI2C_ANA_CALI_PD_WORKAROUND
#include "soc/regi2c_saradc.h"

static DRAM_ATTR uint8_t reg_val[REGI2C_ANA_CALI_BYTE_NUM];

void IRAM_ATTR regi2c_analog_cali_reg_read(void)
{
    for (int i = 0; i < REGI2C_ANA_CALI_BYTE_NUM; i++) {
        reg_val[i] = regi2c_ctrl_read_reg(I2C_SAR_ADC, I2C_SAR_ADC_HOSTID, i);
    }
}

void IRAM_ATTR regi2c_analog_cali_reg_write(void)
{
    for (int i = 0; i < REGI2C_ANA_CALI_BYTE_NUM; i++) {
        regi2c_ctrl_write_reg(I2C_SAR_ADC, I2C_SAR_ADC_HOSTID, i, reg_val[i]);
    }
}
#endif   //#if ADC_CALI_PD_WORKAROUND

/**
 * REGI2C_SARADC reference count
 */
static int s_i2c_saradc_enable_cnt;

void regi2c_saradc_enable(void)
{
    regi2c_enter_critical();
    s_i2c_saradc_enable_cnt++;
    if (s_i2c_saradc_enable_cnt == 1) {
        regi2c_ctrl_ll_i2c_saradc_enable();
    }
    regi2c_exit_critical();
}

void regi2c_saradc_disable(void)
{
    regi2c_enter_critical();
    s_i2c_saradc_enable_cnt--;
    if (s_i2c_saradc_enable_cnt < 0){
        regi2c_exit_critical();
        ESP_HW_LOGE(TAG, "REGI2C_SARADC is already disabled");
    } else if (s_i2c_saradc_enable_cnt == 0) {
        regi2c_ctrl_ll_i2c_saradc_disable();
    }
    regi2c_exit_critical();

}
