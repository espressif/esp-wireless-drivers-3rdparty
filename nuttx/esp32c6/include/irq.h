/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <nuttx/config.h>

#define WIFI_MAC_INTR_SOURCE                0
#define WIFI_MAC_NMI_SOURCE                 1
#define WIFI_PWR_INTR_SOURCE                2
#define WIFI_BB_INTR_SOURCE                 3
#define BT_MAC_INTR_SOURCE                  4
#define BT_BB_INTR_SOURCE                   5
#define BT_BB_NMI_SOURCE                    6
#define LP_TIMER_INTR_SOURCE                7
#define COEX_INTR_SOURCE                    8
#define BLE_TIMER_INTR_SOURCE               9
#define BLE_SEC_INTR_SOURCE                 10
#define I2C_MASTER_INTR_SOURCE              11
#define ZB_MAC_INTR_SOURCE                  12
#define PMU_INTR_SOURCE                     13
#define EFUSE_INTR_SOURCE                   14
#define LP_RTC_TIMER_INTR_SOURCE            15
#define LP_UART_INTR_SOURCE                 16
#define LP_I2C_INTR_SOURCE                  17
#define LP_WDT_INTR_SOURCE                  18
#define LP_PERI_TIMEOUT_INTR_SOURCE         19
#define LP_APM_M0_INTR_SOURCE               20
#define LP_APM_M1_INTR_SOURCE               21
#define FROM_CPU_INTR0_SOURCE               22
#define FROM_CPU_INTR1_SOURCE               23
#define FROM_CPU_INTR2_SOURCE               24
#define FROM_CPU_INTR3_SOURCE               25
#define ASSIST_DEBUG_INTR_SOURCE            26
#define TRACE_INTR_SOURCE                   27
#define CACHE_INTR_SOURCE                   28
#define CPU_PERI_TIMEOUT_INTR_SOURCE        29
#define GPIO_INTR_SOURCE                    30
#define GPIO_NMI_SOURCE                     31
#define PAU_INTR_SOURCE                     32
#define HP_PERI_TIMEOUT_INTR_SOURCE         33
#define MODEM_PERI_TIMEOUT_INTR_SOURCE      34
#define HP_APM_M0_INTR_SOURCE               35
#define HP_APM_M1_INTR_SOURCE               36
#define HP_APM_M2_INTR_SOURCE               37
#define HP_APM_M3_INTR_SOURCE               38
#define LP_APM0_INTR_SOURCE                 39
#define MSPI_INTR_SOURCE                    40
#define I2S1_INTR_SOURCE                    41
#define UHCI0_INTR_SOURCE                   42
#define UART0_INTR_SOURCE                   43
#define UART1_INTR_SOURCE                   44
#define LEDC_INTR_SOURCE                    45
#define TWAI0_INTR_SOURCE                   46
#define TWAI1_INTR_SOURCE                   47
#define USB_SERIAL_JTAG_INTR_SOURCE         48
#define RMT_INTR_SOURCE                     49
#define I2C_EXT0_INTR_SOURCE                50
#define TG0_T0_LEVEL_INTR_SOURCE            51
#define TG0_T1_LEVEL_INTR_SOURCE            52
#define TG0_WDT_LEVEL_INTR_SOURCE           53
#define TG1_T0_LEVEL_INTR_SOURCE            54
#define TG1_T1_LEVEL_INTR_SOURCE            55
#define TG1_WDT_LEVEL_INTR_SOURCE           56
#define SYSTIMER_TARGET0_EDGE_INTR_SOURCE   57
#define SYSTIMER_TARGET1_EDGE_INTR_SOURCE   58
#define SYSTIMER_TARGET2_EDGE_INTR_SOURCE   59
#define APB_ADC_INTR_SOURCE                 60
#define MCPWM0_INTR_SOURCE                  61
#define PCNT_INTR_SOURCE                    62
#define PARL_IO_INTR_SOURCE                 63
#define SLC0_INTR_SOURCE                    64
#define SLC_INTR_SOURCE                     65
#define DMA_IN_CH0_INTR_SOURCE              66
#define DMA_IN_CH1_INTR_SOURCE              67
#define DMA_IN_CH2_INTR_SOURCE              68
#define DMA_OUT_CH0_INTR_SOURCE             69
#define DMA_OUT_CH1_INTR_SOURCE             70
#define DMA_OUT_CH2_INTR_SOURCE             71
#define GSPI2_INTR_SOURCE                   72
#define AES_INTR_SOURCE                     73
#define SHA_INTR_SOURCE                     74
#define RSA_INTR_SOURCE                     75
#define ECC_INTR_SOURCE                     76

/* Total number of peripherals interrupt sources */

#define ESP_NSOURCES                        77

/* CPU Interrupts */

#define ESP_NCPUINTS               32

/* The interrupts numbered 0, 3, 4, and 7 are used by the CPU for core-local interrupts (CLINT) */

#define ESP_CPUINT_PERIPHSET       0xffffff66

/* The Wireless drivers may require other CPU interrupts to be reserved */

#ifdef CONFIG_ESPRESSIF_WIFI
#  define ESP_WIRELESS_RESERVE_INT  (1 << 1)
#else
#  define ESP_WIRELESS_RESERVE_INT  0
#endif

/* IRQ numbers. */

/* ecall is dispatched like normal interrupts.  It occupies an IRQ number. */

#define RISCV_NIRQ_INTERRUPTS      16  /* Number of RISC-V dispatched interrupts. */
#define ESP_IRQ_FIRSTPERIPH        16  /* First peripheral IRQ number */

/* IRQ numbers for peripheral interrupts coming through the Interrupt
 * Matrix.
 */

#define ESP_IRQ2SOURCE(irq)        ((irq) - ESP_IRQ_FIRSTPERIPH)
#define ESP_SOURCE2IRQ(id)         ((id) + ESP_IRQ_FIRSTPERIPH)

/* Peripheral IRQs */

#define ESP_IRQ_WIFI_MAC                ESP_SOURCE2IRQ(WIFI_MAC_INTR_SOURCE)
#define ESP_IRQ_WIFI_MAC_NMI            ESP_SOURCE2IRQ(WIFI_MAC_NMI_SOURCE)
#define ESP_IRQ_WIFI_PWR                ESP_SOURCE2IRQ(WIFI_PWR_INTR_SOURCE)
#define ESP_IRQ_WIFI_BB                 ESP_SOURCE2IRQ(WIFI_BB_INTR_SOURCE)
#define ESP_IRQ_BT_MAC                  ESP_SOURCE2IRQ(BT_MAC_INTR_SOURCE)
#define ESP_IRQ_BT_BB                   ESP_SOURCE2IRQ(BT_BB_INTR_SOURCE)
#define ESP_IRQ_BT_BB_NMI               ESP_SOURCE2IRQ(BT_BB_NMI_SOURCE)
#define ESP_IRQ_LP_TIMER                ESP_SOURCE2IRQ(LP_TIMER_INTR_SOURCE)
#define ESP_IRQ_COEX                    ESP_SOURCE2IRQ(COEX_INTR_SOURCE)
#define ESP_IRQ_BLE_TIMER               ESP_SOURCE2IRQ(BLE_TIMER_INTR_SOURCE)
#define ESP_IRQ_BLE_SEC                 ESP_SOURCE2IRQ(BLE_SEC_INTR_SOURCE)
#define ESP_IRQ_I2C_MASTER              ESP_SOURCE2IRQ(I2C_MASTER_INTR_SOURCE)
#define ESP_IRQ_ZB_MAC                  ESP_SOURCE2IRQ(ZB_MAC_INTR_SOURCE)
#define ESP_IRQ_PMU                     ESP_SOURCE2IRQ(PMU_INTR_SOURCE)
#define ESP_IRQ_EFUSE                   ESP_SOURCE2IRQ(EFUSE_INTR_SOURCE)
#define ESP_IRQ_LP_RTC_TIMER            ESP_SOURCE2IRQ(LP_RTC_TIMER_INTR_SOURCE)
#define ESP_IRQ_LP_UART                 ESP_SOURCE2IRQ(LP_UART_INTR_SOURCE)
#define ESP_IRQ_LP_I2C                  ESP_SOURCE2IRQ(LP_I2C_INTR_SOURCE)
#define ESP_IRQ_LP_WDT                  ESP_SOURCE2IRQ(LP_WDT_INTR_SOURCE)
#define ESP_IRQ_LP_PERI_TIMEOUT         ESP_SOURCE2IRQ(LP_PERI_TIMEOUT_INTR_SOURCE)
#define ESP_IRQ_LP_APM_M0               ESP_SOURCE2IRQ(LP_APM_M0_INTR_SOURCE)
#define ESP_IRQ_LP_APM_M1               ESP_SOURCE2IRQ(LP_APM_M1_INTR_SOURCE)
#define ESP_IRQ_FROM_CPU_INTR0          ESP_SOURCE2IRQ(FROM_CPU_INTR0_SOURCE)
#define ESP_IRQ_FROM_CPU_INTR1          ESP_SOURCE2IRQ(FROM_CPU_INTR1_SOURCE)
#define ESP_IRQ_FROM_CPU_INTR2          ESP_SOURCE2IRQ(FROM_CPU_INTR2_SOURCE)
#define ESP_IRQ_FROM_CPU_INTR3          ESP_SOURCE2IRQ(FROM_CPU_INTR3_SOURCE)
#define ESP_IRQ_ASSIST_DEBUG            ESP_SOURCE2IRQ(ASSIST_DEBUG_INTR_SOURCE)
#define ESP_IRQ_TRACE                   ESP_SOURCE2IRQ(TRACE_INTR_SOURCE)
#define ESP_IRQ_CACHE                   ESP_SOURCE2IRQ(CACHE_INTR_SOURCE)
#define ESP_IRQ_CPU_PERI_TIMEOUT        ESP_SOURCE2IRQ(CPU_PERI_TIMEOUT_INTR_SOURCE)
#define ESP_IRQ_GPIO                    ESP_SOURCE2IRQ(GPIO_INTR_SOURCE)
#define ESP_IRQ_GPIO_NMI                ESP_SOURCE2IRQ(GPIO_NMI_SOURCE)
#define ESP_IRQ_PAU                     ESP_SOURCE2IRQ(PAU_INTR_SOURCE)
#define ESP_IRQ_HP_PERI_TIMEOUT         ESP_SOURCE2IRQ(HP_PERI_TIMEOUT_INTR_SOURCE)
#define ESP_IRQ_MODEM_PERI_TIMEOUT      ESP_SOURCE2IRQ(MODEM_PERI_TIMEOUT_INTR_SOURCE)
#define ESP_IRQ_HP_APM_M0               ESP_SOURCE2IRQ(HP_APM_M0_INTR_SOURCE)
#define ESP_IRQ_HP_APM_M1               ESP_SOURCE2IRQ(HP_APM_M1_INTR_SOURCE)
#define ESP_IRQ_HP_APM_M2               ESP_SOURCE2IRQ(HP_APM_M2_INTR_SOURCE)
#define ESP_IRQ_HP_APM_M3               ESP_SOURCE2IRQ(HP_APM_M3_INTR_SOURCE)
#define ESP_IRQ_LP_APM0                 ESP_SOURCE2IRQ(LP_APM0_INTR_SOURCE)
#define ESP_IRQ_MSPI                    ESP_SOURCE2IRQ(MSPI_INTR_SOURCE)
#define ESP_IRQ_I2S1                    ESP_SOURCE2IRQ(I2S1_INTR_SOURCE)
#define ESP_IRQ_UHCI0                   ESP_SOURCE2IRQ(UHCI0_INTR_SOURCE)
#define ESP_IRQ_UART0                   ESP_SOURCE2IRQ(UART0_INTR_SOURCE)
#define ESP_IRQ_UART1                   ESP_SOURCE2IRQ(UART1_INTR_SOURCE)
#define ESP_IRQ_LEDC                    ESP_SOURCE2IRQ(LEDC_INTR_SOURCE)
#define ESP_IRQ_TWAI0                   ESP_SOURCE2IRQ(TWAI0_INTR_SOURCE)
#define ESP_IRQ_TWAI1                   ESP_SOURCE2IRQ(TWAI1_INTR_SOURCE)
#define ESP_IRQ_USB_SERIAL_JTAG         ESP_SOURCE2IRQ(USB_SERIAL_JTAG_INTR_SOURCE)
#define ESP_IRQ_RMT                     ESP_SOURCE2IRQ(RMT_INTR_SOURCE)
#define ESP_IRQ_I2C_EXT0                ESP_SOURCE2IRQ(I2C_EXT0_INTR_SOURCE)
#define ESP_IRQ_TG0_T0_LEVEL            ESP_SOURCE2IRQ(TG0_T0_LEVEL_INTR_SOURCE)
#define ESP_IRQ_TG0_T1_LEVEL            ESP_SOURCE2IRQ(TG0_T1_LEVEL_INTR_SOURCE)
#define ESP_IRQ_TG0_WDT_LEVEL           ESP_SOURCE2IRQ(TG0_WDT_LEVEL_INTR_SOURCE)
#define ESP_IRQ_TG1_T0_LEVEL            ESP_SOURCE2IRQ(TG1_T0_LEVEL_INTR_SOURCE)
#define ESP_IRQ_TG1_T1_LEVEL            ESP_SOURCE2IRQ(TG1_T1_LEVEL_INTR_SOURCE)
#define ESP_IRQ_TG1_WDT_LEVEL           ESP_SOURCE2IRQ(TG1_WDT_LEVEL_INTR_SOURCE)
#define ESP_IRQ_SYSTIMER_TARGET0_EDGE   ESP_SOURCE2IRQ(SYSTIMER_TARGET0_EDGE_INTR_SOURCE)
#define ESP_IRQ_SYSTIMER_TARGET1_EDGE   ESP_SOURCE2IRQ(SYSTIMER_TARGET1_EDGE_INTR_SOURCE)
#define ESP_IRQ_SYSTIMER_TARGET2_EDGE   ESP_SOURCE2IRQ(SYSTIMER_TARGET2_EDGE_INTR_SOURCE)
#define ESP_IRQ_APB_ADC                 ESP_SOURCE2IRQ(APB_ADC_INTR_SOURCE)
#define ESP_IRQ_MCPWM0                  ESP_SOURCE2IRQ(MCPWM0_INTR_SOURCE)
#define ESP_IRQ_PCNT                    ESP_SOURCE2IRQ(PCNT_INTR_SOURCE)
#define ESP_IRQ_PARL_IO                 ESP_SOURCE2IRQ(PARL_IO_INTR_SOURCE)
#define ESP_IRQ_SLC0                    ESP_SOURCE2IRQ(SLC0_INTR_SOURCE)
#define ESP_IRQ_SLC                     ESP_SOURCE2IRQ(SLC_INTR_SOURCE)
#define ESP_IRQ_DMA_IN_CH0              ESP_SOURCE2IRQ(DMA_IN_CH0_INTR_SOURCE)
#define ESP_IRQ_DMA_IN_CH1              ESP_SOURCE2IRQ(DMA_IN_CH1_INTR_SOURCE)
#define ESP_IRQ_DMA_IN_CH2              ESP_SOURCE2IRQ(DMA_IN_CH2_INTR_SOURCE)
#define ESP_IRQ_DMA_OUT_CH0             ESP_SOURCE2IRQ(DMA_OUT_CH0_INTR_SOURCE)
#define ESP_IRQ_DMA_OUT_CH1             ESP_SOURCE2IRQ(DMA_OUT_CH1_INTR_SOURCE)
#define ESP_IRQ_DMA_OUT_CH2             ESP_SOURCE2IRQ(DMA_OUT_CH2_INTR_SOURCE)
#define ESP_IRQ_GSPI2                   ESP_SOURCE2IRQ(GSPI2_INTR_SOURCE)
#define ESP_IRQ_AES                     ESP_SOURCE2IRQ(AES_INTR_SOURCE)
#define ESP_IRQ_SHA                     ESP_SOURCE2IRQ(SHA_INTR_SOURCE)
#define ESP_IRQ_RSA                     ESP_SOURCE2IRQ(RSA_INTR_SOURCE)
#define ESP_IRQ_ECC                     ESP_SOURCE2IRQ(ECC_INTR_SOURCE)


#define ESP_NIRQ_PERIPH                 ESP_NSOURCES

/* Second level GPIO interrupts.  GPIO interrupts are decoded and dispatched
 * as a second level of decoding:  The first level dispatches to the GPIO
 * interrupt handler.  The second to the decoded GPIO interrupt handler.
 */

#ifdef CONFIG_ESPRESSIF_GPIO_IRQ
#  define ESP_NIRQ_GPIO             22
#  define ESP_FIRST_GPIOIRQ         (RISCV_NIRQ_INTERRUPTS + ESP_NIRQ_PERIPH)
#  define ESP_LAST_GPIOIRQ          (ESP_FIRST_GPIOIRQ + ESP_NIRQ_GPIO - 1)
#  define ESP_PIN2IRQ(p)            ((p) + ESP_FIRST_GPIOIRQ)
#  define ESP_IRQ2PIN(i)            ((i) - ESP_FIRST_GPIOIRQ)
#else
#  define ESP_NIRQ_GPIO             0
#endif

/* Total number of IRQs: ecall + Number of peripheral IRQs + GPIOs IRQs. */

#define NR_IRQS  (RISCV_NIRQ_INTERRUPTS + ESP_NIRQ_PERIPH + ESP_NIRQ_GPIO)
