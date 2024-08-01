/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <nuttx/config.h>

/* RESERVED interrupts: 0 to 14 */

#define WIFI_MAC_INTR_SOURCE                0
#define WIFI_MAC_NMI_SOURCE                 1
#define WIFI_PWR_INTR_SOURCE                2
#define WIFI_BB_INTR_SOURCE                 3
#define BT_MAC_INTR_SOURCE                  4
#define BT_BB_INTR_SOURCE                   5
#define BT_BB_NMI_SOURCE                    6
#define RWBT_INTR_SOURCE                    7
#define RWBLE_INTR_SOURCE                   8
#define RWBT_NMI_SOURCE                     9
#define RWBLE_NMI_SOURCE                    10
#define I2C_MASTER_SOURCE                   11
#define SLC0_INTR_SOURCE                    12
#define SLC1_INTR_SOURCE                    13
#define APB_CTRL_INTR_SOURCE                14
#define UHCI0_INTR_SOURCE                   15
#define GPIO_INTR_SOURCE                    16
#define GPIO_NMI_SOURCE                     17
#define SPI1_INTR_SOURCE                    18
#define SPI2_INTR_SOURCE                    19
#define I2S1_INTR_SOURCE                    20
#define UART0_INTR_SOURCE                   21
#define UART1_INTR_SOURCE                   22
#define LEDC_INTR_SOURCE                    23
#define EFUSE_INTR_SOURCE                   24
#define TWAI_INTR_SOURCE                    25
#define USB_SERIAL_JTAG_INTR_SOURCE         26
#define RTC_CORE_INTR_SOURCE                27
#define RMT_INTR_SOURCE                     28
#define I2C_EXT0_INTR_SOURCE                29
#define TIMER1_INTR_SOURCE                  30
#define TIMER2_INTR_SOURCE                  31
#define TG0_T0_LEVEL_INTR_SOURCE            32
#define TG0_WDT_LEVEL_INTR_SOURCE           33
#define TG1_T0_LEVEL_INTR_SOURCE            34
#define TG1_WDT_LEVEL_INTR_SOURCE           35
#define CACHE_IA_INTR_SOURCE                36
#define SYSTIMER_TARGET0_EDGE_INTR_SOURCE   37
#define SYSTIMER_TARGET1_EDGE_INTR_SOURCE   38
#define SYSTIMER_TARGET2_EDGE_INTR_SOURCE   39
#define SPI_MEM_REJECT_CACHE_INTR_SOURCE    40
#define ICACHE_PRELOAD0_INTR_SOURCE         41
#define ICACHE_SYNC0_INTR_SOURCE            42
#define APB_ADC_INTR_SOURCE                 43
#define DMA_CH0_INTR_SOURCE                 44
#define DMA_CH1_INTR_SOURCE                 45
#define DMA_CH2_INTR_SOURCE                 46
#define RSA_INTR_SOURCE                     47
#define AES_INTR_SOURCE                     48
#define SHA_INTR_SOURCE                     49
#define FROM_CPU_INTR0_SOURCE               50
#define FROM_CPU_INTR1_SOURCE               51
#define FROM_CPU_INTR2_SOURCE               52
#define FROM_CPU_INTR3_SOURCE               53
#define ASSIST_DEBUG_INTR_SOURCE            54
#define DMA_APBPERI_PMS_INTR_SOURCE         55
#define CORE0_IRAM0_PMS_INTR_SOURCE         56
#define CORE0_DRAM0_PMS_INTR_SOURCE         57
#define CORE0_PIF_PMS_INTR_SOURCE           58
#define CORE0_PIF_PMS_SIZE_INTR_SOURCE      59
#define BAK_PMS_VIOLATE_INTR_SOURCE         60
#define CACHE_CORE0_ACS_INTR_SOURCE         61

/* RESERVED interrupts 60-61 */

/* Total number of peripherals */

#define ESP_NSOURCES                        62

/* CPU Interrupts.
 *
 * The ESP32-C3 CPU interrupt controller accepts 31 asynchronous interrupts.
 */

#define ESP_NCPUINTS               32

#define ESP_CPUINT_PERIPHSET       0xfffffffe

/* The Wireless drivers may require other CPU interrupts to be reserved */

#ifdef CONFIG_ESPRESSIF_WIFI
#  define ESP_WIRELESS_RESERVE_INT  (1 << 1)
#else
#  define ESP_WIRELESS_RESERVE_INT  0
#endif

/* Reserved CPU interrupt for specific drivers */

#define ESP_CPUINT_WMAC            1  /* Wi-Fi MAC */
#define ESP_CPUINT_BT_BB           5  /* BT BB */
#define ESP_CPUINT_RWBLE           8  /* RW BLE */

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
#define ESP_IRQ_RWBT                    ESP_SOURCE2IRQ(RWBT_INTR_SOURCE)
#define ESP_IRQ_RWBLE                   ESP_SOURCE2IRQ(RWBLE_INTR_SOURCE)
#define ESP_IRQ_RWBT_NMI                ESP_SOURCE2IRQ(RWBT_NMI_SOURCE)
#define ESP_IRQ_RWBLE_NMI               ESP_SOURCE2IRQ(RWBLE_NMI_SOURCE)
#define ESP_IRQ_I2C_MASTER              ESP_SOURCE2IRQ(I2C_MASTER_SOURCE)
#define ESP_IRQ_SLC0                    ESP_SOURCE2IRQ(SLC0_INTR_SOURCE)
#define ESP_IRQ_SLC1                    ESP_SOURCE2IRQ(SLC1_INTR_SOURCE)
#define ESP_IRQ_APB_CTRL                ESP_SOURCE2IRQ(APB_CTRL_INTR_SOURCE)
#define ESP_IRQ_UHCI0                   ESP_SOURCE2IRQ(UHCI0_INTR_SOURCE)
#define ESP_IRQ_GPIO                    ESP_SOURCE2IRQ(GPIO_INTR_SOURCE)
#define ESP_IRQ_GPIO_NMI                ESP_SOURCE2IRQ(GPIO_NMI_SOURCE)
#define ESP_IRQ_SPI1                    ESP_SOURCE2IRQ(SPI1_INTR_SOURCE)
#define ESP_IRQ_SPI2                    ESP_SOURCE2IRQ(SPI2_INTR_SOURCE)
#define ESP_IRQ_I2S1                    ESP_SOURCE2IRQ(I2S1_INTR_SOURCE)
#define ESP_IRQ_UART0                   ESP_SOURCE2IRQ(UART0_INTR_SOURCE)
#define ESP_IRQ_UART1                   ESP_SOURCE2IRQ(UART1_INTR_SOURCE)
#define ESP_IRQ_LEDC                    ESP_SOURCE2IRQ(LEDC_INTR_SOURCE)
#define ESP_IRQ_EFUSE                   ESP_SOURCE2IRQ(EFUSE_INTR_SOURCE)
#define ESP_IRQ_TWAI                    ESP_SOURCE2IRQ(TWAI_INTR_SOURCE)
#define ESP_IRQ_USB_SERIAL_JTAG         ESP_SOURCE2IRQ(USB_SERIAL_JTAG_INTR_SOURCE)
#define ESP_IRQ_RTC_CORE                ESP_SOURCE2IRQ(RTC_CORE_INTR_SOURCE)
#define ESP_IRQ_RMT                     ESP_SOURCE2IRQ(RMT_INTR_SOURCE)
#define ESP_IRQ_I2C_EXT0                ESP_SOURCE2IRQ(I2C_EXT0_INTR_SOURCE)
#define ESP_IRQ_TIMER1                  ESP_SOURCE2IRQ(TIMER1_INTR_SOURCE)
#define ESP_IRQ_TIMER2                  ESP_SOURCE2IRQ(TIMER2_INTR_SOURCE)
#define ESP_IRQ_TG0_T0_LEVEL            ESP_SOURCE2IRQ(TG0_T0_LEVEL_INTR_SOURCE)
#define ESP_IRQ_TG0_WDT_LEVEL           ESP_SOURCE2IRQ(TG0_WDT_LEVEL_INTR_SOURCE)
#define ESP_IRQ_TG1_T0_LEVEL            ESP_SOURCE2IRQ(TG1_T0_LEVEL_INTR_SOURCE)
#define ESP_IRQ_TG1_WDT_LEVEL           ESP_SOURCE2IRQ(TG1_WDT_LEVEL_INTR_SOURCE)
#define ESP_IRQ_CACHE_IA                ESP_SOURCE2IRQ(CACHE_IA_INTR_SOURCE)
#define ESP_IRQ_SYSTIMER_TARGET0_EDGE   ESP_SOURCE2IRQ(SYSTIMER_TARGET0_EDGE_INTR_SOURCE)
#define ESP_IRQ_SYSTIMER_TARGET1_EDGE   ESP_SOURCE2IRQ(SYSTIMER_TARGET1_EDGE_INTR_SOURCE)
#define ESP_IRQ_SYSTIMER_TARGET2_EDGE   ESP_SOURCE2IRQ(SYSTIMER_TARGET2_EDGE_INTR_SOURCE)
#define ESP_IRQ_SPI_MEM_REJECT_CACHE    ESP_SOURCE2IRQ(SPI_MEM_REJECT_CACHE_INTR_SOURCE)
#define ESP_IRQ_ICACHE_PRELOAD0         ESP_SOURCE2IRQ(ICACHE_PRELOAD0_INTR_SOURCE)
#define ESP_IRQ_ICACHE_SYNC0            ESP_SOURCE2IRQ(ICACHE_SYNC0_INTR_SOURCE)
#define ESP_IRQ_APB_ADC                 ESP_SOURCE2IRQ(APB_ADC_INTR_SOURCE)
#define ESP_IRQ_DMA_CH0                 ESP_SOURCE2IRQ(DMA_CH0_INTR_SOURCE)
#define ESP_IRQ_DMA_CH1                 ESP_SOURCE2IRQ(DMA_CH1_INTR_SOURCE)
#define ESP_IRQ_DMA_CH2                 ESP_SOURCE2IRQ(DMA_CH2_INTR_SOURCE)
#define ESP_IRQ_RSA                     ESP_SOURCE2IRQ(RSA_INTR_SOURCE)
#define ESP_IRQ_AES                     ESP_SOURCE2IRQ(AES_INTR_SOURCE)
#define ESP_IRQ_SHA                     ESP_SOURCE2IRQ(SHA_INTR_SOURCE)
#define ESP_IRQ_FROM_CPU_INTR0          ESP_SOURCE2IRQ(FROM_CPU_INTR0_SOURCE)
#define ESP_IRQ_FROM_CPU_INTR1          ESP_SOURCE2IRQ(FROM_CPU_INTR1_SOURCE)
#define ESP_IRQ_FROM_CPU_INTR2          ESP_SOURCE2IRQ(FROM_CPU_INTR2_SOURCE)
#define ESP_IRQ_FROM_CPU_INTR3          ESP_SOURCE2IRQ(FROM_CPU_INTR3_SOURCE)
#define ESP_IRQ_ASSIST_DEBUG            ESP_SOURCE2IRQ(ASSIST_DEBUG_INTR_SOURCE)
#define ESP_IRQ_DMA_APBPERI_PMS         ESP_SOURCE2IRQ(DMA_APBPERI_PMS_INTR_SOURCE)
#define ESP_IRQ_CORE0_IRAM0_PMS         ESP_SOURCE2IRQ(CORE0_IRAM0_PMS_INTR_SOURCE)
#define ESP_IRQ_CORE0_DRAM0_PMS         ESP_SOURCE2IRQ(CORE0_DRAM0_PMS_INTR_SOURCE)
#define ESP_IRQ_CORE0_PIF_PMS           ESP_SOURCE2IRQ(CORE0_PIF_PMS_INTR_SOURCE)
#define ESP_IRQ_CORE0_PIF_PMS_SIZE      ESP_SOURCE2IRQ(CORE0_PIF_PMS_SIZE_INTR_SOURCE)
#define ESP_IRQ_AK_PMS_VIOLATE          ESP_SOURCE2IRQ(BAK_PMS_VIOLATE_INTR_SOURCE)
#define ESP_IRQ_CACHE_CORE0_ACS         ESP_SOURCE2IRQ(CACHE_CORE0_ACS_INTR_SOURCE)

#define ESP_NIRQ_PERIPH                 ESP_NSOURCES

/* Second level GPIO interrupts.  GPIO interrupts are decoded and dispatched
 * as a second level of decoding:  The first level dispatches to the GPIO
 * interrupt handler.  The second to the decoded GPIO interrupt handler.
 */

#ifdef CONFIG_ESPRESSIF_GPIO_IRQ
#  define ESP_NIRQ_GPIO           22
#  define ESP_FIRST_GPIOIRQ       (RISCV_NIRQ_INTERRUPTS + ESP_NIRQ_PERIPH)
#  define ESP_LAST_GPIOIRQ        (ESP_FIRST_GPIOIRQ + ESP_NIRQ_GPIO - 1)
#  define ESP_PIN2IRQ(p)          ((p) + ESP_FIRST_GPIOIRQ)
#  define ESP_IRQ2PIN(i)          ((i) - ESP_FIRST_GPIOIRQ)
#else
#  define ESP_NIRQ_GPIO           0
#endif

#ifdef CONFIG_ESPRESSIF_RTCIO_IRQ

/* Second level RTC interrupts.  RTC interrupts are decoded and dispatched
 * as a second level of decoding:  The first level dispatches to the RTC
 * interrupt handler.  The second to the decoded RTC interrupt handler.
 * A third level might be required to be implemented on the driver.
 */

#  define ESP_NIRQ_RTCIO              9

#  define ESP_FIRST_RTCIOIRQ          (RISCV_NIRQ_INTERRUPTS+ESP_NIRQ_PERIPH+ESP_NIRQ_GPIO)
#  define ESP_LAST_RTCIOIRQ           (ESP_FIRST_RTCIOIRQ+ESP_NIRQ_RTCIO-1)
#  define ESP_IRQ_RTC_SLP_WAKEUP      (ESP_FIRST_RTCIOIRQ+0)
#  define ESP_IRQ_RTC_SLP_REJECT      (ESP_FIRST_RTCIOIRQ+1)
#  define ESP_IRQ_RTC_WDT             (ESP_FIRST_RTCIOIRQ+2)
#  define ESP_IRQ_RTC_BROWN_OUT       (ESP_FIRST_RTCIOIRQ+3)
#  define ESP_IRQ_RTC_MAIN_TIMER      (ESP_FIRST_RTCIOIRQ+4)
#  define ESP_IRQ_RTC_SWD             (ESP_FIRST_RTCIOIRQ+5)
#  define ESP_IRQ_RTC_XTAL32K_DEAD    (ESP_FIRST_RTCIOIRQ+6)
#  define ESP_IRQ_RTC_GLITCH_DET      (ESP_FIRST_RTCIOIRQ+7)
#  define ESP_IRQ_RTC_BBPLL_CAL       (ESP_FIRST_RTCIOIRQ+8)
#else
#  define ESP_NIRQ_RTCIO              0
#endif /* CONFIG_ESPRESSIF_RTCIO_IRQ */

/* Total number of IRQs: ecall + Number of peripheral IRQs + GPIOs IRQs + RTCIO IRQs. */

#define NR_IRQS  (RISCV_NIRQ_INTERRUPTS + ESP_NIRQ_PERIPH + ESP_NIRQ_GPIO + ESP_NIRQ_RTCIO)
