/*
 * SPDX-FileCopyrightText: 2018-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __NuttX__
#include <esp_attr.h>
#include <esp_heap_caps.h>
#include <sdkconfig.h>
#include "esp_mem.h"
#else
#include <stdlib.h>
#include <sys/types.h>
#include <sdkconfig.h>
#include "esp_attr.h"
#include <nuttx/kmalloc.h>
#endif

#ifndef CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC

IRAM_ATTR void *esp_mbedtls_mem_calloc(size_t n, size_t size)
{
#ifdef CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC
    return heap_caps_calloc(n, size, MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
#elif CONFIG_MBEDTLS_EXTERNAL_MEM_ALLOC
    return heap_caps_calloc(n, size, MALLOC_CAP_SPIRAM|MALLOC_CAP_8BIT);
#elif CONFIG_MBEDTLS_IRAM_8BIT_MEM_ALLOC
#ifdef CONFIG_MBEDTLS_ASYMMETRIC_CONTENT_LEN
    if ((n*size) >= CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN || (n*size) >= CONFIG_MBEDTLS_SSL_OUT_CONTENT_LEN) {
#else
    if ((n*size) >= CONFIG_MBEDTLS_SSL_MAX_CONTENT_LEN) {
#endif
        return heap_caps_calloc_prefer(n, size, 2, MALLOC_CAP_INTERNAL|MALLOC_CAP_IRAM_8BIT, MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    } else {
        return heap_caps_calloc(n, size, MALLOC_CAP_INTERNAL|MALLOC_CAP_8BIT);
    }

#else
#ifndef __NuttX__
    return calloc(n, size);
#else
    return kmm_calloc(n, size);
#endif
#endif
}

IRAM_ATTR void esp_mbedtls_mem_free(void *ptr)
{
#ifndef __NuttX__
    return heap_caps_free(ptr);
#else
    return kmm_free(ptr);
#endif
}

#endif /* !CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC */
