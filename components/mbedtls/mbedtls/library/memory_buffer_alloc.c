/*
 *  Buffer-based memory allocator
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"

/* No need for the header guard as MBEDTLS_MEMORY_BUFFER_ALLOC_C
   is dependent upon MBEDTLS_PLATFORM_C */
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"

#include <string.h>

#if defined(MBEDTLS_MEMORY_BACKTRACE)
#include <execinfo.h>
#endif

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

#define MAGIC1       0xFF00AA55
#define MAGIC2       0xEE119966
#define MAX_BT 20

typedef struct _memory_header memory_header;
struct _memory_header {
    size_t          magic1;
    size_t          size;
    size_t          alloc;
    memory_header   *prev;
    memory_header   *next;
    memory_header   *prev_free;
    memory_header   *next_free;
#if defined(MBEDTLS_MEMORY_BACKTRACE)
    char            **trace;
    size_t          trace_count;
#endif
    size_t          magic2;
};

typedef struct {
    unsigned char   *buf;
    size_t          len;
    memory_header   *first;
    memory_header   *first_free;
    int             verify;
#if defined(MBEDTLS_MEMORY_DEBUG)
    size_t          alloc_count;
    size_t          free_count;
    size_t          total_used;
    size_t          maximum_used;
    size_t          header_count;
    size_t          maximum_header_count;
#endif
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t   mutex;
#endif
}
buffer_alloc_ctx;

static buffer_alloc_ctx esp_heap;

#if defined(MBEDTLS_MEMORY_DEBUG)
static void esp_debug_header(memory_header *hdr)
{
#if defined(MBEDTLS_MEMORY_BACKTRACE)
    size_t i;
#endif

    esp_mbedtls_fprintf(stderr, "HDR:  PTR(%10zu), PREV(%10zu), NEXT(%10zu), "
                            "ALLOC(%zu), SIZE(%10zu)\n",
                    (size_t) hdr, (size_t) hdr->prev, (size_t) hdr->next,
                    hdr->alloc, hdr->size);
    esp_mbedtls_fprintf(stderr, "      FPREV(%10zu), FNEXT(%10zu)\n",
                    (size_t) hdr->prev_free, (size_t) hdr->next_free);

#if defined(MBEDTLS_MEMORY_BACKTRACE)
    esp_mbedtls_fprintf(stderr, "TRACE: \n");
    for (i = 0; i < hdr->trace_count; i++) {
        esp_mbedtls_fprintf(stderr, "%s\n", hdr->trace[i]);
    }
    esp_mbedtls_fprintf(stderr, "\n");
#endif
}

static void esp_debug_chain(void)
{
    memory_header *cur = esp_heap.first;

    esp_mbedtls_fprintf(stderr, "\nBlock list\n");
    while (cur != NULL) {
        esp_debug_header(cur);
        cur = cur->next;
    }

    esp_mbedtls_fprintf(stderr, "Free list\n");
    cur = esp_heap.first_free;

    while (cur != NULL) {
        esp_debug_header(cur);
        cur = cur->next_free;
    }
}
#endif /* MBEDTLS_MEMORY_DEBUG */

static int esp_verify_header(memory_header *hdr)
{
    if (hdr->magic1 != MAGIC1) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_mbedtls_fprintf(stderr, "FATAL: MAGIC1 mismatch\n");
#endif
        return 1;
    }

    if (hdr->magic2 != MAGIC2) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_mbedtls_fprintf(stderr, "FATAL: MAGIC2 mismatch\n");
#endif
        return 1;
    }

    if (hdr->alloc > 1) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_mbedtls_fprintf(stderr, "FATAL: alloc has illegal value\n");
#endif
        return 1;
    }

    if (hdr->prev != NULL && hdr->prev == hdr->next) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_mbedtls_fprintf(stderr, "FATAL: prev == next\n");
#endif
        return 1;
    }

    if (hdr->prev_free != NULL && hdr->prev_free == hdr->next_free) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_mbedtls_fprintf(stderr, "FATAL: prev_free == next_free\n");
#endif
        return 1;
    }

    return 0;
}

static int esp_verify_chain(void)
{
    memory_header *prv = esp_heap.first, *cur;

    if (prv == NULL || esp_verify_header(prv) != 0) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_mbedtls_fprintf(stderr, "FATAL: verification of first header "
                                "failed\n");
#endif
        return 1;
    }

    if (esp_heap.first->prev != NULL) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_mbedtls_fprintf(stderr, "FATAL: verification failed: "
                                "first->prev != NULL\n");
#endif
        return 1;
    }

    cur = esp_heap.first->next;

    while (cur != NULL) {
        if (esp_verify_header(cur) != 0) {
#if defined(MBEDTLS_MEMORY_DEBUG)
            esp_mbedtls_fprintf(stderr, "FATAL: verification of header "
                                    "failed\n");
#endif
            return 1;
        }

        if (cur->prev != prv) {
#if defined(MBEDTLS_MEMORY_DEBUG)
            esp_mbedtls_fprintf(stderr, "FATAL: verification failed: "
                                    "cur->prev != prv\n");
#endif
            return 1;
        }

        prv = cur;
        cur = cur->next;
    }

    return 0;
}

static void *esp_buffer_alloc_calloc(size_t n, size_t size)
{
    memory_header *new, *cur = esp_heap.first_free;
    unsigned char *p;
    void *ret;
    size_t original_len, len;
#if defined(MBEDTLS_MEMORY_BACKTRACE)
    void *trace_buffer[MAX_BT];
    size_t trace_cnt;
#endif

    if (esp_heap.buf == NULL || esp_heap.first == NULL) {
        return NULL;
    }

    original_len = len = n * size;

    if (n == 0 || size == 0 || len / n != size) {
        return NULL;
    } else if (len > (size_t) -MBEDTLS_MEMORY_ALIGN_MULTIPLE) {
        return NULL;
    }

    if (len % MBEDTLS_MEMORY_ALIGN_MULTIPLE) {
        len -= len % MBEDTLS_MEMORY_ALIGN_MULTIPLE;
        len += MBEDTLS_MEMORY_ALIGN_MULTIPLE;
    }

    // Find block that fits
    //
    while (cur != NULL) {
        if (cur->size >= len) {
            break;
        }

        cur = cur->next_free;
    }

    if (cur == NULL) {
        return NULL;
    }

    if (cur->alloc != 0) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_mbedtls_fprintf(stderr, "FATAL: block in free_list but allocated "
                                "data\n");
#endif
        esp_mbedtls_exit(1);
    }

#if defined(MBEDTLS_MEMORY_DEBUG)
    esp_heap.alloc_count++;
#endif

    // Found location, split block if > memory_header + 4 room left
    //
    if (cur->size - len < sizeof(memory_header) +
        MBEDTLS_MEMORY_ALIGN_MULTIPLE) {
        cur->alloc = 1;

        // Remove from free_list
        //
        if (cur->prev_free != NULL) {
            cur->prev_free->next_free = cur->next_free;
        } else {
            esp_heap.first_free = cur->next_free;
        }

        if (cur->next_free != NULL) {
            cur->next_free->prev_free = cur->prev_free;
        }

        cur->prev_free = NULL;
        cur->next_free = NULL;

#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_heap.total_used += cur->size;
        if (esp_heap.total_used > esp_heap.maximum_used) {
            esp_heap.maximum_used = esp_heap.total_used;
        }
#endif
#if defined(MBEDTLS_MEMORY_BACKTRACE)
        trace_cnt = backtrace(trace_buffer, MAX_BT);
        cur->trace = backtrace_symbols(trace_buffer, trace_cnt);
        cur->trace_count = trace_cnt;
#endif

        if ((esp_heap.verify & MBEDTLS_MEMORY_VERIFY_ALLOC) && esp_verify_chain() != 0) {
            esp_mbedtls_exit(1);
        }

        ret = (unsigned char *) cur + sizeof(memory_header);
        memset(ret, 0, original_len);

        return ret;
    }

    p = ((unsigned char *) cur) + sizeof(memory_header) + len;
    new = (memory_header *) p;

    new->size = cur->size - len - sizeof(memory_header);
    new->alloc = 0;
    new->prev = cur;
    new->next = cur->next;
#if defined(MBEDTLS_MEMORY_BACKTRACE)
    new->trace = NULL;
    new->trace_count = 0;
#endif
    new->magic1 = MAGIC1;
    new->magic2 = MAGIC2;

    if (new->next != NULL) {
        new->next->prev = new;
    }

    // Replace cur with new in free_list
    //
    new->prev_free = cur->prev_free;
    new->next_free = cur->next_free;
    if (new->prev_free != NULL) {
        new->prev_free->next_free = new;
    } else {
        esp_heap.first_free = new;
    }

    if (new->next_free != NULL) {
        new->next_free->prev_free = new;
    }

    cur->alloc = 1;
    cur->size = len;
    cur->next = new;
    cur->prev_free = NULL;
    cur->next_free = NULL;

#if defined(MBEDTLS_MEMORY_DEBUG)
    esp_heap.header_count++;
    if (esp_heap.header_count > esp_heap.maximum_header_count) {
        esp_heap.maximum_header_count = esp_heap.header_count;
    }
    esp_heap.total_used += cur->size;
    if (esp_heap.total_used > esp_heap.maximum_used) {
        esp_heap.maximum_used = esp_heap.total_used;
    }
#endif
#if defined(MBEDTLS_MEMORY_BACKTRACE)
    trace_cnt = backtrace(trace_buffer, MAX_BT);
    cur->trace = backtrace_symbols(trace_buffer, trace_cnt);
    cur->trace_count = trace_cnt;
#endif

    if ((esp_heap.verify & MBEDTLS_MEMORY_VERIFY_ALLOC) && esp_verify_chain() != 0) {
        esp_mbedtls_exit(1);
    }

    ret = (unsigned char *) cur + sizeof(memory_header);
    memset(ret, 0, original_len);

    return ret;
}

static void esp_buffer_alloc_free(void *ptr)
{
    memory_header *hdr, *old = NULL;
    unsigned char *p = (unsigned char *) ptr;

    if (ptr == NULL || esp_heap.buf == NULL || esp_heap.first == NULL) {
        return;
    }

    if (p < esp_heap.buf || p >= esp_heap.buf + esp_heap.len) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_mbedtls_fprintf(stderr, "FATAL: esp_mbedtls_free() outside of managed "
                                "space\n");
#endif
        esp_mbedtls_exit(1);
    }

    p -= sizeof(memory_header);
    hdr = (memory_header *) p;

    if (esp_verify_header(hdr) != 0) {
        esp_mbedtls_exit(1);
    }

    if (hdr->alloc != 1) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_mbedtls_fprintf(stderr, "FATAL: esp_mbedtls_free() on unallocated "
                                "data\n");
#endif
        esp_mbedtls_exit(1);
    }

    hdr->alloc = 0;

#if defined(MBEDTLS_MEMORY_DEBUG)
    esp_heap.free_count++;
    esp_heap.total_used -= hdr->size;
#endif

#if defined(MBEDTLS_MEMORY_BACKTRACE)
    free(hdr->trace);
    hdr->trace = NULL;
    hdr->trace_count = 0;
#endif

    // Regroup with block before
    //
    if (hdr->prev != NULL && hdr->prev->alloc == 0) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_heap.header_count--;
#endif
        hdr->prev->size += sizeof(memory_header) + hdr->size;
        hdr->prev->next = hdr->next;
        old = hdr;
        hdr = hdr->prev;

        if (hdr->next != NULL) {
            hdr->next->prev = hdr;
        }

        memset(old, 0, sizeof(memory_header));
    }

    // Regroup with block after
    //
    if (hdr->next != NULL && hdr->next->alloc == 0) {
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_heap.header_count--;
#endif
        hdr->size += sizeof(memory_header) + hdr->next->size;
        old = hdr->next;
        hdr->next = hdr->next->next;

        if (hdr->prev_free != NULL || hdr->next_free != NULL) {
            if (hdr->prev_free != NULL) {
                hdr->prev_free->next_free = hdr->next_free;
            } else {
                esp_heap.first_free = hdr->next_free;
            }

            if (hdr->next_free != NULL) {
                hdr->next_free->prev_free = hdr->prev_free;
            }
        }

        hdr->prev_free = old->prev_free;
        hdr->next_free = old->next_free;

        if (hdr->prev_free != NULL) {
            hdr->prev_free->next_free = hdr;
        } else {
            esp_heap.first_free = hdr;
        }

        if (hdr->next_free != NULL) {
            hdr->next_free->prev_free = hdr;
        }

        if (hdr->next != NULL) {
            hdr->next->prev = hdr;
        }

        memset(old, 0, sizeof(memory_header));
    }

    // Prepend to free_list if we have not merged
    // (Does not have to stay in same order as prev / next list)
    //
    if (old == NULL) {
        hdr->next_free = esp_heap.first_free;
        if (esp_heap.first_free != NULL) {
            esp_heap.first_free->prev_free = hdr;
        }
        esp_heap.first_free = hdr;
    }

    if ((esp_heap.verify & MBEDTLS_MEMORY_VERIFY_FREE) && esp_verify_chain() != 0) {
        esp_mbedtls_exit(1);
    }
}

void esp_mbedtls_memory_buffer_set_verify(int verify)
{
    esp_heap.verify = verify;
}

int esp_mbedtls_memory_buffer_alloc_verify(void)
{
    return esp_verify_chain();
}

#if defined(MBEDTLS_MEMORY_DEBUG)
void esp_mbedtls_memory_buffer_alloc_status(void)
{
    esp_mbedtls_fprintf(stderr,
                    "Current use: %zu blocks / %zu bytes, max: %zu blocks / "
                    "%zu bytes (total %zu bytes), alloc / free: %zu / %zu\n",
                    esp_heap.header_count, esp_heap.total_used,
                    esp_heap.maximum_header_count, esp_heap.maximum_used,
                    esp_heap.maximum_header_count * sizeof(memory_header)
                    + esp_heap.maximum_used,
                    esp_heap.alloc_count, esp_heap.free_count);

    if (esp_heap.first->next == NULL) {
        esp_mbedtls_fprintf(stderr, "All memory de-allocated in stack buffer\n");
    } else {
        esp_mbedtls_fprintf(stderr, "Memory currently allocated:\n");
        esp_debug_chain();
    }
}

void esp_mbedtls_memory_buffer_alloc_count_get(size_t *alloc_count, size_t *free_count)
{
    *alloc_count = esp_heap.alloc_count;
    *free_count = esp_heap.free_count;
}

void esp_mbedtls_memory_buffer_alloc_max_get(size_t *max_used, size_t *max_blocks)
{
    *max_used   = esp_heap.maximum_used;
    *max_blocks = esp_heap.maximum_header_count;
}

void esp_mbedtls_memory_buffer_alloc_max_reset(void)
{
    esp_heap.maximum_used = 0;
    esp_heap.maximum_header_count = 0;
}

void esp_mbedtls_memory_buffer_alloc_cur_get(size_t *cur_used, size_t *cur_blocks)
{
    *cur_used   = esp_heap.total_used;
    *cur_blocks = esp_heap.header_count;
}
#endif /* MBEDTLS_MEMORY_DEBUG */

#if defined(MBEDTLS_THREADING_C)
static void *esp_buffer_alloc_calloc_mutexed(size_t n, size_t size)
{
    void *buf;
    if (esp_mbedtls_mutex_lock(&esp_heap.mutex) != 0) {
        return NULL;
    }
    buf = esp_buffer_alloc_calloc(n, size);
    if (esp_mbedtls_mutex_unlock(&esp_heap.mutex)) {
        return NULL;
    }
    return buf;
}

static void esp_buffer_alloc_free_mutexed(void *ptr)
{
    /* We have no good option here, but corrupting the esp_heap seems
     * worse than losing memory. */
    if (esp_mbedtls_mutex_lock(&esp_heap.mutex)) {
        return;
    }
    esp_buffer_alloc_free(ptr);
    (void) esp_mbedtls_mutex_unlock(&esp_heap.mutex);
}
#endif /* MBEDTLS_THREADING_C */

void esp_mbedtls_memory_buffer_alloc_init(unsigned char *buf, size_t len)
{
    memset(&esp_heap, 0, sizeof(buffer_alloc_ctx));

#if defined(MBEDTLS_THREADING_C)
    esp_mbedtls_mutex_init(&esp_heap.mutex);
    esp_mbedtls_platform_set_calloc_free(esp_buffer_alloc_calloc_mutexed,
                                     esp_buffer_alloc_free_mutexed);
#else
    esp_mbedtls_platform_set_calloc_free(esp_buffer_alloc_calloc, esp_buffer_alloc_free);
#endif

    if (len < sizeof(memory_header) + MBEDTLS_MEMORY_ALIGN_MULTIPLE) {
        return;
    } else if ((size_t) buf % MBEDTLS_MEMORY_ALIGN_MULTIPLE) {
        /* Adjust len first since buf is used in the computation */
        len -= MBEDTLS_MEMORY_ALIGN_MULTIPLE
               - (size_t) buf % MBEDTLS_MEMORY_ALIGN_MULTIPLE;
        buf += MBEDTLS_MEMORY_ALIGN_MULTIPLE
               - (size_t) buf % MBEDTLS_MEMORY_ALIGN_MULTIPLE;
    }

    memset(buf, 0, len);

    esp_heap.buf = buf;
    esp_heap.len = len;

    esp_heap.first = (memory_header *) buf;
    esp_heap.first->size = len - sizeof(memory_header);
    esp_heap.first->magic1 = MAGIC1;
    esp_heap.first->magic2 = MAGIC2;
    esp_heap.first_free = esp_heap.first;
}

void esp_mbedtls_memory_buffer_alloc_free(void)
{
#if defined(MBEDTLS_THREADING_C)
    esp_mbedtls_mutex_free(&esp_heap.mutex);
#endif
    esp_mbedtls_platform_zeroize(&esp_heap, sizeof(buffer_alloc_ctx));
}

#if defined(MBEDTLS_SELF_TEST)
static int esp_check_pointer(void *p)
{
    if (p == NULL) {
        return -1;
    }

    if ((size_t) p % MBEDTLS_MEMORY_ALIGN_MULTIPLE != 0) {
        return -1;
    }

    return 0;
}

static int esp_check_all_free(void)
{
    if (
#if defined(MBEDTLS_MEMORY_DEBUG)
        esp_heap.total_used != 0 ||
#endif
        esp_heap.first != esp_heap.first_free ||
        (void *) esp_heap.first != (void *) esp_heap.buf) {
        return -1;
    }

    return 0;
}

#define TEST_ASSERT(condition)            \
    if (!(condition))                     \
    {                                       \
        if (verbose != 0)                  \
        esp_mbedtls_printf("failed\n");  \
                                            \
        ret = 1;                            \
        goto cleanup;                       \
    }

int esp_mbedtls_memory_buffer_alloc_self_test(int verbose)
{
    unsigned char buf[1024];
    unsigned char *p, *q, *r, *end;
    int ret = 0;

    if (verbose != 0) {
        esp_mbedtls_printf("  MBA test #1 (basic alloc-free cycle): ");
    }

    esp_mbedtls_memory_buffer_alloc_init(buf, sizeof(buf));

    p = esp_mbedtls_calloc(1, 1);
    q = esp_mbedtls_calloc(1, 128);
    r = esp_mbedtls_calloc(1, 16);

    TEST_ASSERT(esp_check_pointer(p) == 0 &&
                esp_check_pointer(q) == 0 &&
                esp_check_pointer(r) == 0);

    esp_mbedtls_free(r);
    esp_mbedtls_free(q);
    esp_mbedtls_free(p);

    TEST_ASSERT(esp_check_all_free() == 0);

    /* Memorize end to compare with the next test */
    end = esp_heap.buf + esp_heap.len;

    esp_mbedtls_memory_buffer_alloc_free();

    if (verbose != 0) {
        esp_mbedtls_printf("passed\n");
    }

    if (verbose != 0) {
        esp_mbedtls_printf("  MBA test #2 (buf not aligned): ");
    }

    esp_mbedtls_memory_buffer_alloc_init(buf + 1, sizeof(buf) - 1);

    TEST_ASSERT(esp_heap.buf + esp_heap.len == end);

    p = esp_mbedtls_calloc(1, 1);
    q = esp_mbedtls_calloc(1, 128);
    r = esp_mbedtls_calloc(1, 16);

    TEST_ASSERT(esp_check_pointer(p) == 0 &&
                esp_check_pointer(q) == 0 &&
                esp_check_pointer(r) == 0);

    esp_mbedtls_free(r);
    esp_mbedtls_free(q);
    esp_mbedtls_free(p);

    TEST_ASSERT(esp_check_all_free() == 0);

    esp_mbedtls_memory_buffer_alloc_free();

    if (verbose != 0) {
        esp_mbedtls_printf("passed\n");
    }

    if (verbose != 0) {
        esp_mbedtls_printf("  MBA test #3 (full): ");
    }

    esp_mbedtls_memory_buffer_alloc_init(buf, sizeof(buf));

    p = esp_mbedtls_calloc(1, sizeof(buf) - sizeof(memory_header));

    TEST_ASSERT(esp_check_pointer(p) == 0);
    TEST_ASSERT(esp_mbedtls_calloc(1, 1) == NULL);

    esp_mbedtls_free(p);

    p = esp_mbedtls_calloc(1, sizeof(buf) - 2 * sizeof(memory_header) - 16);
    q = esp_mbedtls_calloc(1, 16);

    TEST_ASSERT(esp_check_pointer(p) == 0 && esp_check_pointer(q) == 0);
    TEST_ASSERT(esp_mbedtls_calloc(1, 1) == NULL);

    esp_mbedtls_free(q);

    TEST_ASSERT(esp_mbedtls_calloc(1, 17) == NULL);

    esp_mbedtls_free(p);

    TEST_ASSERT(esp_check_all_free() == 0);

    esp_mbedtls_memory_buffer_alloc_free();

    if (verbose != 0) {
        esp_mbedtls_printf("passed\n");
    }

cleanup:
    esp_mbedtls_memory_buffer_alloc_free();

    return ret;
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_MEMORY_BUFFER_ALLOC_C */
