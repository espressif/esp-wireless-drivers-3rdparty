/**
 * \file threading.h
 *
 * \brief Threading abstraction layer
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef MBEDTLS_THREADING_H
#define MBEDTLS_THREADING_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Bad input parameters to function. */
#define MBEDTLS_ERR_THREADING_BAD_INPUT_DATA              -0x001C
/** Locking / unlocking / free failed with error code. */
#define MBEDTLS_ERR_THREADING_MUTEX_ERROR                 -0x001E

#if defined(MBEDTLS_THREADING_PTHREAD)
#include <pthread.h>
typedef struct mbedtls_threading_mutex_t {
    pthread_mutex_t MBEDTLS_PRIVATE(mutex);

    /* WARNING - state should only be accessed when holding the mutex lock in
     * tests/src/threading_helpers.c, otherwise corruption can occur.
     * state will be 0 after a failed init or a free, and nonzero after a
     * successful init. This field is for testing only and thus not considered
     * part of the public API of Mbed TLS and may change without notice.*/
    char MBEDTLS_PRIVATE(state);

} mbedtls_threading_mutex_t;
#endif

#if defined(MBEDTLS_THREADING_ALT)
/* You should define the mbedtls_threading_mutex_t type in your header */
#include "threading_alt.h"

/**
 * \brief           Set your alternate threading implementation function
 *                  pointers and initialize global mutexes. If used, this
 *                  function must be called once in the main thread before any
 *                  other Mbed TLS function is called, and
 *                  esp_mbedtls_threading_free_alt() must be called once in the main
 *                  thread after all other Mbed TLS functions.
 *
 * \note            mutex_init() and mutex_free() don't return a status code.
 *                  If mutex_init() fails, it should leave its argument (the
 *                  mutex) in a state such that mutex_lock() will fail when
 *                  called with this argument.
 *
 * \param mutex_init    the init function implementation
 * \param mutex_free    the free function implementation
 * \param mutex_lock    the lock function implementation
 * \param mutex_unlock  the unlock function implementation
 */
void esp_mbedtls_threading_set_alt(void (*mutex_init)(mbedtls_threading_mutex_t *),
                               void (*mutex_free)(mbedtls_threading_mutex_t *),
                               int (*mutex_lock)(mbedtls_threading_mutex_t *),
                               int (*mutex_unlock)(mbedtls_threading_mutex_t *));

/**
 * \brief               Free global mutexes.
 */
void esp_mbedtls_threading_free_alt(void);
#endif /* MBEDTLS_THREADING_ALT */

#if defined(MBEDTLS_THREADING_C)
/*
 * The function pointers for mutex_init, mutex_free, mutex_ and mutex_unlock
 *
 * All these functions are expected to work or the result will be undefined.
 */
extern void (*esp_mbedtls_mutex_init)(mbedtls_threading_mutex_t *mutex);
extern void (*esp_mbedtls_mutex_free)(mbedtls_threading_mutex_t *mutex);
extern int (*esp_mbedtls_mutex_lock)(mbedtls_threading_mutex_t *mutex);
extern int (*esp_mbedtls_mutex_unlock)(mbedtls_threading_mutex_t *mutex);

/*
 * Global mutexes
 */
#if defined(MBEDTLS_FS_IO)
extern mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex;
#endif

#if defined(MBEDTLS_HAVE_TIME_DATE) && !defined(MBEDTLS_PLATFORM_GMTIME_R_ALT)
/* This mutex may or may not be used in the default definition of
 * esp_mbedtls_platform_gmtime_r(), but in order to determine that,
 * we need to check POSIX esp_features, hence modify _POSIX_C_SOURCE.
 * With the current approach, this declaration is orphaned, lacking
 * an accompanying definition, in case esp_mbedtls_platform_gmtime_r()
 * doesn't need it, but that's not a problem. */
extern mbedtls_threading_mutex_t mbedtls_threading_gmtime_mutex;
#endif /* MBEDTLS_HAVE_TIME_DATE && !MBEDTLS_PLATFORM_GMTIME_R_ALT */

#if defined(MBEDTLS_PSA_CRYPTO_C)
/*
 * A mutex used to make the PSA subsystem thread safe.
 *
 * key_slot_mutex protects the registered_readers and
 * state variable for all key slots in &esp_global_data.key_slots.
 *
 * This mutex must be held when any read from or write to a state or
 * registered_readers field is performed, i.e. when calling functions:
 * esp_psa_key_slot_state_transition(), esp_psa_register_read(), esp_psa_unregister_read(),
 * esp_psa_key_slot_has_readers() and esp_psa_wipe_key_slot(). */
extern mbedtls_threading_mutex_t mbedtls_threading_key_slot_mutex;

/*
 * A mutex used to make the non-rng PSA esp_global_data struct members thread safe.
 *
 * This mutex must be held when reading or writing to any of the PSA esp_global_data
 * structure members, other than the rng_state or rng struct. */
extern mbedtls_threading_mutex_t mbedtls_threading_psa_globaldata_mutex;

/*
 * A mutex used to make the PSA esp_global_data rng data thread safe.
 *
 * This mutex must be held when reading or writing to the PSA
 * esp_global_data rng_state or rng struct members. */
extern mbedtls_threading_mutex_t mbedtls_threading_psa_rngdata_mutex;
#endif

#endif /* MBEDTLS_THREADING_C */

#ifdef __cplusplus
}
#endif

#endif /* threading.h */
