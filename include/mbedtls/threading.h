/**
 * \file threading.h
 *
 * \brief Threading abstraction layer
 */
/*
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_THREADING_H
#define MBEDTLS_THREADING_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_THREADING_C)

#define MBEDTLS_ERR_THREADING_FEATURE_UNAVAILABLE   -0x001A
                            /**< The selected feature is not available. */
#define MBEDTLS_ERR_THREADING_BAD_INPUT_DATA        -0x001C
                            /**< Bad input parameters to function. */
#define MBEDTLS_ERR_THREADING_MUTEX_ERROR           -0x001E
                            /**< Locking / unlocking / free failed with
                             * error code. */


#if defined(MBEDTLS_THREADING_ALT)

/* You should define the mbedtls_threading_mutex_t type in your header */
#include "threading_alt.h"

#elif defined(MBEDTLS_THREADING_PTHREAD)
/* pthreads implementation of the threading primitives */

#include <pthread.h>
typedef struct _mbedtls_threading_mutex_t
{
    pthread_mutex_t mutex;
    char is_valid;
} mbedtls_threading_mutex_t;

#else

/* For no given implementation, define as an opaque pointer */
typedef struct _mbedtls_threading_mutex_t
{
    void* mutex;
} mbedtls_threading_mutex_t;

#endif /* !MBEDTLS_THREADING_ALT && !MBEDTLS_THREADING_PTHREAD */

#if !defined(MBEDTLS_THREADING_ALT)

/**
 * \brief          Initialize mutex
 *
 * \param mutex    Pointer to mutex to initialize
 *
 * \note           The function initializes the passed mutex.
 *
 * \note           The implementation may be provided by the user application,
 *                 if MBEDTLS_THREADING_ALT or MBEDTLS_MUTEX_XXX_MACRO symbols
 *                 are defined.
 */
void mbedtls_mutex_init( mbedtls_threading_mutex_t *mutex );

/**
 * \brief          Free mutex
 *
 * \param mutex    Pointer to mutex to deallocate
 *
 * \note           The function deallocates the passed mutex.
 *
 * \note           The implementation may be provided by the user application,
 *                 if MBEDTLS_THREADING_ALT or MBEDTLS_MUTEX_XXX_MACRO symbols
 *                 are defined.
 */
void mbedtls_mutex_free( mbedtls_threading_mutex_t *mutex );

/**
 * \brief          Lock mutex
 *
 * \param mutex    Pointer to mutex to lock
 *
 * \note           The function locks the passed mutex.
 *
 * \note           The implementation may be provided by the user application,
 *                 if MBEDTLS_THREADING_ALT or MBEDTLS_MUTEX_XXX_MACRO symbols
 *                 are defined.
 */
int mbedtls_mutex_lock( mbedtls_threading_mutex_t *mutex );

/**
 * \brief          Unlock mutex
 *
 * \param mutex    Pointer to mutex to unlock
 *
 * \note           The function unlocks the passed mutex.
 *
 * \note           The implementation may be provided by the user application,
 *                 if MBEDTLS_THREADING_ALT or MBEDTLS_MUTEX_XXX_MACRO symbols
 *                 are defined.
 */
int mbedtls_mutex_unlock( mbedtls_threading_mutex_t *mutex );

#else

/**
 * \brief          Pointer to initialize mutex function
 *
 * \param mutex    Pointer to mutex to initialize
 *
 */
typedef void (mbedtls_mutex_init_t)( mbedtls_threading_mutex_t* mutex );

/**
 * \brief          Pointer to free mutex function
 *
 * \param mutex    Pointer to mutex to deallocate
 *
 */
typedef void (mbedtls_mutex_free_t)( mbedtls_threading_mutex_t* );

/**
 * \brief          Pointer to lock mutex function
 *
 * \param mutex    Pointer to mutex to lock
 *
 */
typedef int (mbedtls_mutex_lock_t)( mbedtls_threading_mutex_t* );

/**
 * \brief          Pointer to unlock mutex function
 *
 * \param mutex    Pointer to mutex to unlock
 *
 */
typedef int (mbedtls_mutex_unlock_t)( mbedtls_threading_mutex_t* );

/**
 * \brief           Set your alternate threading implementation function
 *                  pointers and initialize global mutexes. If used, this
 *                  function must be called once in the main thread before any
 *                  other mbed TLS function is called, and
 *                  mbedtls_threading_free_alt() must be called once in the main
 *                  thread after all other mbed TLS functions.
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
void mbedtls_threading_set_alt( mbedtls_mutex_init_t* mutex_init,
                                mbedtls_mutex_free_t* mutex_free,
                                mbedtls_mutex_lock_t* mutex_lock,
                                mbedtls_mutex_unlock_t* mutex_unlock );

/**
 * \brief               Free global mutexes.
 */
void mbedtls_threading_free_alt( void );

/*
 * The function pointers for mutex_init, mutex_free, mutex_lock and mutex_unlock
 *
 * All these functions are expected to work or the result will be undefined.
 */
extern void (*mbedtls_mutex_init)( mbedtls_threading_mutex_t *mutex );
extern void (*mbedtls_mutex_free)( mbedtls_threading_mutex_t *mutex );
extern int (*mbedtls_mutex_lock)( mbedtls_threading_mutex_t *mutex );
extern int (*mbedtls_mutex_unlock)( mbedtls_threading_mutex_t *mutex );

#endif /* MBEDTLS_THREADING_ALT */

/*
 * Global mutexes
 */
extern mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex;
extern mbedtls_threading_mutex_t mbedtls_threading_gmtime_mutex;

#endif /* MBEDTLS_THREADING_C */

#ifdef __cplusplus
}
#endif

#endif /* threading.h */
