/*
 *  Threading abstraction layer - pthreads implementation
 *
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_THREADING_C)

#include "mbedtls/threading.h"

#if defined(MBEDTLS_THREADING_PTHREAD)
void mbedtls_mutex_init( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL )
        return;

    mutex->is_valid = pthread_mutex_init( &mutex->mutex, NULL ) == 0;
}

void mbedtls_mutex_free( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL || !mutex->is_valid )
        return;

    (void) pthread_mutex_destroy( &mutex->mutex );
    mutex->is_valid = 0;
}

int mbedtls_mutex_lock( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL || ! mutex->is_valid )
        return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );

    if( pthread_mutex_lock( &mutex->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );

    return( 0 );
}

int mbedtls_mutex_unlock( mbedtls_threading_mutex_t *mutex )
{
    if( mutex == NULL || ! mutex->is_valid )
        return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );

    if( pthread_mutex_unlock( &mutex->mutex ) != 0 )
        return( MBEDTLS_ERR_THREADING_MUTEX_ERROR );

    return( 0 );
}

/*
 * With pthreads we can statically initialize mutexes
 */
#define MBEDTLS_MUTEX_INITIALIZER      { PTHREAD_MUTEX_INITIALIZER, 1 }


#elif defined(MBEDTLS_THREADING_ALT)

#if !defined(MBEDTLS_MUTEX_INIT_MACRO) && \
    !defined(MBEDTLS_MUTEX_FREE_MACRO) && \
    !defined(MBEDTLS_MUTEX_LOCK_MACRO) && \
    !defined(MBEDTLS_UNLOCK_FREE_MACRO)

static int threading_mutex_fail( mbedtls_threading_mutex_t *mutex )
{
    ((void) mutex );
    return( MBEDTLS_ERR_THREADING_BAD_INPUT_DATA );
}

static void threading_mutex_dummy( mbedtls_threading_mutex_t *mutex )
{
    ((void) mutex );
    return;
}

#define MBEDTLS_MUTEX_INIT_MACRO      threading_mutex_dummy
#define MBEDTLS_MUTEX_FREE_MACRO      threading_mutex_dummy
#define MBEDTLS_MUTEX_LOCK_MACRO      threading_mutex_fail
#define MBEDTLS_MUTEX_UNLOCK_MACRO    threading_mutex_fail

#endif /* !MBEDTLS_MUTEX_INIT_MACRO && !MBEDTLS_MUTEX_FREE_MACRO &&
        * !MBEDTLS_MUTEX_LOCK_MACRO && !MBEDTLS_UNLOCK_FREE_MACRO */

/*
 * Set functions pointers and initialize global mutexes
 */
void mbedtls_threading_set_alt( mbedtls_mutex_init_t* mutex_init,
                                mbedtls_mutex_free_t* mutex_free,
                                mbedtls_mutex_lock_t* mutex_lock,
                                mbedtls_mutex_unlock_t* mutex_unlock )
{
    mbedtls_mutex_init = mutex_init;
    mbedtls_mutex_free = mutex_free;
    mbedtls_mutex_lock = mutex_lock;
    mbedtls_mutex_unlock = mutex_unlock;

#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_init( &mbedtls_threading_readdir_mutex );
#endif /* MBEDTLS_FS_IO */

#if defined(MBEDTLS_HAVE_TIME_DATE)
    mbedtls_mutex_init( &mbedtls_threading_gmtime_mutex );
#endif /* MBEDTLS_HAVE_TIME_DATE */
}

/*
 * Free global mutexes
 */
void mbedtls_threading_free_alt( void )
{
#if defined(MBEDTLS_FS_IO)
    mbedtls_mutex_free( &mbedtls_threading_readdir_mutex );
#endif /* MBEDTLS_FS_IO */

#if defined(MBEDTLS_HAVE_TIME_DATE)
    mbedtls_mutex_free( &mbedtls_threading_gmtime_mutex );
#endif /* MBEDTLS_HAVE_TIME_DATE */
}

mbedtls_mutex_init_t* mbedtls_mutex_init =
                            (mbedtls_mutex_init_t*)MBEDTLS_MUTEX_INIT_MACRO;
mbedtls_mutex_free_t* mbedtls_mutex_free =
                            (mbedtls_mutex_free_t*)MBEDTLS_MUTEX_FREE_MACRO;
mbedtls_mutex_lock_t* mbedtls_mutex_lock =
                            (mbedtls_mutex_lock_t*)MBEDTLS_MUTEX_LOCK_MACRO;
mbedtls_mutex_unlock_t* mbedtls_mutex_unlock =
                            (mbedtls_mutex_unlock_t*)MBEDTLS_MUTEX_UNLOCK_MACRO;

#endif /* MBEDTLS_THREADING_ALT */

/*
 * Define global mutexes
 */
#if defined(MBEDTLS_MUTEX_INITIALIZER)

#if defined(MBEDTLS_FS_IO)
mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex = MBEDTLS_MUTEX_INITIALIZER;
#endif /* MBEDTLS_FS_IO */

#if defined(MBEDTLS_HAVE_TIME_DATE)
mbedtls_threading_mutex_t mbedtls_threading_gmtime_mutex = MBEDTLS_MUTEX_INITIALIZER;
#endif /* MBEDTLS_HAVE_TIME_DATE */

#else

#if defined(MBEDTLS_FS_IO)
mbedtls_threading_mutex_t mbedtls_threading_readdir_mutex;
#endif /* MBEDTLS_FS_IO */

#if defined(MBEDTLS_HAVE_TIME_DATE)
mbedtls_threading_mutex_t mbedtls_threading_gmtime_mutex;
#endif /* MBEDTLS_HAVE_TIME_DATE */

#endif /* MBEDTLS_MUTEX_INITIALIZER */

#endif /* MBEDTLS_THREADING_C */
