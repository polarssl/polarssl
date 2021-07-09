/*
 *  Platform-specific and custom entropy polling functions
 *
 *  Copyright The Mbed TLS Contributors
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
 */

#if defined(__linux__) && !defined(_GNU_SOURCE)
/* Ensure that syscall() is available even when compiling with -std=c99 */
#define _GNU_SOURCE
#endif

#include "common.h"

#include <string.h>

#if defined(MBEDTLS_ENTROPY_C)

#include "mbedtls/entropy.h"
#include "entropy_poll.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_TIMING_C)
#include "mbedtls/timing.h"
#endif
#if defined(MBEDTLS_ENTROPY_NV_SEED)
#include "mbedtls/platform.h"
#endif

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)

#if !defined(unix) && !defined(__unix__) && !defined(__unix) && \
    !defined(__APPLE__) && !defined(_WIN32) && !defined(__QNXNTO__) && \
    !defined(__HAIKU__) && !defined(__midipix__)
#error "Platform entropy sources only work on Unix and Windows, see MBEDTLS_NO_PLATFORM_ENTROPY in mbedtls_config.h"
#endif

#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)

#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0400
#endif
#include <windows.h>
#include <wincrypt.h>

int mbedtls_platform_entropy_poll( void *data, unsigned char *output, size_t len,
                           size_t *olen )
{
    HCRYPTPROV provider;
    ((void) data);
    *olen = 0;

    if( CryptAcquireContext( &provider, NULL, NULL,
                              PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) == FALSE )
    {
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    if( CryptGenRandom( provider, (DWORD) len, output ) == FALSE )
    {
        CryptReleaseContext( provider, 0 );
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    CryptReleaseContext( provider, 0 );
    *olen = len;

    return( 0 );
}
#else /* _WIN32 && !EFIX64 && !EFI32 */

/*
 * Test for Linux getrandom() support.
 * Since there is no wrapper in the libc yet, use the generic syscall wrapper
 * available in GNU libc and compatible libc's (eg uClibc).
 */
#if ((defined(__linux__) && defined(__GLIBC__)) || defined(__midipix__))
#include <unistd.h>
#include <sys/syscall.h>
#if defined(SYS_getrandom)
#define HAVE_GETRANDOM
#include <errno.h>

static int getrandom_wrapper( void *buf, size_t buflen, unsigned int flags )
{
    /* MemSan cannot understand that the syscall writes to the buffer */
#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
    memset( buf, 0, buflen );
#endif
#endif
    return( syscall( SYS_getrandom, buf, buflen, flags ) );
}
#endif /* SYS_getrandom */
#endif /* __linux__ || __midipix__ */

#if defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/param.h>
#if (defined(__FreeBSD__) && __FreeBSD_version >= 1200000) || \
    (defined(__DragonFly__) && __DragonFly_version >= 500700)
#include <errno.h>
#include <sys/random.h>
#define HAVE_GETRANDOM
static int getrandom_wrapper( void *buf, size_t buflen, unsigned int flags )
{
    return getrandom( buf, buflen, flags );
}
#endif /* (__FreeBSD__ && __FreeBSD_version >= 1200000) ||
          (__DragonFly__ && __DragonFly_version >= 500700) */
#endif /* __FreeBSD__ || __DragonFly__ */

/*
 * Some BSD systems provide KERN_ARND.
 * This is equivalent to reading from /dev/urandom, only it doesn't require an
 * open file descriptor, and provides up to 256 bytes per call (basically the
 * same as getentropy(), but with a longer history).
 *
 * Documentation: https://netbsd.gw.com/cgi-bin/man-cgi?sysctl+7
 */
#if (defined(__FreeBSD__) || defined(__NetBSD__)) && !defined(HAVE_GETRANDOM)
#include <sys/param.h>
#include <sys/sysctl.h>
#if defined(KERN_ARND)
#define HAVE_SYSCTL_ARND

static int sysctl_arnd_wrapper( unsigned char *buf, size_t buflen )
{
    int name[2];
    size_t len;

    name[0] = CTL_KERN;
    name[1] = KERN_ARND;

    while( buflen > 0 )
    {
        len = buflen > 256 ? 256 : buflen;
        if( sysctl(name, 2, buf, &len, NULL, 0) == -1 )
            return( -1 );
        buflen -= len;
        buf += len;
    }
    return( 0 );
}
#endif /* KERN_ARND */
#endif /* __FreeBSD__ || __NetBSD__ */

#if defined(__APPLE__)
#include <sys/random.h>
#define HAVE_GETENTROPY

static int getentropy_wrapper( void *buf, size_t buflen )
{
     size_t len = 0;
     unsigned char *p = buf;
     while (buflen > 0)
     {
         len = buflen > 256 ? 256 : buflen;
         if( getentropy( p, len ) != 0 )
             return ( -1 );
         buflen -= len;
         p += len;
     }
     return( 0 );
}
#endif /* __APPLE__ */

#include <stdio.h>

int mbedtls_platform_entropy_poll( void *data,
                           unsigned char *output, size_t len, size_t *olen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    ((void) data);

#if defined(HAVE_GETRANDOM)
    ret = getrandom_wrapper( output, len, 0 );
    if( ret >= 0 )
    {
        *olen = ret;
        return( 0 );
    }
    else if( errno != ENOSYS )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    else
        return( ret );
#endif /* HAVE_GETRANDOM */

#if defined(HAVE_GETENTROPY)
    ret = getentropy_wrapper( output, len );
    if( ret == 0 )
    {
        *olen = len;
        return( 0 );
    }
    else /* only a bad buffer address would lead to it */
        return( MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED );
#endif /* HAVE_GETENTROPY */

#if defined(HAVE_SYSCTL_ARND)
    ret = sysctl_arnd_wrapper( output, len );
    if ( ret == -1 )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    *olen = len;
    return( 0 );
#endif /* HAVE_SYSCTL_ARND */

/* Fallback */
#if !defined(HAVE_GETRANDOM) && !defined(HAVE_GETENTROPY) && !defined(HAVE_SYSCTL_ARND)
    FILE *file;
    size_t read_len;

    *olen = 0;

    file = fopen( "/dev/urandom", "rb" );
    if( file == NULL )
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    read_len = fread( output, 1, len, file );
    if( read_len != len )
    {
        fclose( file );
        return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );
    }

    fclose( file );
    *olen = len;

    return( 0 );
#endif /* !HAVE_GETRANDOM && !HAVE_GETENTROPY && !HAVE_SYSCTL_ARND */
}
#endif /* _WIN32 && !EFIX64 && !EFI32 */
#endif /* !MBEDTLS_NO_PLATFORM_ENTROPY */

#if defined(MBEDTLS_ENTROPY_NV_SEED)
int mbedtls_nv_seed_poll( void *data,
                          unsigned char *output, size_t len, size_t *olen )
{
    unsigned char buf[MBEDTLS_ENTROPY_BLOCK_SIZE];
    size_t use_len = MBEDTLS_ENTROPY_BLOCK_SIZE;
    ((void) data);

    memset( buf, 0, MBEDTLS_ENTROPY_BLOCK_SIZE );

    if( mbedtls_nv_seed_read( buf, MBEDTLS_ENTROPY_BLOCK_SIZE ) < 0 )
      return( MBEDTLS_ERR_ENTROPY_SOURCE_FAILED );

    if( len < use_len )
      use_len = len;

    memcpy( output, buf, use_len );
    *olen = use_len;

    return( 0 );
}
#endif /* MBEDTLS_ENTROPY_NV_SEED */

#endif /* MBEDTLS_ENTROPY_C */
