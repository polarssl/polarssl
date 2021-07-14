/**
 * \file common.h
 *
 * \brief Utility macros for internal use in the library
 */
/*
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

#ifndef MBEDTLS_LIBRARY_COMMON_H
#define MBEDTLS_LIBRARY_COMMON_H

#if defined(MBEDTLS_CONFIG_FILE)
#include MBEDTLS_CONFIG_FILE
#else
#include "mbedtls/config.h"
#endif

#include <stdint.h>

/** Helper to define a function as static except when building invasive tests.
 *
 * If a function is only used inside its own source file and should be
 * declared `static` to allow the compiler to optimize for code size,
 * but that function has unit tests, define it with
 * ```
 * MBEDTLS_STATIC_TESTABLE int mbedtls_foo(...) { ... }
 * ```
 * and declare it in a header in the `library/` directory with
 * ```
 * #if defined(MBEDTLS_TEST_HOOKS)
 * int mbedtls_foo(...);
 * #endif
 * ```
 */
#if defined(MBEDTLS_TEST_HOOKS)
#define MBEDTLS_STATIC_TESTABLE
#else
#define MBEDTLS_STATIC_TESTABLE static
#endif

/** Byte Reading Macros
 *
 * To tidy up code and save horizontal and vertical space, use byte
 * reading macros to cast
 */
#define MBEDTLS_BYTE_0( x ) ( (uint8_t) (   ( x )         & 0xff ) )
#define MBEDTLS_BYTE_1( x ) ( (uint8_t) ( ( ( x ) >> 8  ) & 0xff ) )
#define MBEDTLS_BYTE_2( x ) ( (uint8_t) ( ( ( x ) >> 16 ) & 0xff ) )
#define MBEDTLS_BYTE_3( x ) ( (uint8_t) ( ( ( x ) >> 24 ) & 0xff ) )
#define MBEDTLS_BYTE_4( x ) ( (uint8_t) ( ( ( x ) >> 32 ) & 0xff ) )
#define MBEDTLS_BYTE_5( x ) ( (uint8_t) ( ( ( x ) >> 40 ) & 0xff ) )
#define MBEDTLS_BYTE_6( x ) ( (uint8_t) ( ( ( x ) >> 48 ) & 0xff ) )
#define MBEDTLS_BYTE_7( x ) ( (uint8_t) ( ( ( x ) >> 56 ) & 0xff ) )

/**
 * Get the unsigned 32 bits integer corresponding to four bytes in
 * big-endian order (MSB first).
 *
 * \param   data    Base address of the memory to get the four bytes from.
 * \param   offset  Offset from \p base of the first and most significant
 *                  byte of the four bytes to build the 32 bits unsigned
 *                  integer from.
 */
#ifndef MBEDTLS_GET_UINT32_BE
#define MBEDTLS_GET_UINT32_BE( data , offset )              \
    (                                                       \
          ( (uint32_t) ( data )[( offset )    ] << 24 )     \
        | ( (uint32_t) ( data )[( offset ) + 1] << 16 )     \
        | ( (uint32_t) ( data )[( offset ) + 2] <<  8 )     \
        | ( (uint32_t) ( data )[( offset ) + 3]       )     \
    )
#endif

/**
 * Put in memory a 32 bits unsigned integer in big-endian order.
 *
 * \param   n       32 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 32
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the most significant
 *                  byte of the 32 bits unsigned integer \p n.
 */
#ifndef MBEDTLS_PUT_UINT32_BE
#define MBEDTLS_PUT_UINT32_BE( n, data, offset )                    \
    do {                                                            \
        ( data )[( offset )    ] = (unsigned char) ( (n) >> 24 );   \
        ( data )[( offset ) + 1] = (unsigned char) ( (n) >> 16 );   \
        ( data )[( offset ) + 2] = (unsigned char) ( (n) >>  8 );   \
        ( data )[( offset ) + 3] = (unsigned char) ( (n)       );   \
    } while( 0 )
#endif

/**
 * Get the unsigned 32 bits integer corresponding to four bytes in
 * little-endian order (LSB first).
 *
 * \param   data    Base address of the memory to get the four bytes from.
 * \param   offset  Offset from \p base of the first and least significant
 *                  byte of the four bytes to build the 32 bits unsigned
 *                  integer from.
 */
#ifndef MBEDTLS_GET_UINT32_LE
#define MBEDTLS_GET_UINT32_LE( data, offset )              \
    (                                                      \
          ( (uint32_t) ( data )[( offset )    ]       )    \
        | ( (uint32_t) ( data )[( offset ) + 1] <<  8 )    \
        | ( (uint32_t) ( data )[( offset ) + 2] << 16 )    \
        | ( (uint32_t) ( data )[( offset ) + 3] << 24 )    \
    )
#endif

/**
 * Put in memory a 32 bits unsigned integer in little-endian order.
 *
 * \param   n       32 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 32
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the least significant
 *                  byte of the 32 bits unsigned integer \p n.
 */
#ifndef MBEDTLS_PUT_UINT32_LE
#define MBEDTLS_PUT_UINT32_LE( n, data, offset )                                \
    do {                                                                        \
        ( data )[( offset )    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
        ( data )[( offset ) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
        ( data )[( offset ) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
        ( data )[( offset ) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
    } while( 0 )
#endif

/**
 * Get the unsigned 16 bits integer corresponding to two bytes in
 * little-endian order (LSB first).
 *
 * \param   data    Base address of the memory to get the two bytes from.
 * \param   offset  Offset from \p base of the first and least significant
 *                  byte of the two bytes to build the 16 bits unsigned
 *                  integer from.
 */
#ifndef MBEDTLS_GET_UINT16_LE
#define MBEDTLS_GET_UINT16_LE( data, offset )               \
    (                                                       \
          ( (uint16_t) ( data )[( offset )    ]       )     \
        | ( (uint16_t) ( data )[( offset ) + 1] <<  8 )     \
    )
#endif

/**
 * Put in memory a 16 bits unsigned integer in little-endian order.
 *
 * \param   n       16 bits unsigned integer to put in memory.
 * \param   data    Base address of the memory where to put the 16
 *                  bits unsigned integer in.
 * \param   offset  Offset from \p base where to put the least significant
 *                  byte of the 16 bits unsigned integer \p n.
 */
#ifndef MBEDTLS_PUT_UINT16_LE
#define MBEDTLS_PUT_UINT16_LE( n, data, offset )                            \
{                                                                           \
    ( data )[( offset )    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    ( data )[( offset ) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
}
#endif

#endif /* MBEDTLS_LIBRARY_COMMON_H */
