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

/** Allow library to access its structs' private members.
 *
 * Although structs defined in header files are publicly available,
 * their members are private and should not be accessed by the user.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

/** Byte Reading Macros
 *
 * Obtain the most significant byte of x using 0xff
 * Using MBEDTLS_BYTE_a will shift a*8 bits
 * to retrieve the next byte of information
 */
#define MBEDTLS_BYTE_0( x ) ( (uint8_t) ( ( x ) & 0xff ) )
#define MBEDTLS_BYTE_1( x ) ( (uint8_t) ( ( ( x ) >> 8  ) & 0xff ) )
#define MBEDTLS_BYTE_2( x ) ( (uint8_t) ( ( ( x ) >> 16 ) & 0xff ) )
#define MBEDTLS_BYTE_3( x ) ( (uint8_t) ( ( ( x ) >> 24 ) & 0xff ) )

/**
 * 32-bit integer manipulation macros
 *
 * \brief   Using GET-
 *          From input data, take the most significant bytes
 *          and concatonate them as you shift along
 *          Using PUT-
 *          Read from a 32 bit integer and store each byte
 *          in memory, offset by a byte each, resulting in
 *          each byte being adjacent in memory.
 *
 * \param   n   32 bit integer where data is accessed via
 *              PUT or stored using GET
 * \param   b   const unsigned char array of data to be
 *              manipulated
 * \param   i   offset in bytes, In the case of UINT32, i
 *              would increment by 4 every use assuming
 *              the data is being stored in the same location
 */

/**
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef MBEDTLS_GET_UINT32_BE
#define MBEDTLS_GET_UINT32_BE(n,b,i)                    \
    do {                                                \
        (n) = ( (uint32_t) (b)[(i)    ] << 24 )         \
            | ( (uint32_t) (b)[(i) + 1] << 16 )         \
            | ( (uint32_t) (b)[(i) + 2] <<  8 )         \
            | ( (uint32_t) (b)[(i) + 3]       );        \
    } while( 0 )
#endif

#ifndef MBEDTLS_PUT_UINT32_BE
#define MBEDTLS_PUT_UINT32_BE(n,b,i)                    \
    do {                                                \
        (b)[(i)    ] = (unsigned char) ( (n) >> 24 );   \
        (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );   \
        (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );   \
        (b)[(i) + 3] = (unsigned char) ( (n)       );   \
    } while( 0 )
#endif

/**
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef MBEDTLS_GET_UINT32_LE
#define MBEDTLS_GET_UINT32_LE(n,b,i)                    \
    do {                                                \
        (n) = ( (uint32_t) (b)[(i)    ]       )         \
            | ( (uint32_t) (b)[(i) + 1] <<  8 )         \
            | ( (uint32_t) (b)[(i) + 2] << 16 )         \
            | ( (uint32_t) (b)[(i) + 3] << 24 );        \
    } while( 0 )
#endif

#ifndef MBEDTLS_PUT_UINT32_LE
#define MBEDTLS_PUT_UINT32_LE(n,b,i)                                \
    do {                                                            \
        (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
        (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
        (b)[(i) + 2] = (unsigned char) ( ( (n) >> 16 ) & 0xFF );    \
        (b)[(i) + 3] = (unsigned char) ( ( (n) >> 24 ) & 0xFF );    \
    } while( 0 )
#endif

/**
 * 32-bit integer conversion from bytes (little endian)
 */
#define MBEDTLS_BYTES_TO_U32_LE( data, offset )                 \
    ( (uint32_t) (data)[offset]                                 \
      | (uint32_t) ( (uint32_t) (data)[( offset ) + 1] << 8 )   \
      | (uint32_t) ( (uint32_t) (data)[( offset ) + 2] << 16 )  \
      | (uint32_t) ( (uint32_t) (data)[( offset ) + 3] << 24 )  \
    )

/**
 * 16-bit integer manipulation macros
 *
 * \brief   Using GET-
 *          From input data, take the most significant bytes
 *          and concatonate them as you shift along
 *          Using PUT-
 *          Read from a 16 bit integer and store each byte
 *          in memory, offset by a byte each, resulting in
 *          each byte being adjacent in memory.
 *
 * \param   n   16 bit integer where data is accessed via
 *              PUT or stored using GET
 * \param   b   const unsigned char array of data to be
 *              manipulated
 * \param   i   offset in bytes, In the case of UINT16, i
 *              would increment by 2 every use assuming
 *              the data is being stored in the same location
 */

/**
 * 16-bit integer manipulation macros (little endian)
 */
#ifndef MBEDTLS_GET_UINT16_LE
#define MBEDTLS_GET_UINT16_LE( n, b, i )                \
{                                                       \
    (n) = ( (uint16_t) (b)[(i)    ]       )             \
        | ( (uint16_t) (b)[(i) + 1] <<  8 );            \
}
#endif

#ifndef MBEDTLS_PUT_UINT16_LE
#define MBEDTLS_PUT_UINT16_LE( n, b, i )                        \
{                                                               \
    (b)[(i)    ] = (unsigned char) ( ( (n)       ) & 0xFF );    \
    (b)[(i) + 1] = (unsigned char) ( ( (n) >>  8 ) & 0xFF );    \
}
#endif


#endif /* MBEDTLS_LIBRARY_COMMON_H */
