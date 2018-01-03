/*
 *  SM4 Implementation
 *
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
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

/*
 *  Chinese standard block cipher SM4 (GB/T 32907-2016).
 *  SM4 has a 128-bit block size and a 128-bit key only.
 *  Test vectors from draft-ribose-cfrg-sm4-02 (they're perhaps not the best).
 */

#if !defined( MBEDTLS_CONFIG_FILE )
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined( MBEDTLS_SM4_C )

#include "mbedtls/sm4.h"

#if defined( MBEDTLS_SELF_TEST )
#include <string.h>
#if defined( MBEDTLS_PLATFORM_C )
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */


// 32-bit integer manipulation macros ( big endian / network byte order )

#ifndef GET_UINT32_BE
#define GET_UINT32_BE( n,b,i )                  \
{                                               \
    (n) = ( (uint32_t) ( b )[( i )    ] << 24 ) \
        | ( (uint32_t) ( b )[( i ) + 1] << 16 ) \
        | ( (uint32_t) ( b )[( i ) + 2] <<  8 ) \
        | ( (uint32_t) ( b )[( i ) + 3]     );  \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE( n,b,i )                  \
{                                               \
    ( b )[( i )    ] = (uint8_t) ( (n) >> 24 ); \
    ( b )[( i ) + 1] = (uint8_t) ( (n) >> 16 ); \
    ( b )[( i ) + 2] = (uint8_t) ( (n) >>  8 ); \
    ( b )[( i ) + 3] = (uint8_t) ( (n)       ); \
}
#endif

// Cyclic rotation

#ifndef ROTL32
#define ROTL32( x, y ) ( ( (x) << (y) ) | ( (x) >> ( 32 - (y) ) ) )
#endif

// SM4 nonlinear tau function -- 4 simultaneous S-Box lookups

#define SM4_TAU(x) ( ( (uint32_t) sm4_sbox[(x) & 0xFF] ) |                   \
                   ( ( (uint32_t) sm4_sbox[( (x) >> 8 ) & 0xFF] ) << 8 ) |   \
                   ( ( (uint32_t) sm4_sbox[( (x) >> 16 ) & 0xFF] ) << 16 ) | \
                   ( ( (uint32_t) sm4_sbox[(x) >> 24] << 24 ) ) )

// SM4 linear operations ( bijective )

#define SM4_L1(x)   ( (x) ^ ROTL32( x, 2 ) ^ ROTL32( x, 10 ) ^ \
                    ROTL32( x, 18 ) ^ ROTL32( x, 24 ) )

#define SM4_L2(x)   ( (x) ^ ROTL32( x, 13 ) ^ ROTL32( x, 23 ) )

// The SM4 S-box

static const unsigned char sm4_sbox[0x100] =
{
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7,
    0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A,
    0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95,
    0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B,
    0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2,
    0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87,
    0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E,
    0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5,
    0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55,
    0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3,
    0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F,
    0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F,
    0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F,
    0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8,
    0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0,
    0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E,
    0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20,
    0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48
};

// helpers

void mbedtls_sm4_init( mbedtls_sm4_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_sm4_context ) );
}

void mbedtls_sm4_free( mbedtls_sm4_context *ctx )
{
    if( ctx == NULL )
        return;
    mbedtls_sm4_init( ctx );
}

// Key schedule

int mbedtls_sm4_setkey_enc( mbedtls_sm4_context *ctx,
                            const unsigned char *key,
                            unsigned int keybits )
{
    int i;
    uint32_t t0, t1, t2, t3, x, ck;

    if( keybits != 128 )
        return MBEDTLS_ERR_SM4_INVALID_KEY_LENGTH;

    GET_UINT32_BE( t0, key, 0 );            // get the key
    GET_UINT32_BE( t1, key, 4 );
    GET_UINT32_BE( t2, key, 8 );
    GET_UINT32_BE( t3, key, 12 );

    t0 ^= 0xA3B1BAC6;                       // constant "family key"
    t1 ^= 0x56AA3350;
    t2 ^= 0x677D9197;
    t3 ^= 0xB27022DC;

    ck = 0x00040C14;                        // round constant generation

    for( i = 0; i < 32; i++ )
    {
        x = t1 ^ t2 ^ t3 ^ ck ^ 0x00030201;
        x = SM4_TAU(x);
        x = SM4_L2(x);
        x ^= t0;
        ctx->rk[i] = x;                     // store the round key

        t0 = t1;                            // shift keys
        t1 = t2;
        t2 = t3;
        t3 = x;

        ck = ( ck + 0x1C1C1C1C ) & 0xFCFCFCFC;
    }

    return 0;
}

// set up decryption key

int mbedtls_sm4_setkey_dec( mbedtls_sm4_context *ctx,
                            const unsigned char *key,
                            unsigned int keybits )
{
    int i;
    uint32_t x;

    if( ( i = mbedtls_sm4_setkey_enc( ctx, key, keybits ) ) != 0 )
        return i;

    for( i = 0; i < 16; i++ ) {             // reverse the key order
        x = ctx->rk[i];
        ctx->rk[i] = ctx->rk[31 - i];
        ctx->rk[31 - i] = x;
    }

    return 0;
}

// SM4-ECB  Electronic Codebook Mode  Encryption/Decryption

int mbedtls_sm4_crypt_ecb( mbedtls_sm4_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] )
{
    uint32_t t0, t1, t2, t3, x, i;

    ( (void) mode );                        // parameter not used

    GET_UINT32_BE( t0, input, 0 );          // input
    GET_UINT32_BE( t1, input, 4 );
    GET_UINT32_BE( t2, input, 8 );
    GET_UINT32_BE( t3, input, 12 );

    for( i = 0; i < 32; )
    {
        x = t1 ^ t2 ^ t3 ^ ctx->rk[i++];    // unrolled
        x = SM4_TAU(x);
        x = SM4_L1(x);
        t0 ^= x;

        x = t0 ^ t2 ^ t3 ^ ctx->rk[i++];
        x = SM4_TAU(x);
        x = SM4_L1(x);
        t1 ^= x;

        x = t0 ^ t1 ^ t3 ^ ctx->rk[i++];
        x = SM4_TAU(x);
        x = SM4_L1(x);
        t2 ^= x;

        x = t0 ^ t1 ^ t2 ^ ctx->rk[i++];
        x = SM4_TAU(x);
        x = SM4_L1(x);
        t3 ^= x;
    }

    PUT_UINT32_BE( t3, output, 0 );         // output in reverse order
    PUT_UINT32_BE( t2, output, 4 );
    PUT_UINT32_BE( t1, output, 8 );
    PUT_UINT32_BE( t0, output, 12 );

    return 0;
}

#if defined( MBEDTLS_SELF_TEST )

// Test ECB

static int sm4_self_test_ecb( int verbose )
{
    // key and plaintext
    const unsigned char test_in[16] =
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const unsigned char test_ct[16] =
    {
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
        0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
    };

    mbedtls_sm4_context ctx;
    unsigned char blk[16];

    // ECB encryption test

    if( verbose )
        mbedtls_printf( "  SM4-ECB-128 (enc): ");
    mbedtls_sm4_setkey_enc( &ctx, test_in, 128 );
    memset( blk, 0, sizeof( blk ) );
    mbedtls_sm4_crypt_ecb( &ctx, MBEDTLS_SM4_ENCRYPT, test_in, blk );
    if( memcmp( blk, test_ct, 16 ) != 0 )
    {
        if( verbose )
            mbedtls_printf( "failed\n" );
        return 1;
    }
    if( verbose )
        mbedtls_printf( "passed\n" );

    // ECB decryption test

    if( verbose )
        mbedtls_printf( "  SM4-ECB-128 (dec): ");
    mbedtls_sm4_setkey_dec( &ctx, test_in, 128 );
    memset( blk, 0, sizeof( blk ) );
    mbedtls_sm4_crypt_ecb( &ctx, MBEDTLS_SM4_DECRYPT, test_ct, blk );
    if( memcmp( blk, test_in, 16 ) != 0 )
    {
        if( verbose )
            mbedtls_printf( "failed\n" );
        return 1;
    }
    if( verbose )
        mbedtls_printf( "passed\n\n" );

    return 0;
}
#endif /* MBEDTLS_SELF_TEST */


#if defined( MBEDTLS_CIPHER_MODE_CBC )

/*
 * SM4-CBC encryption/decryption
 */

int mbedtls_sm4_crypt_cbc( mbedtls_sm4_context *ctx,
                            int mode,
                            size_t length,
                            unsigned char iv[16],
                            const unsigned char *input,
                            unsigned char *output )
{
    int i;
    unsigned char temp[16];

    if( length % 16 != 0 )
        return( MBEDTLS_ERR_SM4_INVALID_INPUT_LENGTH );

    if( mode == MBEDTLS_SM4_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, 16 );
            mbedtls_sm4_crypt_ecb( ctx, mode, input, output );

            for( i = 0; i < 16; i++ )
                output[i] = (uint8_t)( output[i] ^ iv[i] );

            memcpy( iv, temp, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }
    else
    {
        while( length > 0 )
        {
            for( i = 0; i < 16; i++ )
                output[i] = (uint8_t)( input[i] ^ iv[i] );

            mbedtls_sm4_crypt_ecb( ctx, mode, output, output );
            memcpy( iv, output, 16 );

            input  += 16;
            output += 16;
            length -= 16;
        }
    }

    return( 0 );
}


#if defined( MBEDTLS_SELF_TEST )

// Test CBC

static int sm4_self_test_cbc( int verbose )
{
    // key and plaintext
    const unsigned char test_in[32] =
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const unsigned char test_ct[32] =
    {
        0x26, 0x77, 0xF4, 0x6B, 0x09, 0xC1, 0x22, 0xCC,
        0x97, 0x55, 0x33, 0x10, 0x5B, 0xD4, 0xA2, 0x2A,
        0xF6, 0x12, 0x5F, 0x72, 0x75, 0xCE, 0x55, 0x2C,
        0x3A, 0x2B, 0xBC, 0xF5, 0x33, 0xDE, 0x8A, 0x3B
    };
    mbedtls_sm4_context ctx;
    unsigned char iv[16], out[32];

    // test encrypt

    if( verbose )
        mbedtls_printf( "  SM4-CBC-128 (enc): ");

    mbedtls_sm4_setkey_enc( &ctx, test_in, 128 );
    memset( out, 0, sizeof( out ) );
    memcpy( iv, test_in, 16 );

    mbedtls_sm4_crypt_cbc( &ctx, MBEDTLS_SM4_ENCRYPT, 32, iv, test_in, out );

    if( memcmp( out, test_ct, 32 ) != 0 )
    {
        if( verbose )
            mbedtls_printf( "failed\n ");
        return( 1 );
    }
    if( verbose )
        mbedtls_printf( "passed\n" );

    // test decrypt

    if( verbose )
        mbedtls_printf( "  SM4-CBC-128 (dec): ");

    mbedtls_sm4_setkey_dec( &ctx, test_in, 128 );
    memset( out, 0, sizeof( out ) );
    memcpy( iv, test_in, 16 );

    mbedtls_sm4_crypt_cbc( &ctx, MBEDTLS_SM4_DECRYPT, 32, iv, test_ct, out );

    if( memcmp( out, test_in, 32 ) != 0 )
    {
        if( verbose )
            mbedtls_printf( "failed\n ");
        return( 1 );
    }
    if( verbose )
        mbedtls_printf( "passed\n\n" );

    return( 0 );
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_CIPHER_MODE_CBC */



#if defined( MBEDTLS_CIPHER_MODE_CTR )

// SM4-CTR  Counter Mode

int mbedtls_sm4_crypt_ctr( mbedtls_sm4_context *ctx,
                            size_t length,
                            size_t *nc_off,
                            unsigned char nonce_counter[16],
                            unsigned char stream_block[16],
                            const unsigned char *input,
                            unsigned char *output )
{
    int c, i;
    size_t n;

    n = *nc_off;
    while( length-- )
    {
        if( n == 0 )
        {
            mbedtls_sm4_crypt_ecb( ctx, MBEDTLS_SM4_ENCRYPT, nonce_counter,
                                    stream_block );
            for( i = 15; i >= 0; i-- )
                if( ++nonce_counter[i] != 0 )
                    break;
        }
        c = *input++;
        *output++ = (uint8_t)( c ^ stream_block[n] );

        n = ( n + 1 ) & 0x0F;
    }
    *nc_off = n;

    return( 0 );
}


#if defined( MBEDTLS_SELF_TEST )

// Test CTR

static int sm4_self_test_ctr( int verbose )
{
    // key and plaintext
    const unsigned char test_in[16] =
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    const unsigned char test_pt[64] =
    {
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
        0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
        0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA
    };
    const unsigned char test_ct[64] =
    {
        0xC2, 0xB4, 0x75, 0x9E, 0x78, 0xAC, 0x3C, 0xF4,
        0x3D, 0x08, 0x52, 0xF4, 0xE8, 0xD5, 0xF9, 0xFD,
        0x72, 0x56, 0xE8, 0xA5, 0xFC, 0xB6, 0x5A, 0x35,
        0x0E, 0xE0, 0x06, 0x30, 0x91, 0x2E, 0x44, 0x49,
        0x2A, 0x0B, 0x17, 0xE1, 0xB8, 0x5B, 0x06, 0x0D,
        0x0F, 0xBA, 0x61, 0x2D, 0x8A, 0x95, 0x83, 0x16,
        0x38, 0xB3, 0x61, 0xFD, 0x5F, 0xFA, 0xCD, 0x94,
        0x2F, 0x08, 0x14, 0x85, 0xA8, 0x3C, 0xA3, 0x5D
    };

    size_t t;
    mbedtls_sm4_context ctx;
    unsigned char ctr[16], blk[16], out[64];

    mbedtls_sm4_setkey_enc( &ctx, test_in, 128 );

    // test encrypt

    if( verbose )
        mbedtls_printf( "  SM4-CTR-128 (enc): ");

    memset( out, 0, sizeof( out ) );
    memset( blk, 0, sizeof( blk ) );
    memcpy( ctr, test_in, 16 );
    t = 0;

    mbedtls_sm4_crypt_ctr( &ctx, 64, &t, ctr, blk, test_pt, out );

    if( memcmp( out, test_ct, 64 ) != 0 )
    {
        if( verbose )
            mbedtls_printf( "failed\n ");
        return( 1 );
    }
    if( verbose )
        mbedtls_printf( "passed\n" );

    // test decrypt

    if( verbose )
        mbedtls_printf( "  SM4-CTR-128 (dec): ");

    memset( out, 0, sizeof( out ) );
    memset( blk, 0, sizeof( blk ) );
    memcpy( ctr, test_in, 16 );
    t = 0;

    mbedtls_sm4_crypt_ctr( &ctx, 64, &t, ctr, blk, test_ct, out );

    if( memcmp( out, test_pt, 64 ) != 0 )
    {
        if( verbose )
            mbedtls_printf( "failed\n ");
        return( 1 );
    }
    if( verbose )
        mbedtls_printf( "passed\n\n" );

    return 0;
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_CIPHER_MODE_CTR */


#if defined( MBEDTLS_SELF_TEST )

// master self test

int mbedtls_sm4_self_test( int verbose )
{
    if( sm4_self_test_ecb( verbose ) )
        return 1;
#ifdef MBEDTLS_CIPHER_MODE_CBC
    if( sm4_self_test_cbc( verbose ) )
        return 1;
#endif /* MBEDTLS_CIPHER_MODE_CBC */
#ifdef MBEDTLS_CIPHER_MODE_CTR
    if( sm4_self_test_ctr( verbose ) )
        return 1;
#endif /* MBEDTLS_CIPHER_MODE_CTR */

    return 0;
}
#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_SM4_C */

