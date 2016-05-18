/**
 * \file sha3.c
 *
 * \brief SHA-3 cryptographic hash functions (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
 *
 * \author Daniel King <damaki.gh@gmail.com>
 *
 *  Copyright (C) 2006-2016, ARM Limited, All Rights Reserved
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

#if defined(MBEDTLS_SHA3_C)

#include "mbedtls/sha3.h"

#include <stddef.h>
#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if !defined(MBEDTLS_SHA3_ALT)

static int mbedtls_convert_sponge_result( int sponge_ret )
{
    switch ( sponge_ret )
    {
        case 0:
            return 0;

        case MBEDTLS_ERR_KECCAK_SPONGE_BAD_STATE:
            return MBEDTLS_ERR_SHA3_BAD_STATE;

        case MBEDTLS_ERR_KECCAK_SPONGE_NOT_SETUP:
            return MBEDTLS_ERR_SHA3_BAD_NOT_STARTED;

        default:
        case MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA:
            return MBEDTLS_ERR_SHA3_BAD_INPUT_DATA;
    }
}

void mbedtls_sha3_init( mbedtls_sha3_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_keccak_sponge_init( &ctx->sponge_ctx );
        ctx->digest_size = 0U;
    }
}

void mbedtls_sha3_free( mbedtls_sha3_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_keccak_sponge_free( &ctx->sponge_ctx );
        ctx->digest_size = 0U;
    }
}

void mbedtls_sha3_clone( mbedtls_sha3_context *dst,
                         const mbedtls_sha3_context *src )
{
    mbedtls_keccak_sponge_clone( &dst->sponge_ctx, &src->sponge_ctx );
    dst->digest_size = src->digest_size;
    dst->block_size  = src->block_size;
}

int mbedtls_sha3_starts( mbedtls_sha3_context *ctx, mbedtls_sha3_type_t type )
{
    int sponge_ret;

    if ( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    switch (type)
    {
    case MBEDTLS_SHA3_224:
        ctx->digest_size = 224U / 8U;
        ctx->block_size  = MBEDTLS_KECCAKF_STATE_SIZE_BYTES - ( 28U * 2U );
        sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx, 224U * 2U, 0x02U, 2U );
        break;

    case MBEDTLS_SHA3_256:
        ctx->digest_size = 256U / 8U;
        ctx->block_size  = MBEDTLS_KECCAKF_STATE_SIZE_BYTES - ( 32U * 2U );
        sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx, 256U * 2U, 0x02U, 2U );
        break;

    case MBEDTLS_SHA3_384:
        ctx->digest_size = 384U / 8U;
        ctx->block_size  = MBEDTLS_KECCAKF_STATE_SIZE_BYTES - ( 48U * 2U );
        sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx, 384U * 2U, 0x02U, 2U );

        break;
    case MBEDTLS_SHA3_512:
        ctx->digest_size = 512U / 8U;
        ctx->block_size  = MBEDTLS_KECCAKF_STATE_SIZE_BYTES - ( 64U * 2U );
        sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx, 512U * 2U, 0x02U, 2U );
        break;

    default:
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}

int mbedtls_sha3_update( mbedtls_sha3_context *ctx,
        const unsigned char* input,
        size_t size )
{
    int sponge_ret;

    if ( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_absorb( &ctx->sponge_ctx, input, size );

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}

int mbedtls_sha3_finish( mbedtls_sha3_context *ctx, unsigned char* output )
{
    int sponge_ret;

    if ( ( ctx == NULL ) || ( output == NULL ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_squeeze( &ctx->sponge_ctx, output, ctx->digest_size );

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}

int mbedtls_sha3_process( mbedtls_sha3_context *ctx, const unsigned char* input )
{
    int sponge_ret;

    if ( ( ctx == NULL ) || ( input == NULL ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_process( &ctx->sponge_ctx, input );

    return( mbedtls_convert_sponge_result( sponge_ret ) );
}

#endif /* MBEDTLS_SHA3_ALT */

int mbedtls_sha3( const unsigned char* input,
                  size_t ilen,
                  mbedtls_sha3_type_t type,
                  unsigned char* output )
{
    mbedtls_sha3_context ctx;
    int result;

    mbedtls_sha3_init( &ctx );

    result = mbedtls_sha3_starts( &ctx, type );
    if ( 0 != result )
    {
        goto cleanup;
    }

    result = mbedtls_sha3_update( &ctx, input, ilen );
    if ( 0 != result )
    {
        goto cleanup;
    }

    result = mbedtls_sha3_finish( &ctx, output );

cleanup:
    mbedtls_sha3_free( &ctx );

    return( result );
}

#ifdef MBEDTLS_SELF_TEST

static const unsigned char test_data[2][4] =
{
    "",
    "abc",
};

static const size_t test_data_len[2] =
{
    0U, /* "" */
    3U  /* "abc" */
};

static const unsigned char test_hash_sha3_224[2][28] =
{
    { /* "" */
        0x6B, 0x4E, 0x03, 0x42, 0x36, 0x67, 0xDB, 0xB7,
        0x3B, 0x6E, 0x15, 0x45, 0x4F, 0x0E, 0xB1, 0xAB,
        0xD4, 0x59, 0x7F, 0x9A, 0x1B, 0x07, 0x8E, 0x3F,
        0x5B, 0x5A, 0x6B, 0xC7
    },
    { /* "abc" */
        0xE6, 0x42, 0x82, 0x4C, 0x3F, 0x8C, 0xF2, 0x4A,
        0xD0, 0x92, 0x34, 0xEE, 0x7D, 0x3C, 0x76, 0x6F,
        0xC9, 0xA3, 0xA5, 0x16, 0x8D, 0x0C, 0x94, 0xAD,
        0x73, 0xB4, 0x6F, 0xDF
    }
};

static const unsigned char test_hash_sha3_256[2][32] =
{
    { /* "" */
        0xA7, 0xFF, 0xC6, 0xF8, 0xBF, 0x1E, 0xD7, 0x66,
        0x51, 0xC1, 0x47, 0x56, 0xA0, 0x61, 0xD6, 0x62,
        0xF5, 0x80, 0xFF, 0x4D, 0xE4, 0x3B, 0x49, 0xFA,
        0x82, 0xD8, 0x0A, 0x4B, 0x80, 0xF8, 0x43, 0x4A
    },
    { /* "abc" */
        0x3A, 0x98, 0x5D, 0xA7, 0x4F, 0xE2, 0x25, 0xB2,
        0x04, 0x5C, 0x17, 0x2D, 0x6B, 0xD3, 0x90, 0xBD,
        0x85, 0x5F, 0x08, 0x6E, 0x3E, 0x9D, 0x52, 0x5B,
        0x46, 0xBF, 0xE2, 0x45, 0x11, 0x43, 0x15, 0x32
    }
};

static const unsigned char test_hash_sha3_384[2][48] =
{
    { /* "" */
        0x0C, 0x63, 0xA7, 0x5B, 0x84, 0x5E, 0x4F, 0x7D,
        0x01, 0x10, 0x7D, 0x85, 0x2E, 0x4C, 0x24, 0x85,
        0xC5, 0x1A, 0x50, 0xAA, 0xAA, 0x94, 0xFC, 0x61,
        0x99, 0x5E, 0x71, 0xBB, 0xEE, 0x98, 0x3A, 0x2A,
        0xC3, 0x71, 0x38, 0x31, 0x26, 0x4A, 0xDB, 0x47,
        0xFB, 0x6B, 0xD1, 0xE0, 0x58, 0xD5, 0xF0, 0x04
    },
    { /* "abc" */
        0xEC, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6F, 0xC9,
        0x26, 0x45, 0x9F, 0x58, 0xE2, 0xC6, 0xAD, 0x8D,
        0xF9, 0xB4, 0x73, 0xCB, 0x0F, 0xC0, 0x8C, 0x25,
        0x96, 0xDA, 0x7C, 0xF0, 0xE4, 0x9B, 0xE4, 0xB2,
        0x98, 0xD8, 0x8C, 0xEA, 0x92, 0x7A, 0xC7, 0xF5,
        0x39, 0xF1, 0xED, 0xF2, 0x28, 0x37, 0x6D, 0x25
    }
};

static const unsigned char test_hash_sha3_512[2][64] =
{
    { /* "" */
        0xA6, 0x9F, 0x73, 0xCC, 0xA2, 0x3A, 0x9A, 0xC5,
        0xC8, 0xB5, 0x67, 0xDC, 0x18, 0x5A, 0x75, 0x6E,
        0x97, 0xC9, 0x82, 0x16, 0x4F, 0xE2, 0x58, 0x59,
        0xE0, 0xD1, 0xDC, 0xC1, 0x47, 0x5C, 0x80, 0xA6,
        0x15, 0xB2, 0x12, 0x3A, 0xF1, 0xF5, 0xF9, 0x4C,
        0x11, 0xE3, 0xE9, 0x40, 0x2C, 0x3A, 0xC5, 0x58,
        0xF5, 0x00, 0x19, 0x9D, 0x95, 0xB6, 0xD3, 0xE3,
        0x01, 0x75, 0x85, 0x86, 0x28, 0x1D, 0xCD, 0x26
    },
    { /* "abc" */
        0xB7, 0x51, 0x85, 0x0B, 0x1A, 0x57, 0x16, 0x8A,
        0x56, 0x93, 0xCD, 0x92, 0x4B, 0x6B, 0x09, 0x6E,
        0x08, 0xF6, 0x21, 0x82, 0x74, 0x44, 0xF7, 0x0D,
        0x88, 0x4F, 0x5D, 0x02, 0x40, 0xD2, 0x71, 0x2E,
        0x10, 0xE1, 0x16, 0xE9, 0x19, 0x2A, 0xF3, 0xC9,
        0x1A, 0x7E, 0xC5, 0x76, 0x47, 0xE3, 0x93, 0x40,
        0x57, 0x34, 0x0B, 0x4C, 0xF4, 0x08, 0xD5, 0xA5,
        0x65, 0x92, 0xF8, 0x27, 0x4E, 0xEC, 0x53, 0xF0
    }
};

static const unsigned char long_kat_hash_sha3_224[28] =
{
    0xD6, 0x93, 0x35, 0xB9, 0x33, 0x25, 0x19, 0x2E,
    0x51, 0x6A, 0x91, 0x2E, 0x6D, 0x19, 0xA1, 0x5C,
    0xB5, 0x1C, 0x6E, 0xD5, 0xC1, 0x52, 0x43, 0xE7,
    0xA7, 0xFD, 0x65, 0x3C
};

static const unsigned char long_kat_hash_sha3_256[32] =
{
    0x5C, 0x88, 0x75, 0xAE, 0x47, 0x4A, 0x36, 0x34,
    0xBA, 0x4F, 0xD5, 0x5E, 0xC8, 0x5B, 0xFF, 0xD6,
    0x61, 0xF3, 0x2A, 0xCA, 0x75, 0xC6, 0xD6, 0x99,
    0xD0, 0xCD, 0xCB, 0x6C, 0x11, 0x58, 0x91, 0xC1
};

static const unsigned char long_kat_hash_sha3_384[48] =
{
    0xEE, 0xE9, 0xE2, 0x4D, 0x78, 0xC1, 0x85, 0x53,
    0x37, 0x98, 0x34, 0x51, 0xDF, 0x97, 0xC8, 0xAD,
    0x9E, 0xED, 0xF2, 0x56, 0xC6, 0x33, 0x4F, 0x8E,
    0x94, 0x8D, 0x25, 0x2D, 0x5E, 0x0E, 0x76, 0x84,
    0x7A, 0xA0, 0x77, 0x4D, 0xDB, 0x90, 0xA8, 0x42,
    0x19, 0x0D, 0x2C, 0x55, 0x8B, 0x4B, 0x83, 0x40
};

static const unsigned char long_kat_hash_sha3_512[64] =
{
    0x3C, 0x3A, 0x87, 0x6D, 0xA1, 0x40, 0x34, 0xAB,
    0x60, 0x62, 0x7C, 0x07, 0x7B, 0xB9, 0x8F, 0x7E,
    0x12, 0x0A, 0x2A, 0x53, 0x70, 0x21, 0x2D, 0xFF,
    0xB3, 0x38, 0x5A, 0x18, 0xD4, 0xF3, 0x88, 0x59,
    0xED, 0x31, 0x1D, 0x0A, 0x9D, 0x51, 0x41, 0xCE,
    0x9C, 0xC5, 0xC6, 0x6E, 0xE6, 0x89, 0xB2, 0x66,
    0xA8, 0xAA, 0x18, 0xAC, 0xE8, 0x28, 0x2A, 0x0E,
    0x0D, 0xB5, 0x96, 0xC9, 0x0B, 0x0A, 0x7B, 0x87
};

static int mbedtls_sha3_kat_test( int verbose,
                                  const char* type_name,
                                  mbedtls_sha3_type_t type,
                                  size_t test_num )
{
    uint8_t hash[64];
    int result;

    result = mbedtls_sha3( test_data[test_num], test_data_len[test_num], type, hash );
    if ( result != 0 )
    {
        if ( verbose != 0 )
        {
            mbedtls_printf( "  %s test %zi error code: %i\n",
                            type_name, test_num, result );
        }

        return( result );
    }

    switch( type )
    {
        case MBEDTLS_SHA3_224:
            result = memcmp( hash, test_hash_sha3_224[test_num], 28U );
            break;
        case MBEDTLS_SHA3_256:
            result = memcmp( hash, test_hash_sha3_256[test_num], 32U );
            break;
        case MBEDTLS_SHA3_384:
            result = memcmp( hash, test_hash_sha3_384[test_num], 48U );
            break;
        case MBEDTLS_SHA3_512:
            result = memcmp( hash, test_hash_sha3_512[test_num], 64U );
            break;
    }

    if ( 0 != result )
    {
        if ( verbose != 0 )
        {
            mbedtls_printf( "  %s test %zi failed\n", type_name, test_num );
        }

        return( -1 );
    }

    if ( verbose != 0 )
    {
        mbedtls_printf( "  %s test %zi passed\n", type_name, test_num );
    }

    return( 0 );
}

static int mbedtls_sha3_long_kat_test( int verbose,
                                       const char* type_name,
                                       mbedtls_sha3_type_t type )
{
    mbedtls_sha3_context ctx;
    unsigned char buffer[1000];
    unsigned char hash[64];
    size_t i;
    int result = 0;

    memset( buffer, 'a', 1000U );

    if ( verbose != 0 )
    {
        mbedtls_printf( "  %s long KAT test ", type_name );
    }

    mbedtls_sha3_init( &ctx );

    result = mbedtls_sha3_starts( &ctx, type );
    if ( result != 0 )
    {
        if ( verbose != 0 )
        {
            mbedtls_printf( "setup failed\n " );
        }
    }

    /* Process 1,000,000 (one million) 'a' characters */
    for ( i = 0U; i < 1000; i++ )
    {
        result = mbedtls_sha3_update( &ctx, buffer, 1000U );
        if ( result != 0 )
        {
            if ( verbose != 0 )
            {
                mbedtls_printf( "update error code: %i\n", result );
            }

            goto cleanup;
        }
    }

    result = mbedtls_sha3_finish( &ctx, hash );
    if ( result != 0 )
    {
        if ( verbose != 0 )
        {
            mbedtls_printf( "finish error code: %i\n", result );
        }

        goto cleanup;
    }

    switch( type )
    {
        case MBEDTLS_SHA3_224:
            result = memcmp( hash, long_kat_hash_sha3_224, 28U );
            break;
        case MBEDTLS_SHA3_256:
            result = memcmp( hash, long_kat_hash_sha3_256, 32U );
            break;
        case MBEDTLS_SHA3_384:
            result = memcmp( hash, long_kat_hash_sha3_384, 48U );
            break;
        case MBEDTLS_SHA3_512:
            result = memcmp( hash, long_kat_hash_sha3_512, 64U );
            break;
    }

    if ( result != 0 )
    {
        if ( verbose != 0 )
        {
            mbedtls_printf( "failed\n" );
        }
    }

    if ( verbose != 0 )
    {
        mbedtls_printf( "passed\n" );
    }

cleanup:
    mbedtls_sha3_free( &ctx );
    return( result );
}

int mbedtls_sha3_self_test( int verbose )
{
    size_t i;

    /* Known Answer Tests (KAT) */
    for ( i = 0U; i < 2U; i++ )
    {
        if ( 0 != mbedtls_sha3_kat_test( verbose, "SHA3-224", MBEDTLS_SHA3_224, i ) )
            return( -1 );

        if ( 0 != mbedtls_sha3_kat_test( verbose, "SHA3-256", MBEDTLS_SHA3_256, i ) )
            return( -1 );

        if ( 0 != mbedtls_sha3_kat_test( verbose, "SHA3-384", MBEDTLS_SHA3_384, i ) )
            return( -1 );

        if ( 0 != mbedtls_sha3_kat_test( verbose, "SHA3-512", MBEDTLS_SHA3_512, i ) )
            return( -1 );
    }

    /* Long KAT tests */
    if ( 0 != mbedtls_sha3_long_kat_test( verbose, "SHA3-224", MBEDTLS_SHA3_224 ) )
        return( -1 );

    if ( 0 != mbedtls_sha3_long_kat_test( verbose, "SHA3-256", MBEDTLS_SHA3_256 ) )
        return( -1 );

    if ( 0 != mbedtls_sha3_long_kat_test( verbose, "SHA3-384", MBEDTLS_SHA3_384 ) )
        return( -1 );

    if ( 0 != mbedtls_sha3_long_kat_test( verbose, "SHA3-512", MBEDTLS_SHA3_512 ) )
        return( -1 );

    if ( verbose != 0 )
    {
        mbedtls_printf( "\n" );
    }

    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_SHA3_C */
