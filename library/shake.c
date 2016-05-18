/**
 * \file shale.c
 *
 * \brief SHA-3 eXtensible Output Functions (XOF) (SHAKE128, SHAKE256)
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

#if defined(MBEDTLS_SHAKE_C)

#include "mbedtls/shake.h"

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

#if !defined(MBEDTLS_SHAKE_ALT)

static int mbedtls_convert_sponge_result( int sponge_ret )
{
    switch ( sponge_ret )
    {
        case 0:
            return 0;

        case MBEDTLS_ERR_KECCAK_SPONGE_BAD_STATE:
            return MBEDTLS_ERR_SHAKE_BAD_STATE;

        case MBEDTLS_ERR_KECCAK_SPONGE_NOT_SETUP:
            return MBEDTLS_ERR_SHAKE_BAD_NOT_STARTED;

        default:
        case MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA:
            return MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA;
    }
}

void mbedtls_shake_init( mbedtls_shake_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_keccak_sponge_init( &ctx->sponge_ctx );
    }
}

void mbedtls_shake_free( mbedtls_shake_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_keccak_sponge_free( &ctx->sponge_ctx );
    }
}

void mbedtls_shake_clone( mbedtls_shake_context *dst,
                          const mbedtls_shake_context *src )
{
    mbedtls_keccak_sponge_clone( &dst->sponge_ctx, &src->sponge_ctx );
}

int mbedtls_shake_starts( mbedtls_shake_context *ctx, mbedtls_shake_type_t type )
{
    int sponge_ret;

    if ( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA );
    }

    switch (type)
    {
    case MBEDTLS_SHAKE128:
        ctx->block_size  = MBEDTLS_KECCAKF_STATE_SIZE_BYTES - 32U;
        sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx, 256U, 0x0FU, 4U );
        break;

    case MBEDTLS_SHAKE256:
        ctx->block_size  = MBEDTLS_KECCAKF_STATE_SIZE_BYTES - 64U;
        sponge_ret = mbedtls_keccak_sponge_starts( &ctx->sponge_ctx, 512U, 0x0FU, 4U );
        break;

    default:
        return( MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA );
    }

    return mbedtls_convert_sponge_result( sponge_ret );
}

int mbedtls_shake_update( mbedtls_shake_context *ctx,
        const unsigned char* input,
        size_t size )
{
    int sponge_ret;

    if ( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_absorb( &ctx->sponge_ctx, input, size );

    return mbedtls_convert_sponge_result( sponge_ret );
}

int mbedtls_shake_output( mbedtls_shake_context *ctx,
                          unsigned char* output,
                          size_t olen )
{
    int sponge_ret;

    if ( ( ctx == NULL ) || ( output == NULL ) )
    {
        return( MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_squeeze( &ctx->sponge_ctx, output, olen );

    return mbedtls_convert_sponge_result( sponge_ret );
}

int mbedtls_shake_process( mbedtls_shake_context *ctx, const unsigned char* input )
{
    int sponge_ret;

    if ( ( ctx == NULL ) || ( input == NULL ) )
    {
        return( MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA );
    }

    sponge_ret = mbedtls_keccak_sponge_process( &ctx->sponge_ctx, input );

    return mbedtls_convert_sponge_result( sponge_ret );
}

#endif /* !MBEDTLS_SHAKE_ALT */

int mbedtls_shake( const unsigned char* input,
                   size_t ilen,
                   mbedtls_shake_type_t type,
                   unsigned char* output,
                   size_t olen )
{
    mbedtls_shake_context ctx;
    int result;

    mbedtls_shake_init( &ctx );

    result = mbedtls_shake_starts( &ctx, type );
    if ( 0 != result )
    {
        goto cleanup;
    }

    result = mbedtls_shake_update( &ctx, input, ilen );
    if ( 0 != result )
    {
        goto cleanup;
    }

    result = mbedtls_shake_output( &ctx, output, olen );

cleanup:
    mbedtls_shake_free( &ctx );

    return( result );
}

#ifdef MBEDTLS_SELF_TEST

static const unsigned char shake128_test_input[2][16] =
{
    {
        0xD4, 0xD6, 0x7B, 0x00, 0xCA, 0x51, 0x39, 0x77,
        0x91, 0xB8, 0x12, 0x05, 0xD5, 0x58, 0x2C, 0x0A
    },
    {
        0xCC, 0x0A, 0x93, 0x9D, 0x40, 0xFE, 0xFD, 0xC6,
        0xC9, 0x9A, 0xCF, 0xA3, 0x7D, 0xE1, 0x0D, 0xF6
    }
};

static const unsigned char shake128_test_output[2][16] =
{
    {
        0xD0, 0xAC, 0xFB, 0x2A, 0x14, 0x92, 0x8C, 0xAF,
        0x8C, 0x16, 0x8A, 0xE5, 0x14, 0x92, 0x5E, 0x4E
    },
    {
        0xB7, 0x0B, 0x72, 0x4A, 0x91, 0xBA, 0x86, 0x5E,
        0xF4, 0x34, 0xF8, 0x50, 0x48, 0x50, 0x48, 0x91
    }
};

static const unsigned char shake256_test_input[2][32] =
{
    {
        0xEF, 0x89, 0x6C, 0xDC, 0xB3, 0x63, 0xA6, 0x15,
        0x91, 0x78, 0xA1, 0xBB, 0x1C, 0x99, 0x39, 0x46,
        0xC5, 0x04, 0x02, 0x09, 0x5C, 0xDA, 0xEA, 0x4F,
        0xD4, 0xD4, 0x19, 0xAA, 0x47, 0x32, 0x1C, 0x88
    },
    {
        0x76, 0x89, 0x1A, 0x7B, 0xCC, 0x6C, 0x04, 0x49,
        0x00, 0x35, 0xB7, 0x43, 0x15, 0x2F, 0x64, 0xA8,
        0xDD, 0x2E, 0xA1, 0x8A, 0xB4, 0x72, 0xB8, 0xD3,
        0x6E, 0xCF, 0x45, 0x85, 0x8D, 0x0B, 0x00, 0x46
    }
};

static const unsigned char shake256_test_output[2][32] =
{
    {
        0x7A, 0xBB, 0xA4, 0xE8, 0xB8, 0xDD, 0x76, 0x6B,
        0xBA, 0xBE, 0x98, 0xF8, 0xF1, 0x69, 0xCB, 0x62,
        0x08, 0x67, 0x4D, 0xE1, 0x9A, 0x51, 0xD7, 0x3C,
        0x92, 0xB7, 0xDC, 0x04, 0xA4, 0xB5, 0xEE, 0x3D
    },
    {
        0xE8, 0x44, 0x7D, 0xF8, 0x7D, 0x01, 0xBE, 0xEB,
        0x72, 0x4C, 0x9A, 0x2A, 0x38, 0xAB, 0x00, 0xFC,
        0xC2, 0x4E, 0x9B, 0xD1, 0x78, 0x60, 0xE6, 0x73,
        0xB0, 0x21, 0x22, 0x2D, 0x62, 0x1A, 0x78, 0x10
    }
};

int mbedtls_shake_self_test( int verbose )
{
    uint8_t output[32];
    size_t i;
    int result;

    for ( i = 0U; i < 2U; i++ )
    {
        if ( verbose != 0 )
        {
            mbedtls_printf( "  SHAKE128 test %zi ", i );
        }

        result = mbedtls_shake( shake128_test_input[i], 16U,
                                MBEDTLS_SHAKE128,
                                output, 16U );
        if ( result != 0 )
        {
            if ( verbose != 0 )
            {
                mbedtls_printf( "error code: %i\n", result );
            }
            return( -1 );
        }
        if ( 0 != memcmp(shake128_test_output[i], output, 16U ) )
        {
            if ( verbose != 0 )
            {
                mbedtls_printf( "failed\n" );
            }
            return( -1 );
        }

        if ( verbose != 0 )
        {
            mbedtls_printf( "passed\n" );
            mbedtls_printf( "  SHAKE256 test %zi ", i );
        }

        result = mbedtls_shake( shake256_test_input[i], 32U,
                                MBEDTLS_SHAKE256,
                                output, 32U );
        if ( result != 0 )
        {
            if ( verbose != 0 )
            {
                mbedtls_printf( "error code: %i\n", result );
            }
            return( -1 );
        }
        if ( 0 != memcmp(shake256_test_output[i], output, 32U ) )
        {
            if ( verbose != 0 )
            {
                mbedtls_printf( "failed\n" );
            }
            return( -1 );
        }

        if ( verbose != 0 )
        {
            mbedtls_printf( "passed\n" );
        }
    }

    if ( verbose != 0 )
    {
        mbedtls_printf( "\n" );
    }

    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_SHAKE_C */
