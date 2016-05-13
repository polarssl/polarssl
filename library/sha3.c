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

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if !defined(MBEDTLS_SHA3_ALT)

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
}

int mbedtls_sha3_starts( mbedtls_sha3_context *ctx, mbedtls_sha3_type_t type )
{
    if ( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    switch (type)
    {
    case MBEDTLS_SHA3_224:
        ctx->digest_size = 224U / 8U;
        return mbedtls_keccak_sponge_starts( &ctx->sponge_ctx, 224U * 2U, 0x02U, 2U);

    case MBEDTLS_SHA3_256:
        ctx->digest_size = 256U / 8U;
        return mbedtls_keccak_sponge_starts( &ctx->sponge_ctx, 256U * 2U, 0x02U, 2U);

    case MBEDTLS_SHA3_384:
        ctx->digest_size = 384U / 8U;
        return mbedtls_keccak_sponge_starts( &ctx->sponge_ctx, 384U * 2U, 0x02U, 2U);

    case MBEDTLS_SHA3_512:
        ctx->digest_size = 512U / 8U;
        return mbedtls_keccak_sponge_starts( &ctx->sponge_ctx, 512U * 2U, 0x02U, 2U);

    default:
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }
}

int mbedtls_sha3_update( mbedtls_sha3_context *ctx,
        const unsigned char* input,
        size_t size )
{
    if ( ctx == NULL )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    return mbedtls_keccak_sponge_absorb( &ctx->sponge_ctx, input, size );
}

int mbedtls_sha3_finish( mbedtls_sha3_context *ctx, unsigned char* output )
{
    if ( ( ctx == NULL ) || ( output == NULL ) )
    {
        return( MBEDTLS_ERR_SHA3_BAD_INPUT_DATA );
    }

    return mbedtls_keccak_sponge_squeeze( &ctx->sponge_ctx, output, ctx->digest_size );
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

int mbedtls_sha3_self_test( int verbose )
{
    return -1;
}

#endif /* MBEDTLS_SHA3_C */
