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
/*
 *  GB/T 32905-2016 compliant SM3 implementation
 *  The SM3 algorithm was designed by Xiaoyun Wang et al in 2010.
 *
 *  http://www.gmbz.org.cn/upload/2018-07-24/1532401392982079739.pdf
 */

#include "common.h"

#if defined(MBEDTLS_SM3_C)

#include "mbedtls/sm3.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST */

#if !defined(MBEDTLS_SM3_ALT)

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
do {                                                    \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
} while( 0 )
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
do {                                                    \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
} while( 0 )
#endif

void mbedtls_sm3_init( mbedtls_sm3_context *ctx )
{
    memset( ctx, 0, sizeof( mbedtls_sm3_context ) );
}

void mbedtls_sm3_free( mbedtls_sm3_context *ctx )
{
    if( ctx == NULL )
        return;

    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_sm3_context ) );
}

void mbedtls_sm3_clone( mbedtls_sm3_context *dst,
                        const mbedtls_sm3_context *src )
{
    *dst = *src;
}

/*
 * SM3 context setup
 */
int mbedtls_sm3_starts_ret( mbedtls_sm3_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    /* initial IV */
    ctx->state[0] = 0x7380166F;
    ctx->state[1] = 0x4914B2B9;
    ctx->state[2] = 0x172442D7;
    ctx->state[3] = 0xDA8A0600;
    ctx->state[4] = 0xA96F30BC;
    ctx->state[5] = 0x163138AA;
    ctx->state[6] = 0xE38DEE4D;
    ctx->state[7] = 0xB0FB0E4E;

    return( 0 );
}

#if !defined(MBEDTLS_SM3_PROCESS_ALT)
#define EXTMSG_W1_LEN 68
#define EXTMSG_W2_LEN 64
#define EXTMSG_W_LEN (EXTMSG_W1_LEN + EXTMSG_W2_LEN)

#define ROTL32( value, amount ) \
    ( (uint32_t) ( (value) << ( (amount & 0x1f) ) ) | ( (value) >> ( (32 - (amount) ) & 0x1f ) ) )

#define T(i) ( ( (i) <= 15 ) ? 0x79CC4519U : 0x7A879D8AU )
#define GG(j,x,y,z) ( ( (j) <= 15 ) ? ((x) ^ (y) ^ (z)) : ( ((x) & (y)) | ((~x) & (z)) ) )
#define FF(j,x,y,z) ( ( (j) <= 15 ) ? ((x) ^ (y) ^ (z)) : ( ((x) & (y)) | ((x) & (z)) | ((y) & (z)) ) )
#define P0(x) ( (x) ^ ROTL32( (x), 9 ) ^ ROTL32( (x), 17 ) )
#define P1(x) ( (x) ^ ROTL32( (x), 15 ) ^ ROTL32( (x), 23 ) )

/* SM3 Message Expansion */
static void sm3_msgext( uint32_t *w, const unsigned char *bi )
{
    int j;
    for( j = 0; j < 16; j++ )
    {
        GET_UINT32_BE( w[j], bi + j * 4, 0);
    }

    for( j = 16; j < EXTMSG_W1_LEN; j++ )
    {
        w[j] = P1( w[j - 16] ^ w[j - 9] ^ ROTL32( w[j - 3], 15 ) ) ^
                   ROTL32( w[j - 13], 7 ) ^ w[j - 6];
    }

    uint32_t *w_ext = w + EXTMSG_W1_LEN;

    for( j = 0; j < EXTMSG_W2_LEN; j++ )
    {
        w_ext[j] = w[j] ^ w[j + 4];
    }
}

/* SM3 Compression Function, CF */
int mbedtls_internal_sm3_process( mbedtls_sm3_context *ctx,
                                  const unsigned char data[64] )
{
    struct
    {
        uint32_t ss1, ss2, tt1, tt2;
        uint32_t W[EXTMSG_W_LEN];
        uint32_t A[8]; /* a ~ h */
    } local;

    int i, j;

    for( i = 0; i < 8; i++ )
        local.A[i] = ctx->state[i];

    sm3_msgext( local.W, data );

    for( j = 0; j < 64; j++ )
    {
        local.ss1 = ROTL32( ROTL32( local.A[0], 12 ) + local.A[4] + ROTL32( T(j), j ), 7 );
        local.ss2 = local.ss1 ^ ROTL32( local.A[0], 12 );
        local.tt1 = FF( j, local.A[0], local.A[1], local.A[2] ) + local.A[3] + local.ss2 + local.W[j + EXTMSG_W1_LEN];
        local.tt2 = GG( j, local.A[4], local.A[5], local.A[6] ) + local.A[7] + local.ss1 + local.W[j];
        local.A[3] = local.A[2];
        local.A[2] = ROTL32( local.A[1], 9 );
        local.A[1] = local.A[0];
        local.A[0] = local.tt1;
        local.A[7] = local.A[6];
        local.A[6] = ROTL32( local.A[5], 19 );
        local.A[5] = local.A[4];
        local.A[4] = P0( local.tt2 );
    }

    for( i = 0; i < 8; i++ )
        ctx->state[i] ^= local.A[i];

    /* Zeroise buffers and variables to clear sensitive data from memory. */
    mbedtls_platform_zeroize( &local, sizeof( local ) );

    return 0;
}
#endif /* !MBEDTLS_SM3_PROCESS_ALT */

/*
 * SM3 process buffer
 */
int mbedtls_sm3_update_ret( mbedtls_sm3_context *ctx,
                            const unsigned char *input,
                            size_t ilen )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t fill;
    uint32_t left;

    if( ilen == 0 )
        return( 0 );

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        if( ( ret = mbedtls_internal_sm3_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        if( ( ret = mbedtls_internal_sm3_process( ctx, input ) ) != 0 )
            return( ret );

        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
        memcpy( (void *) (ctx->buffer + left), input, ilen );

    return( 0 );
}

/*
 * SM3 final digest
 */
int mbedtls_sm3_finish_ret( mbedtls_sm3_context *ctx,
                            unsigned char output[32] )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    uint32_t used;
    uint32_t high, low;

    /*
     * Add padding: 0x80 then 0x00 until 8 bytes remain for the length
     */
    used = ctx->total[0] & 0x3F;

    ctx->buffer[used++] = 0x80;

    if( used <= 56 )
    {
        /* Enough room for padding + length in current block */
        memset( ctx->buffer + used, 0, 56 - used );
    }
    else
    {
        /* We'll need an extra block */
        memset( ctx->buffer + used, 0, 64 - used );

        if( ( ret = mbedtls_internal_sm3_process( ctx, ctx->buffer ) ) != 0 )
            return( ret );

        memset( ctx->buffer, 0, 56 );
    }

    /*
     * Add message length
     */
    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_BE( low,  ctx->buffer, 60 );
    PUT_UINT32_BE( high, ctx->buffer, 56 );
    if( ( ret = mbedtls_internal_sm3_process( ctx, ctx->buffer ) ) != 0 )
        return( ret );

    /*
     * Output final state
     */
    PUT_UINT32_BE( ctx->state[0], output,  0 );
    PUT_UINT32_BE( ctx->state[1], output,  4 );
    PUT_UINT32_BE( ctx->state[2], output,  8 );
    PUT_UINT32_BE( ctx->state[3], output, 12 );
    PUT_UINT32_BE( ctx->state[4], output, 16 );
    PUT_UINT32_BE( ctx->state[5], output, 20 );
    PUT_UINT32_BE( ctx->state[6], output, 24 );
    PUT_UINT32_BE( ctx->state[7], output, 28 );

    return( 0 );
}

#endif /* !MBEDTLS_SM3_ALT */

/*
 * output = SM3( input buffer )
 */
int mbedtls_sm3_ret( const unsigned char *input,
                     size_t ilen,
                     unsigned char output[32] )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_sm3_context ctx;

    mbedtls_sm3_init( &ctx );

    if( ( ret = mbedtls_sm3_starts_ret( &ctx ) ) != 0 )
        goto exit;

    if( ( ret = mbedtls_sm3_update_ret( &ctx, input, ilen ) ) != 0 )
        goto exit;

    if( ( ret = mbedtls_sm3_finish_ret( &ctx, output ) ) != 0 )
        goto exit;

exit:
    mbedtls_sm3_free( &ctx );

    return( ret );
}

#if defined(MBEDTLS_SELF_TEST)

/*
 * GB/T 32905-2016 test vectors
 */
static const unsigned char sm3_test_str1[3] =
{
    0x61, 0x62, 0x63
};

static const unsigned char sm3_test_str2[64] =
{
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64
};

static const unsigned char*  sm3_test_str[2] =
{
    sm3_test_str1, sm3_test_str2
};

static const size_t sm3_test_strlen[2] =
{
    3, 64
};

static const unsigned char sm3_test_sum[2][32] =
{
    { 0x66, 0xC7, 0xF0, 0xF4, 0x62, 0xEE, 0xED, 0xD9,
      0xD1, 0xF2, 0xD4, 0x6B, 0xDC, 0x10, 0xE4, 0xE2,
      0x41, 0x67, 0xC4, 0x87, 0x5C, 0xF2, 0xF7, 0xA2,
      0x29, 0x7D, 0xA0, 0x2B, 0x8F, 0x4B, 0xA8, 0xE0 },
    { 0xDE, 0xBE, 0x9F, 0xF9, 0x22, 0x75, 0xB8, 0xA1,
      0x38, 0x60, 0x48, 0x89, 0xC1, 0x8E, 0x5A, 0x4D,
      0x6F, 0xDB, 0x70, 0xE5, 0x38, 0x7E, 0x57, 0x65,
      0x29, 0x3D, 0xCB, 0xA3, 0x9C, 0x0C, 0x57, 0x32 }
};

static int sm3_clone_ret_test( const unsigned char *input,
                               size_t ilen,
                               unsigned char output[32] )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    mbedtls_sm3_context ctx;
    mbedtls_sm3_context cl;

    mbedtls_sm3_init( &ctx );
    mbedtls_sm3_init( &cl );

    if( ( ret = mbedtls_sm3_starts_ret( &ctx ) ) != 0 )
        goto exit;

    if( ( ret = mbedtls_sm3_update_ret( &ctx, input, ilen ) ) != 0 )
        goto exit;

    mbedtls_sm3_clone( &cl, &ctx );

    if( ( ret = mbedtls_sm3_finish_ret( &cl, output ) ) != 0 )
        goto exit;

exit:
    mbedtls_sm3_free( &ctx );
    mbedtls_sm3_free( &cl );

    return( ret );
}

/*
 * Checkup routine
 */
int mbedtls_sm3_self_test( int verbose )
{
    int i, ret = 0;
    unsigned char sm3sum[32];

    for( i = 0; i < 2; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  SM3 test #%d: ", i + 1 );

        ret = mbedtls_sm3_ret( sm3_test_str[i], sm3_test_strlen[i], sm3sum );
        if( ret != 0 )
            goto fail;

        if( memcmp( sm3sum, sm3_test_sum[i], 32 ) != 0 )
        {
            ret = 1;
            goto fail;
        }

        ret = sm3_clone_ret_test( sm3_test_str[i], sm3_test_strlen[i], sm3sum );
        if( ret != 0 )
            goto fail;

        if( memcmp( sm3sum, sm3_test_sum[i], 32 ) != 0 )
        {
            ret = 1;
            goto fail;
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( 0 );

fail:
    if( verbose != 0 )
        mbedtls_printf( "failed\n" );

    return( ret );
}

#endif /* MBEDTLS_SELF_TEST */

#endif /* MBEDTLS_SM3_C */
