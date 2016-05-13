/**
 * \file keccakf.c
 *
 * \brief Keccak-f[1600] implementation for mbed TLS
 *
 * \author Daniel King <damaki.gh@gmail.com>
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

#include "mbedtls/keccakf.h"
#include <stddef.h>

#if defined(MBEDTLS_KECCAKF_C)

#if !defined(MBEDTLS_KECCAKF_ALT)

#define ROTL64( x, amount ) ( (uint64_t)( x << amount) | ( x >> ( 64 - amount ) ) )

static const uint64_t round_constants[24] =
{
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808AULL,
    0x8000000080008000ULL,
    0x000000000000808BULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008AULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000AULL,
    0x000000008000808BULL,
    0x800000000000008BULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800AULL,
    0x800000008000000AULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL
};

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/**
 * \brief Keccak Theta round operation.
 *
 * \param in_ctx
 * \param out_ctx
 */
static void mbedtls_keccakf_theta( const mbedtls_keccakf_context *in_ctx,
                                   mbedtls_keccakf_context *out_ctx )
{
    uint64_t c_left;
    uint64_t c_right;
    uint64_t d;
    size_t x;
    size_t x1;

    for ( x = 0U; x < 5U; x++ )
    {
        x1 = ( x + 9U ) % 5U; /* x - 1 (mod 5), e.g. if x==0 then x2==4 */
        c_left = in_ctx->state[x1][0] ^
                 in_ctx->state[x1][1] ^
                 in_ctx->state[x1][2] ^
                 in_ctx->state[x1][3] ^
                 in_ctx->state[x1][4];

        x1 = ( x + 1U ) % 5U;
        c_right = in_ctx->state[x1][0] ^
                  in_ctx->state[x1][1] ^
                  in_ctx->state[x1][2] ^
                  in_ctx->state[x1][3] ^
                  in_ctx->state[x1][4];

        d = c_left ^ ROTL64( c_right, 1 );

        out_ctx->state[x][0] = in_ctx->state[x][0] ^ d;
        out_ctx->state[x][1] = in_ctx->state[x][1] ^ d;
        out_ctx->state[x][2] = in_ctx->state[x][2] ^ d;
        out_ctx->state[x][3] = in_ctx->state[x][3] ^ d;
        out_ctx->state[x][4] = in_ctx->state[x][4] ^ d;
    }
}

static void mbedtls_keccakf_rho( const mbedtls_keccakf_context *in_ctx,
                                 mbedtls_keccakf_context *out_ctx )
{
    out_ctx->state[0][0] =         in_ctx->state[0][0];
    out_ctx->state[0][1] = ROTL64( in_ctx->state[0][1], 36 );
    out_ctx->state[0][2] = ROTL64( in_ctx->state[0][2], 3  );
    out_ctx->state[0][3] = ROTL64( in_ctx->state[0][3], 41 );
    out_ctx->state[0][4] = ROTL64( in_ctx->state[0][4], 18 );

    out_ctx->state[1][0] = ROTL64( in_ctx->state[1][0], 1  );
    out_ctx->state[1][1] = ROTL64( in_ctx->state[1][1], 44 );
    out_ctx->state[1][2] = ROTL64( in_ctx->state[1][2], 10 );
    out_ctx->state[1][3] = ROTL64( in_ctx->state[1][3], 45 );
    out_ctx->state[1][4] = ROTL64( in_ctx->state[1][4], 2  );

    out_ctx->state[2][0] = ROTL64( in_ctx->state[2][0], 62 );
    out_ctx->state[2][1] = ROTL64( in_ctx->state[2][1], 6  );
    out_ctx->state[2][2] = ROTL64( in_ctx->state[2][2], 43 );
    out_ctx->state[2][3] = ROTL64( in_ctx->state[2][3], 15 );
    out_ctx->state[2][4] = ROTL64( in_ctx->state[2][4], 61 );

    out_ctx->state[3][0] = ROTL64( in_ctx->state[3][0], 28 );
    out_ctx->state[3][1] = ROTL64( in_ctx->state[3][1], 55 );
    out_ctx->state[3][2] = ROTL64( in_ctx->state[3][2], 25 );
    out_ctx->state[3][3] = ROTL64( in_ctx->state[3][3], 21 );
    out_ctx->state[3][4] = ROTL64( in_ctx->state[3][4], 56 );

    out_ctx->state[4][0] = ROTL64( in_ctx->state[4][0], 27 );
    out_ctx->state[4][1] = ROTL64( in_ctx->state[4][1], 20 );
    out_ctx->state[4][2] = ROTL64( in_ctx->state[4][2], 39 );
    out_ctx->state[4][3] = ROTL64( in_ctx->state[4][3], 8  );
    out_ctx->state[4][4] = ROTL64( in_ctx->state[4][4], 14 );
}

static void mbedtls_keccakf_pi( const mbedtls_keccakf_context *in_ctx,
                                mbedtls_keccakf_context *out_ctx )
{
    out_ctx->state[0][0] = in_ctx->state[0][0];
    out_ctx->state[0][1] = in_ctx->state[3][0];
    out_ctx->state[0][2] = in_ctx->state[1][0];
    out_ctx->state[0][3] = in_ctx->state[4][0];
    out_ctx->state[0][4] = in_ctx->state[2][0];

    out_ctx->state[1][0] = in_ctx->state[1][1];
    out_ctx->state[1][1] = in_ctx->state[4][1];
    out_ctx->state[1][2] = in_ctx->state[2][1];
    out_ctx->state[1][3] = in_ctx->state[0][1];
    out_ctx->state[1][4] = in_ctx->state[3][1];

    out_ctx->state[2][0] = in_ctx->state[2][2];
    out_ctx->state[2][1] = in_ctx->state[0][2];
    out_ctx->state[2][2] = in_ctx->state[3][2];
    out_ctx->state[2][3] = in_ctx->state[1][2];
    out_ctx->state[2][4] = in_ctx->state[4][2];

    out_ctx->state[3][0] = in_ctx->state[3][3];
    out_ctx->state[3][1] = in_ctx->state[1][3];
    out_ctx->state[3][2] = in_ctx->state[4][3];
    out_ctx->state[3][3] = in_ctx->state[2][3];
    out_ctx->state[3][4] = in_ctx->state[0][3];

    out_ctx->state[4][0] = in_ctx->state[4][4];
    out_ctx->state[4][1] = in_ctx->state[2][4];
    out_ctx->state[4][2] = in_ctx->state[0][4];
    out_ctx->state[4][3] = in_ctx->state[3][4];
    out_ctx->state[4][4] = in_ctx->state[1][4];
}

static void mbedtls_keccakf_chi_iota( const mbedtls_keccakf_context *in_ctx,
                                      mbedtls_keccakf_context *out_ctx,
                                      size_t round_index )
{
    size_t y;

    out_ctx->state[0][0] = in_ctx->state[0][0] ^ ( ( ~in_ctx->state[1][0] ) & in_ctx->state[2][0] )
            ^ round_constants[ round_index ]; /* iota step */

    out_ctx->state[1][0] = in_ctx->state[1][0] ^ ( ( ~in_ctx->state[2][0] ) & in_ctx->state[3][0] );
    out_ctx->state[2][0] = in_ctx->state[2][0] ^ ( ( ~in_ctx->state[3][0] ) & in_ctx->state[4][0] );
    out_ctx->state[3][0] = in_ctx->state[3][0] ^ ( ( ~in_ctx->state[4][0] ) & in_ctx->state[0][0] );
    out_ctx->state[4][0] = in_ctx->state[4][0] ^ ( ( ~in_ctx->state[0][0] ) & in_ctx->state[1][0] );

    for ( y = 1U; y < 5U; y++ )
    {
        out_ctx->state[0][y] = in_ctx->state[0][y] ^ ( ( ~in_ctx->state[1][y] ) & in_ctx->state[2][y] );
        out_ctx->state[1][y] = in_ctx->state[1][y] ^ ( ( ~in_ctx->state[2][y] ) & in_ctx->state[3][y] );
        out_ctx->state[2][y] = in_ctx->state[2][y] ^ ( ( ~in_ctx->state[3][y] ) & in_ctx->state[4][y] );
        out_ctx->state[3][y] = in_ctx->state[3][y] ^ ( ( ~in_ctx->state[4][y] ) & in_ctx->state[0][y] );
        out_ctx->state[4][y] = in_ctx->state[4][y] ^ ( ( ~in_ctx->state[0][y] ) & in_ctx->state[1][y] );
    }
}

void mbedtls_keccakf_init( mbedtls_keccakf_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_zeroize(&ctx->state, sizeof(ctx->state));
    }
}

void mbedtls_keccakf_free( mbedtls_keccakf_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_zeroize(&ctx->state, sizeof(ctx->state));
    }
}

void mbedtls_keccakf_clone( mbedtls_keccakf_context *dst,
                            const mbedtls_keccakf_context *src )
{
    *dst = *src;
}

int mbedtls_keccakf_permute( mbedtls_keccakf_context *ctx )
{
    mbedtls_keccakf_context temp_state;
    size_t i;

    if ( ctx == NULL )
    {
        return( MBEDTLS_ERR_KECCAKF_BAD_INPUT_DATA );
    }

    for ( i = 0U; i < 24U; i++ )
    {
        mbedtls_keccakf_theta   ( ctx        , &temp_state );
        mbedtls_keccakf_rho     ( &temp_state, ctx         );
        mbedtls_keccakf_pi      ( ctx        , &temp_state );
        mbedtls_keccakf_chi_iota( &temp_state, ctx         , i );
    }

    mbedtls_zeroize( &temp_state, sizeof(temp_state) );

    return( 0 );
}

int mbedtls_keccakf_xor_binary( mbedtls_keccakf_context *ctx,
                                const unsigned char *data,
                                size_t size_bits )
{
    size_t x = 0U;
    size_t y = 0U;
    size_t remaining_bits = size_bits;
    size_t data_offset = 0U;

    if ( ( ctx == NULL ) || ( data == NULL ) || ( size_bits > MBEDTLS_KECCAKF_STATE_SIZE_BITS ) )
    {
        return( MBEDTLS_ERR_KECCAKF_BAD_INPUT_DATA );
    }

    /* process whole lanes */
    while ( remaining_bits >= 64U )
    {
        ctx->state[x][y] ^= (uint64_t)data[data_offset] |
                            (uint64_t)( (uint64_t)data[data_offset + 1U] << 8U  ) |
                            (uint64_t)( (uint64_t)data[data_offset + 2U] << 16U ) |
                            (uint64_t)( (uint64_t)data[data_offset + 3U] << 24U ) |
                            (uint64_t)( (uint64_t)data[data_offset + 4U] << 32U ) |
                            (uint64_t)( (uint64_t)data[data_offset + 5U] << 40U ) |
                            (uint64_t)( (uint64_t)data[data_offset + 6U] << 48U ) |
                            (uint64_t)( (uint64_t)data[data_offset + 7U] << 56U );

        x = ( x + 1U ) % 5U;
        if ( x == 0U )
        {
            y = y + 1U;
        }

        data_offset    += 8U;
        remaining_bits -= 64U;
    }

    /* process last (partial) lane */
    if ( remaining_bits > 0U )
    {
        uint64_t lane = ctx->state[x][y];
        uint64_t byte_offset = 0U;

        /* whole bytes */
        while ( remaining_bits >= 8U )
        {
            lane ^= (uint64_t)( (uint64_t)data[data_offset] << ( byte_offset * 8U ) );

            data_offset++;
            byte_offset++;
            remaining_bits -= 8U;
        }

        /* final bits */
        if ( remaining_bits > 0U )
        {
            /* mask away higher bits to avoid accidentally XORIng them */
            unsigned char mask = ((uint64_t)(1U << remaining_bits) - 1U);
            unsigned char byte = data[data_offset] & mask;

            lane ^= (uint64_t)( (uint64_t)byte << ( byte_offset * 8U ) );
        }

        ctx->state[x][y] = lane;
    }

    return( 0 );
}

int mbedtls_keccakf_read_binary( mbedtls_keccakf_context *ctx,
        unsigned char *data,
        size_t size )
{
    size_t x = 0U;
    size_t y = 0U;
    size_t i;
    size_t remaining_bytes = size;
    size_t data_offset = 0U;

    if ( ( ctx == NULL ) || ( data == NULL ) || ( size > MBEDTLS_KECCAKF_STATE_SIZE_BYTES ) )
    {
        return( MBEDTLS_ERR_KECCAKF_BAD_INPUT_DATA );
    }

    /* process whole lanes */
    while ( remaining_bytes >= 8U )
    {
        const uint64_t lane = ctx->state[x][y];

        data[data_offset     ] = (uint8_t)lane;
        data[data_offset + 1U] = (uint8_t)( lane >> 8U  );
        data[data_offset + 2U] = (uint8_t)( lane >> 16U );
        data[data_offset + 3U] = (uint8_t)( lane >> 24U );
        data[data_offset + 4U] = (uint8_t)( lane >> 32U );
        data[data_offset + 5U] = (uint8_t)( lane >> 40U );
        data[data_offset + 6U] = (uint8_t)( lane >> 48U );
        data[data_offset + 7U] = (uint8_t)( lane >> 56U );

        x = ( x + 1U ) % 5U;
        if ( x == 0U )
        {
            y = y + 1U;
        }

        data_offset     += 8U;
        remaining_bytes -= 8U;
    }

    /* Process last (partial) lane */
    if ( remaining_bytes > 0U )
    {
        const uint64_t lane = ctx->state[x][y];

        for ( i = 0U; i < remaining_bytes; i++ )
        {
            data[data_offset + i] = (uint8_t)( lane >> ( i * 8U ) );
        }
    }

    return( 0 );
}

#endif /* MBEDTLS_KECCAKF_ALT */

#endif /* MBEDTLS_KECCAKF_C */
