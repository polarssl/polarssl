/**
 * \file keccak.c
 *
 * \brief Keccak-f[1600] and sponge implementation for mbed TLS
 *
 * \author Daniel King <damaki.gh@gmail.com>
 */
/*  Copyright (C) 2006-2018, ARM Limited, All Rights Reserved
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

#if defined(MBEDTLS_KECCAK_C)

#include "mbedtls/keccak.h"

#include <stddef.h>
#include <string.h>

#if !( defined(MBEDTLS_KECCAK_F_ALT) || defined(MBEDTLS_KECCAK_SPONGE_ALT) )
/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}
#endif



#if !defined(MBEDTLS_KECCAK_F_ALT)

#define ROTL64( x, amount ) ( (uint64_t) ( x << amount) | ( x >> ( 64 - amount ) ) )

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

/**
 * \brief               Keccak Theta round operation.
 *
 *                      This function implements the algorithm specified in
 *                      Section 3.2.1 of NIST FIPS PUB 202.
 *
 * \param in_state      The Keccak state to transform.
 * \param out_state     The transformed state is written here.
 */
static inline void mbedtls_keccak_f_theta( uint64_t in_state[5][5],
                                           uint64_t out_state[5][5] )
{
    uint64_t cl;
    uint64_t cr;
    uint64_t d;

    cl = in_state[4][0] ^ in_state[4][1] ^ in_state[4][2] ^ in_state[4][3] ^ in_state[4][4];
    cr = in_state[1][0] ^ in_state[1][1] ^ in_state[1][2] ^ in_state[1][3] ^ in_state[1][4];
    d = cl ^ ROTL64( cr, 1 );
    out_state[0][0] = in_state[0][0] ^ d;
    out_state[0][1] = in_state[0][1] ^ d;
    out_state[0][2] = in_state[0][2] ^ d;
    out_state[0][3] = in_state[0][3] ^ d;
    out_state[0][4] = in_state[0][4] ^ d;

    cl = in_state[0][0] ^ in_state[0][1] ^ in_state[0][2] ^ in_state[0][3] ^ in_state[0][4];
    cr = in_state[2][0] ^ in_state[2][1] ^ in_state[2][2] ^ in_state[2][3] ^ in_state[2][4];
    d = cl ^ ROTL64( cr, 1 );
    out_state[1][0] = in_state[1][0] ^ d;
    out_state[1][1] = in_state[1][1] ^ d;
    out_state[1][2] = in_state[1][2] ^ d;
    out_state[1][3] = in_state[1][3] ^ d;
    out_state[1][4] = in_state[1][4] ^ d;

    cl = in_state[1][0] ^ in_state[1][1] ^ in_state[1][2] ^ in_state[1][3] ^ in_state[1][4];
    cr = in_state[3][0] ^ in_state[3][1] ^ in_state[3][2] ^ in_state[3][3] ^ in_state[3][4];
    d = cl ^ ROTL64( cr, 1 );
    out_state[2][0] = in_state[2][0] ^ d;
    out_state[2][1] = in_state[2][1] ^ d;
    out_state[2][2] = in_state[2][2] ^ d;
    out_state[2][3] = in_state[2][3] ^ d;
    out_state[2][4] = in_state[2][4] ^ d;

    cl = in_state[2][0] ^ in_state[2][1] ^ in_state[2][2] ^ in_state[2][3] ^ in_state[2][4];
    cr = in_state[4][0] ^ in_state[4][1] ^ in_state[4][2] ^ in_state[4][3] ^ in_state[4][4];
    d = cl ^ ROTL64( cr, 1 );
    out_state[3][0] = in_state[3][0] ^ d;
    out_state[3][1] = in_state[3][1] ^ d;
    out_state[3][2] = in_state[3][2] ^ d;
    out_state[3][3] = in_state[3][3] ^ d;
    out_state[3][4] = in_state[3][4] ^ d;

    cl = in_state[3][0] ^ in_state[3][1] ^ in_state[3][2] ^ in_state[3][3] ^ in_state[3][4];
    cr = in_state[0][0] ^ in_state[0][1] ^ in_state[0][2] ^ in_state[0][3] ^ in_state[0][4];
    d = cl ^ ROTL64( cr, 1 );
    out_state[4][0] = in_state[4][0] ^ d;
    out_state[4][1] = in_state[4][1] ^ d;
    out_state[4][2] = in_state[4][2] ^ d;
    out_state[4][3] = in_state[4][3] ^ d;
    out_state[4][4] = in_state[4][4] ^ d;
}

/**
 * \brief               Keccak Rho round operation.
 *
 *                      This function implements the algorithm specified in
 *                      Section 3.2.2 of NIST FIPS PUB 202.
 *
 * \param in_state      The Keccak state to transform.
 * \param out_state     The transformed state is written here.
 */
static inline void mbedtls_keccak_f_rho( uint64_t in_state[5][5],
                                         uint64_t out_state[5][5] )
{
    out_state[0][0] =         in_state[0][0];
    out_state[0][1] = ROTL64( in_state[0][1], 36 );
    out_state[0][2] = ROTL64( in_state[0][2], 3  );
    out_state[0][3] = ROTL64( in_state[0][3], 41 );
    out_state[0][4] = ROTL64( in_state[0][4], 18 );

    out_state[1][0] = ROTL64( in_state[1][0], 1  );
    out_state[1][1] = ROTL64( in_state[1][1], 44 );
    out_state[1][2] = ROTL64( in_state[1][2], 10 );
    out_state[1][3] = ROTL64( in_state[1][3], 45 );
    out_state[1][4] = ROTL64( in_state[1][4], 2  );

    out_state[2][0] = ROTL64( in_state[2][0], 62 );
    out_state[2][1] = ROTL64( in_state[2][1], 6  );
    out_state[2][2] = ROTL64( in_state[2][2], 43 );
    out_state[2][3] = ROTL64( in_state[2][3], 15 );
    out_state[2][4] = ROTL64( in_state[2][4], 61 );

    out_state[3][0] = ROTL64( in_state[3][0], 28 );
    out_state[3][1] = ROTL64( in_state[3][1], 55 );
    out_state[3][2] = ROTL64( in_state[3][2], 25 );
    out_state[3][3] = ROTL64( in_state[3][3], 21 );
    out_state[3][4] = ROTL64( in_state[3][4], 56 );

    out_state[4][0] = ROTL64( in_state[4][0], 27 );
    out_state[4][1] = ROTL64( in_state[4][1], 20 );
    out_state[4][2] = ROTL64( in_state[4][2], 39 );
    out_state[4][3] = ROTL64( in_state[4][3], 8  );
    out_state[4][4] = ROTL64( in_state[4][4], 14 );
}

/**
 * \brief               Keccak Pi round operation.
 *
 *                      This function implements the algorithm specified in
 *                      Section 3.2.3 of NIST FIPS PUB 202.
 *
 * \param in_state      The Keccak state to transform.
 * \param out_state     The transformed state is written here.
 */
static inline void mbedtls_keccak_f_pi( uint64_t in_state[5][5],
                                        uint64_t out_state[5][5] )
{
    out_state[0][0] = in_state[0][0];
    out_state[0][1] = in_state[3][0];
    out_state[0][2] = in_state[1][0];
    out_state[0][3] = in_state[4][0];
    out_state[0][4] = in_state[2][0];

    out_state[1][0] = in_state[1][1];
    out_state[1][1] = in_state[4][1];
    out_state[1][2] = in_state[2][1];
    out_state[1][3] = in_state[0][1];
    out_state[1][4] = in_state[3][1];

    out_state[2][0] = in_state[2][2];
    out_state[2][1] = in_state[0][2];
    out_state[2][2] = in_state[3][2];
    out_state[2][3] = in_state[1][2];
    out_state[2][4] = in_state[4][2];

    out_state[3][0] = in_state[3][3];
    out_state[3][1] = in_state[1][3];
    out_state[3][2] = in_state[4][3];
    out_state[3][3] = in_state[2][3];
    out_state[3][4] = in_state[0][3];

    out_state[4][0] = in_state[4][4];
    out_state[4][1] = in_state[2][4];
    out_state[4][2] = in_state[0][4];
    out_state[4][3] = in_state[3][4];
    out_state[4][4] = in_state[1][4];
}

/**
 * \brief               Keccak Chi and Iota round operations.
 *
 *                      This function implements the algorithm specified in
 *                      Sections 3.2.4 and 3.2.5 of NIST FIPS PUB 202.
 *
 *                      The Iota operation is merged into the Chi operation
 *                      to reduce unnecessary overhead.
 *
 * \param in_state      The Keccak state to transform.
 * \param out_state     The transformed state is written here.
 * \param round_index   The index of the current round in the interval [0,23].
 */
static inline void mbedtls_keccak_f_chi_iota( uint64_t in_state[5][5],
                                              uint64_t out_state[5][5],
                                              size_t round_index )
{
    out_state[0][0] = in_state[0][0] ^ ( ( ~in_state[1][0] ) & in_state[2][0] )
            ^ round_constants[ round_index ]; /* iota step */

    out_state[0][1] = in_state[0][1] ^ ( ( ~in_state[1][1] ) & in_state[2][1] );
    out_state[0][2] = in_state[0][2] ^ ( ( ~in_state[1][2] ) & in_state[2][2] );
    out_state[0][3] = in_state[0][3] ^ ( ( ~in_state[1][3] ) & in_state[2][3] );
    out_state[0][4] = in_state[0][4] ^ ( ( ~in_state[1][4] ) & in_state[2][4] );

    out_state[2][0] = in_state[2][0] ^ ( ( ~in_state[3][0] ) & in_state[4][0] );
    out_state[2][1] = in_state[2][1] ^ ( ( ~in_state[3][1] ) & in_state[4][1] );
    out_state[2][2] = in_state[2][2] ^ ( ( ~in_state[3][2] ) & in_state[4][2] );
    out_state[2][3] = in_state[2][3] ^ ( ( ~in_state[3][3] ) & in_state[4][3] );
    out_state[2][4] = in_state[2][4] ^ ( ( ~in_state[3][4] ) & in_state[4][4] );

    out_state[4][0] = in_state[4][0] ^ ( ( ~in_state[0][0] ) & in_state[1][0] );
    out_state[4][1] = in_state[4][1] ^ ( ( ~in_state[0][1] ) & in_state[1][1] );
    out_state[4][2] = in_state[4][2] ^ ( ( ~in_state[0][2] ) & in_state[1][2] );
    out_state[4][3] = in_state[4][3] ^ ( ( ~in_state[0][3] ) & in_state[1][3] );
    out_state[4][4] = in_state[4][4] ^ ( ( ~in_state[0][4] ) & in_state[1][4] );

    out_state[1][0] = in_state[1][0] ^ ( ( ~in_state[2][0] ) & in_state[3][0] );
    out_state[1][1] = in_state[1][1] ^ ( ( ~in_state[2][1] ) & in_state[3][1] );
    out_state[1][2] = in_state[1][2] ^ ( ( ~in_state[2][2] ) & in_state[3][2] );
    out_state[1][3] = in_state[1][3] ^ ( ( ~in_state[2][3] ) & in_state[3][3] );
    out_state[1][4] = in_state[1][4] ^ ( ( ~in_state[2][4] ) & in_state[3][4] );

    out_state[3][0] = in_state[3][0] ^ ( ( ~in_state[4][0] ) & in_state[0][0] );
    out_state[3][1] = in_state[3][1] ^ ( ( ~in_state[4][1] ) & in_state[0][1] );
    out_state[3][2] = in_state[3][2] ^ ( ( ~in_state[4][2] ) & in_state[0][2] );
    out_state[3][3] = in_state[3][3] ^ ( ( ~in_state[4][3] ) & in_state[0][3] );
    out_state[3][4] = in_state[3][4] ^ ( ( ~in_state[4][4] ) & in_state[0][4] );
}

void mbedtls_keccak_f_init( mbedtls_keccak_f_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_zeroize( &ctx->state, sizeof( ctx->state ) );
        mbedtls_zeroize( &ctx->temp, sizeof( ctx->temp ) );
    }
}

void mbedtls_keccak_f_free( mbedtls_keccak_f_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_zeroize( &ctx->state, sizeof( ctx->state ) );
        mbedtls_zeroize( &ctx->temp, sizeof( ctx->temp ) );
    }
}

void mbedtls_keccak_f_clone( mbedtls_keccak_f_context *dst,
                             const mbedtls_keccak_f_context *src )
{
    *dst = *src;
}

int mbedtls_keccak_f_permute( mbedtls_keccak_f_context *ctx )
{
    size_t i;

    if ( ctx == NULL )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA );
    }

    for ( i = 0U; i < 24U; i++ )
    {
        mbedtls_keccak_f_theta   ( ctx->state, ctx->temp );
        mbedtls_keccak_f_rho     ( ctx->temp , ctx->state );
        mbedtls_keccak_f_pi      ( ctx->state, ctx->temp );
        mbedtls_keccak_f_chi_iota( ctx->temp , ctx->state, i );
    }

    return( 0 );
}

int mbedtls_keccak_f_xor_binary( mbedtls_keccak_f_context *ctx,
                                 const unsigned char *data,
                                 size_t size_bits )
{
    size_t x = 0U;
    size_t y = 0U;
    size_t remaining_bits = size_bits;
    size_t data_offset = 0U;

    if ( ( ctx == NULL ) || ( data == NULL ) || ( size_bits > MBEDTLS_KECCAK_F_STATE_SIZE_BITS ) )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA );
    }

    /* process whole lanes */
    while ( remaining_bits >= 64U )
    {
        ctx->state[x][y] ^= (uint64_t) data[data_offset]
                            | (uint64_t) ( (uint64_t) data[data_offset + 1U] << 8U  )
                            | (uint64_t) ( (uint64_t) data[data_offset + 2U] << 16U )
                            | (uint64_t) ( (uint64_t) data[data_offset + 3U] << 24U )
                            | (uint64_t) ( (uint64_t) data[data_offset + 4U] << 32U )
                            | (uint64_t) ( (uint64_t) data[data_offset + 5U] << 40U )
                            | (uint64_t) ( (uint64_t) data[data_offset + 6U] << 48U )
                            | (uint64_t) ( (uint64_t) data[data_offset + 7U] << 56U );

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
        uint64_t shift = 0U;

        /* whole bytes */
        while ( remaining_bits >= 8U )
        {
            lane ^= (uint64_t) ( (uint64_t) data[data_offset] << shift );

            data_offset++;
            shift          += 8U;
            remaining_bits -= 8U;
        }

        /* final bits */
        if ( remaining_bits > 0U )
        {
            /* mask away higher bits to avoid accidentally XORIng them */
            unsigned char mask = ((uint64_t) (1U << remaining_bits) - 1U);
            unsigned char byte = data[data_offset] & mask;

            lane ^= (uint64_t) ( (uint64_t) byte << ( shift * 8U ) );
        }

        ctx->state[x][y] = lane;
    }

    return( 0 );
}

int mbedtls_keccak_f_read_binary( mbedtls_keccak_f_context *ctx,
                                  unsigned char *data,
                                  size_t size )
{
    size_t x = 0U;
    size_t y = 0U;
    size_t i;
    size_t remaining_bytes = size;
    size_t data_offset = 0U;

    if ( ( ctx == NULL ) || ( data == NULL ) || ( size > MBEDTLS_KECCAK_F_STATE_SIZE_BYTES ) )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA );
    }

    /* process whole lanes */
    while ( remaining_bytes >= 8U )
    {
        const uint64_t lane = ctx->state[x][y];

        data[data_offset     ] = (uint8_t) lane;
        data[data_offset + 1U] = (uint8_t) ( lane >> 8U  );
        data[data_offset + 2U] = (uint8_t) ( lane >> 16U );
        data[data_offset + 3U] = (uint8_t) ( lane >> 24U );
        data[data_offset + 4U] = (uint8_t) ( lane >> 32U );
        data[data_offset + 5U] = (uint8_t) ( lane >> 40U );
        data[data_offset + 6U] = (uint8_t) ( lane >> 48U );
        data[data_offset + 7U] = (uint8_t) ( lane >> 56U );

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
            data[data_offset + i] = (uint8_t) ( lane >> ( i * 8U ) );
        }
    }

    return( 0 );
}

#endif /* !defined(MBEDTLS_KECCAK_F_ALT) */



#if !defined(MBEDTLS_KECCAK_SPONGE_ALT)

#define SPONGE_STATE_UNINIT           ( 0 )
#define SPONGE_STATE_ABSORBING        ( 1 )
#define SPONGE_STATE_READY_TO_SQUEEZE ( 2 )
#define SPONGE_STATE_SQUEEZING        ( 3 )

/**
 * \brief       Absorbs the suffix bits into the context.
 *
 * \pre         ctx                != NULL
 * \pre         ctx->queue_len     <  ctx->rate
 * \pre         ctx->queue_len % 8 == 0
 * \pre         ctx->rate % 8      == 0
 * \pre         ctx->suffix_len    <= 8
 *
 * \param ctx   The sponge context. Must not be NULL.
 */
static void mbedtls_keccak_sponge_absorb_suffix( mbedtls_keccak_sponge_context *ctx )
{
    if ( ctx->suffix_len > 0U )
    {
        ctx->queue[ctx->queue_len / 8U] = ctx->suffix;
        ctx->queue_len += ctx->suffix_len;
    }

    if ( ctx->queue_len >= ctx->rate )
    {
        ctx->queue_len = 0U;

        (void) mbedtls_keccak_f_xor_binary( &ctx->keccak_f_ctx, ctx->queue, ctx->rate );
        (void) mbedtls_keccak_f_permute ( &ctx->keccak_f_ctx );
    }
}

/**
 * \brief       Finish the absorption phase and switch to the absorbing phase.
 *
 *              This function absorbs the suffix bits into the sponge state,
 *              adds the padding bits (using the pad10*1 rule), and finally
 *              generates the first block of output bits.
 *
 * \pre         ctx                != NULL
 * \pre         ctx->queue_len     <  ctx->rate
 * \pre         ctx->queue_len % 8 == 0
 * \pre         ctx->rate % 8      == 0
 * \pre         ctx->suffix_len    <= 8
 *
 * \param ctx   The sponge context. Must not be NULL.
 */
static void mbedtls_keccak_sponge_finalize( mbedtls_keccak_sponge_context *ctx )
{
    size_t bits_free_in_queue;

    mbedtls_keccak_sponge_absorb_suffix( ctx );

    bits_free_in_queue = ctx->rate - ctx->queue_len;

    /* Add padding (pad10*1 rule). This adds at least 2 bits */
    /* Note that there might only be 1 bit free if there was 1 byte free in the
     * queue before the suffix was added, and the suffix length is 7 bits.
     */
    if (bits_free_in_queue >= 2U)
    {
        /* Set first bit */
        ctx->queue[ctx->queue_len / 8U] &= ( (unsigned char) ( 1U << ( ctx->queue_len % 8U ) ) ) - 1U;
        ctx->queue[ctx->queue_len / 8U] |= (unsigned char) ( 1U << ( ctx->queue_len % 8U ) );

        /* Add zeroes (if necessary) */
        if ( bits_free_in_queue >= 8U )
        {
            memset( &ctx->queue[( ctx->queue_len / 8U ) + 1U],
                    0,
                    ( ctx->rate - ctx->queue_len ) / 8U );
        }

        /* Add last bit */
        ctx->queue[( ctx->rate - 1U ) / 8U] |= 0x80U;
    }
    else
    {
        /* Only 1 free bit in the block, but we need to add 2 bits, so the second
         * bit spills over to another block.
         */

        /* Add first bit to complete the first block */
        ctx->queue[ctx->queue_len / 8U] |= 0x80U;

        (void) mbedtls_keccak_f_xor_binary( &ctx->keccak_f_ctx, ctx->queue, ctx->rate );
        (void) mbedtls_keccak_f_permute ( &ctx->keccak_f_ctx );

        /* Set the next block to complete the padding */
        memset( ctx->queue, 0, ctx->rate / 8U );
        ctx->queue[( ctx->rate - 1U ) / 8U] |= 0x80U;
    }

    (void) mbedtls_keccak_f_xor_binary( &ctx->keccak_f_ctx, ctx->queue, ctx->rate );
    (void) mbedtls_keccak_f_permute ( &ctx->keccak_f_ctx );

    ctx->state = SPONGE_STATE_SQUEEZING;

    /* Get initial output data into the queue */
    (void) mbedtls_keccak_f_read_binary( &ctx->keccak_f_ctx, ctx->queue, ctx->rate / 8U );
    ctx->queue_len = ctx->rate;
}

void mbedtls_keccak_sponge_init( mbedtls_keccak_sponge_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_keccak_f_init( &ctx->keccak_f_ctx );
        mbedtls_zeroize( ctx->queue, sizeof( ctx->queue ) );
        ctx->queue_len  = 0U;
        ctx->rate       = 0U;
        ctx->suffix_len = 0U;
        ctx->state      = SPONGE_STATE_UNINIT;
        ctx->suffix     = 0U;
    }
}

void mbedtls_keccak_sponge_free( mbedtls_keccak_sponge_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_keccak_f_free( &ctx->keccak_f_ctx );
        mbedtls_zeroize( ctx->queue, sizeof( ctx->queue ) );
        ctx->queue_len  = 0U;
        ctx->rate       = 0U;
        ctx->suffix_len = 0U;
        ctx->state      = SPONGE_STATE_UNINIT;
        ctx->suffix     = 0U;
    }
}

void mbedtls_keccak_sponge_clone( mbedtls_keccak_sponge_context *dst,
                                  const mbedtls_keccak_sponge_context *src )
{
    *dst = *src;
}

int mbedtls_keccak_sponge_starts( mbedtls_keccak_sponge_context *ctx,
                                  size_t capacity,
                                  unsigned char suffix,
                                  size_t suffix_len  )
{
    if ( ctx == NULL )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA );
    }
    else if ( ( capacity == 0U ) ||
              ( capacity >= MBEDTLS_KECCAK_F_STATE_SIZE_BITS ) ||
              ( ( capacity % 8U ) != 0U ) )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA );
    }
    else if ( suffix_len > 8U )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA );
    }
    else if ( ctx->state != SPONGE_STATE_UNINIT )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_STATE );
    }
    else
    {
        ctx->rate       = MBEDTLS_KECCAK_F_STATE_SIZE_BITS - capacity;
        ctx->suffix_len = suffix_len;
        ctx->suffix     = suffix & ( (unsigned char) ( 1U << suffix_len ) - 1U );
    }

    return( 0 );
}

int mbedtls_keccak_sponge_absorb( mbedtls_keccak_sponge_context *ctx,
                                  const unsigned char* data,
                                  size_t size )
{
    size_t data_offset = 0U;
    size_t remaining_bytes = size;
    size_t rate_bytes;

    if ( ( ctx == NULL ) || ( data == NULL ) )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA );
    }
    else if ( ctx->rate == 0U )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_STATE );
    }
    else if ( ctx->state > SPONGE_STATE_ABSORBING )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_STATE );
    }

    if ( remaining_bytes > 0U )
    {
        rate_bytes = ctx->rate / 8U;

        /* Check if there are leftover bytes in the queue from previous invocations */
        if ( ctx->queue_len > 0U )
        {
            size_t queue_free_bytes = (ctx->rate - ctx->queue_len) / 8U;

            if ( remaining_bytes >= queue_free_bytes )
            {
                /* Enough data to fill the queue */
                memcpy( &ctx->queue[ctx->queue_len / 8U],
                        data,
                        queue_free_bytes );

                ctx->queue_len = 0U;

                data_offset     += queue_free_bytes;
                remaining_bytes -= queue_free_bytes;

                (void) mbedtls_keccak_f_xor_binary( &ctx->keccak_f_ctx, ctx->queue, ctx->rate );
                (void) mbedtls_keccak_f_permute( &ctx->keccak_f_ctx );
            }
            else
            {
                /* Not enough data to completely fill the queue.
                 * Store this data with the other leftovers
                 */
                memcpy( &ctx->queue[ctx->queue_len / 8U],
                        data,
                        remaining_bytes );

                ctx->queue_len += remaining_bytes * 8U;
                remaining_bytes = 0U;
            }
        }

        /* Process whole blocks */
        while ( remaining_bytes >= rate_bytes )
        {
            (void) mbedtls_keccak_f_xor_binary( &ctx->keccak_f_ctx, &data[data_offset], ctx->rate );
            (void) mbedtls_keccak_f_permute( &ctx->keccak_f_ctx );

            data_offset     += rate_bytes;
            remaining_bytes -= rate_bytes;
        }

        /* Store leftovers in the queue */
        if ( remaining_bytes > 0U )
        {
            memcpy( ctx->queue, &data[data_offset], remaining_bytes );
            ctx->queue_len = remaining_bytes * 8U;
        }
    }

    return( 0 );
}

int mbedtls_keccak_sponge_squeeze( mbedtls_keccak_sponge_context *ctx,
                                   unsigned char* data,
                                   size_t size )
{
    size_t queue_offset;
    size_t data_offset = 0U;
    size_t queue_len_bytes;
    size_t rate_bytes;

    if ( ( ctx == NULL ) || ( data == NULL ) )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA );
    }
    else if ( ctx->rate == 0U )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_STATE );
    }
    else if ( ctx->state > SPONGE_STATE_SQUEEZING )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_STATE );
    }

    if ( ctx->state < SPONGE_STATE_SQUEEZING )
    {
        mbedtls_keccak_sponge_finalize( ctx );
    }

    if ( size > 0U )
    {
        rate_bytes      = ctx->rate / 8U;
        queue_offset    = (ctx->rate - ctx->queue_len) / 8U;
        queue_len_bytes = ctx->queue_len / 8U;

        /* Consume data from the queue */
        if ( size < queue_len_bytes )
        {
            /* Not enough output requested to empty the queue */
            memcpy ( data, &ctx->queue[queue_offset], size);

            ctx->queue_len -= size * 8U;
            size = 0U;
        }
        else
        {
            /* Consume all data from the output queue */

            memcpy (data, &ctx->queue[queue_offset], queue_len_bytes );

            data_offset += queue_len_bytes;
            size        -= queue_len_bytes;

            ctx->queue_len = 0U;
        }

        /* Process whole blocks */
        while ( size >= rate_bytes )
        {
            (void) mbedtls_keccak_f_permute( &ctx->keccak_f_ctx );
            (void) mbedtls_keccak_f_read_binary( &ctx->keccak_f_ctx,
                                                &data[data_offset],
                                                rate_bytes );

            data_offset += rate_bytes;
            size        -= rate_bytes;
        }

        /* Process last (partial) block */
        if ( size > 0U )
        {
            (void) mbedtls_keccak_f_permute( &ctx->keccak_f_ctx );
            (void) mbedtls_keccak_f_read_binary( &ctx->keccak_f_ctx,
                                                ctx->queue,
                                                rate_bytes );

            memcpy( &data[data_offset], ctx->queue, size );

            ctx->queue_len = ctx->rate - ( size  * 8U );
        }

        if ( ctx->queue_len == 0U )
        {
            /* Generate next block of output for future calls */
            (void) mbedtls_keccak_f_permute( &ctx->keccak_f_ctx );
            (void) mbedtls_keccak_f_read_binary( &ctx->keccak_f_ctx,
                                                ctx->queue,
                                                rate_bytes );

            ctx->queue_len = ctx->rate;
        }
    }

    return( 0 );
}

int mbedtls_keccak_sponge_process( mbedtls_keccak_sponge_context *ctx,
                                   const unsigned char *input )
{
    if ( ( ctx == NULL ) || ( input == NULL ) )
    {
        return( MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA );
    }

    (void) mbedtls_keccak_f_xor_binary( &ctx->keccak_f_ctx, input, ctx->rate );
    (void) mbedtls_keccak_f_permute( &ctx->keccak_f_ctx );

    return( 0 );
}

#endif /* !defined(MBEDTLS_KECCAK_SPONGE_ALT) */

#endif /* MBEDTLS_KECCAK_C */
