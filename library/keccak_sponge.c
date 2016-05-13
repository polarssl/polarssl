/**
 * \file keccak_sponge.c
 *
 * \brief Sponge cryptographic construction built on the Keccak-f[1600] permutation
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

#if defined(MBEDTLS_KECCAK_SPONGE_C)

#if !defined(MBEDTLS_KECCAK_SPONGE_ALT)

#include "mbedtls/keccak_sponge.h"

#include <stddef.h>
#include <string.h>

#define MBEDTLS_KECCAK_SPONGE_STATE_UNINIT           (0)
#define MBEDTLS_KECCAK_SPONGE_STATE_ABSORBING        (1)
#define MBEDTLS_KECCAK_SPONGE_STATE_READY_TO_SQUEEZE (2)
#define MBEDTLS_KECCAK_SPONGE_STATE_SQUEEZING        (3)


/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/**
 * \brief       Absorbs the suffix bits into the context.
 *
 * \pre         ctx             != NULL
 * \pre         ctx->queue_len  <  ctx->rate
 * \pre         ctx->rate % 8   == 0
 * \pre         ctx->suffix_len <= 8
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

        (void)mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx, ctx->queue, ctx->rate );
        (void)mbedtls_keccakf_permute ( &ctx->keccakf_ctx );
    }
}

/**
 * \brief       Finish the absorption phase and switch to the absorbing phase.
 *
 *              This function absorbs the suffix bits into the sponge state,
 *              adds the padding bits (using the pad10*1 rule), and finally
 *              generates the first block of output bits.
 *
 * \pre         ctx             != NULL
 * \pre         ctx->queue_len  <  ctx->rate
 * \pre         ctx->rate % 8   == 0
 * \pre         ctx->suffix_len <= 8
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
        ctx->queue[ctx->queue_len / 8U] &= ( (unsigned char)( 1U << ( ctx->queue_len % 8U ) ) ) - 1U;
        ctx->queue[ctx->queue_len / 8U] |= (unsigned char)( 1U << ( ctx->queue_len % 8U ) );

        /* Add zeroes (if necessary) */
        if ( bits_free_in_queue >= 8U )
        {
            memset( &ctx->queue[( ctx->queue_len / 8U ) + 1U],
                    0,
                    ( ctx->rate - ( ctx->queue_len + 8U ) ) / 8U );
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

        (void)mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx, ctx->queue, ctx->rate );
        (void)mbedtls_keccakf_permute ( &ctx->keccakf_ctx );

        /* Set the next block to complete the padding */
        memset( ctx->queue, 0, ctx->rate / 8U );
        ctx->queue[( ctx->rate - 1U ) / 8U] |= 0x80U;
    }

    (void)mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx, ctx->queue, ctx->rate );
    (void)mbedtls_keccakf_permute ( &ctx->keccakf_ctx );

    ctx->state = MBEDTLS_KECCAK_SPONGE_STATE_SQUEEZING;

    /* Get initial output data into the queue */
    (void)mbedtls_keccakf_read_binary( &ctx->keccakf_ctx, ctx->queue, ctx->rate / 8U );
    ctx->queue_len = ctx->rate;
}

void mbedtls_keccak_sponge_init( mbedtls_keccak_sponge_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_keccakf_init( &ctx->keccakf_ctx );
        mbedtls_zeroize( ctx->queue, sizeof( ctx->queue ) );
        ctx->queue_len  = 0U;
        ctx->rate       = 0U;
        ctx->suffix_len = 0U;
        ctx->state      = MBEDTLS_KECCAK_SPONGE_STATE_UNINIT;
        ctx->suffix     = 0U;
    }
}

void mbedtls_keccak_sponge_free( mbedtls_keccak_sponge_context *ctx )
{
    if ( ctx != NULL )
    {
        mbedtls_keccakf_free( &ctx->keccakf_ctx );
        mbedtls_zeroize( ctx->queue, sizeof( ctx->queue ) );
        ctx->queue_len  = 0U;
        ctx->rate       = 0U;
        ctx->suffix_len = 0U;
        ctx->state      = MBEDTLS_KECCAK_SPONGE_STATE_UNINIT;
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
    if ( ( ctx == NULL ) )
    {
        return( MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA );
    }
    else if ( ( capacity == 0U ) ||
              ( capacity >= MBEDTLS_KECCAKF_STATE_SIZE_BITS ) ||
              ( ( capacity % 8U ) != 0U ) )
    {
        return( MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA );
    }
    else if ( suffix_len > 8U )
    {
        return( MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA );
    }
    else if ( ctx->state != MBEDTLS_KECCAK_SPONGE_STATE_UNINIT )
    {
        return( MBEDTLS_ERR_KECCAK_SPONGE_BAD_STATE );
    }
    else
    {
        ctx->rate       = MBEDTLS_KECCAKF_STATE_SIZE_BITS - capacity;
        ctx->suffix_len = suffix_len;
        ctx->suffix     = suffix & ( (unsigned char)( 1U << suffix_len ) - 1U );
    }

    return 0;
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
        return( MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA );
    }
    else if ( ctx->rate == 0U )
    {
        return( MBEDTLS_ERR_KECCAK_SPONGE_NOT_SETUP );
    }
    else if ( ctx->state > MBEDTLS_KECCAK_SPONGE_STATE_ABSORBING )
    {
        return( MBEDTLS_ERR_KECCAK_SPONGE_BAD_STATE );
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

                (void)mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx, ctx->queue, ctx->rate );
                (void)mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            }
            else
            {
                /* Not enough data to completely fill the queue.
                 * Store this data with the other leftovers
                 */
                memcpy(&ctx->queue[ctx->queue_len / 8U],
                       data,
                       queue_free_bytes );

                ctx->queue_len += queue_free_bytes * 8U;
                remaining_bytes = 0U;
            }
        }

        /* Process whole blocks */
        while ( remaining_bytes >= rate_bytes )
        {
            (void)mbedtls_keccakf_xor_binary( &ctx->keccakf_ctx, &data[data_offset], ctx->rate );
            (void)mbedtls_keccakf_permute( &ctx->keccakf_ctx );

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

    return 0;
}

int mbedtls_keccak_sponge_squeeze( mbedtls_keccak_sponge_context *ctx,
                                   unsigned char* data,
                                   size_t size )
{
    size_t queue_offset;
    size_t data_offset = 0U;
    size_t rate_bytes;

    if ( ( ctx == NULL ) || ( data == NULL ) )
    {
        return( MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA );
    }
    else if ( ctx->rate == 0U )
    {
        return( MBEDTLS_ERR_KECCAK_SPONGE_NOT_SETUP );
    }
    else if ( ctx->state > MBEDTLS_KECCAK_SPONGE_STATE_SQUEEZING )
    {
        return( MBEDTLS_ERR_KECCAK_SPONGE_BAD_STATE );
    }

    if ( ctx->state < MBEDTLS_KECCAK_SPONGE_STATE_SQUEEZING )
    {
        mbedtls_keccak_sponge_finalize( ctx );
    }

    if ( size > 0U )
    {
        rate_bytes   = ctx->rate / 8U;
        queue_offset = (ctx->rate - ctx->queue_len) / 8U;

        /* Consume data from the queue */
        if ( size < ( ctx->queue_len / 8U ) )
        {
            /* Not enough output requested to empty the queue */
            memcpy ( data, &ctx->queue[queue_offset], size);

            ctx->queue_len -= size * 8U;
            size = 0U;
        }
        else
        {
            /* Consume all data from the output queue */
            memcpy (data, &ctx->queue[queue_offset], ctx->queue_len);

            data_offset += ctx->queue_len;
            size        -= ctx->queue_len;

            ctx->queue_len = 0U;
        }

        /* Process whole blocks */
        while ( size >= rate_bytes )
        {
            (void)mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            (void)mbedtls_keccakf_read_binary( &ctx->keccakf_ctx,
                                               &data[data_offset],
                                               rate_bytes );

            data_offset += rate_bytes;
            size        -= rate_bytes;
        }

        /* Process last (partial) block */
        if ( size > 0U )
        {
            (void)mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            (void)mbedtls_keccakf_read_binary( &ctx->keccakf_ctx,
                                               ctx->queue,
                                               rate_bytes );

            memcpy( &data[data_offset], ctx->queue, size );

            ctx->queue_len = ctx->rate - ( size  * 8U );
        }

        if ( ctx->queue_len == 0U )
        {
            /* Generate next block of output for future calls */
            (void)mbedtls_keccakf_permute( &ctx->keccakf_ctx );
            (void)mbedtls_keccakf_read_binary( &ctx->keccakf_ctx,
                                               ctx->queue,
                                               rate_bytes );

            ctx->queue_len = ctx->rate;
        }
    }

    return 0;
}

#endif /* MBEDTLS_KECCAK_SPONGE_ALT */

#endif /* MBEDTLS_KECCAK_SPONGE_C */
