/**
 * \file keccak.h
 *
 * \brief The Keccak-f[1600] permutation and the corresponding sponge construction.
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
#ifndef MBEDTLS_KECCAK_H
#define MBEDTLS_KECCAK_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#define MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA -0x0054 /**< Invalid input parameter(s). */
#define MBEDTLS_ERR_KECCAK_NOT_SETUP      -0x0056 /**< mbedtls_keccak_sponge_starts has not been called. */
#define MBEDTLS_ERR_KECCAK_BAD_STATE      -0x0058 /**< Requested operation cannot be performed with the current context state. */

#define MBEDTLS_KECCAK_F_STATE_SIZE_BITS  ( 1600U )
#define MBEDTLS_KECCAK_F_STATE_SIZE_BYTES ( 1600U / 8U )

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_KECCAK_F_ALT) || defined(MBEDTLS_KECCAK_SPONGE_ALT)
#include "keccak_alt.h"
#endif

#if !defined(MBEDTLS_KECCAK_F_ALT)
typedef struct
{
    uint64_t state[5][5];
    uint64_t temp[5][5];
}
mbedtls_keccak_f_context;
#endif /* !defined(MBEDTLS_KECCAK_F_ALT) */

/**
 * \brief               Initialize a Keccak-f[1600] context.
 *                      This should always be called first.
 *                      Prepares the context for other mbedtls_keccak_f_* functions.
 *
 *                      By default the Keccak state is zeroed.
 */
void mbedtls_keccak_f_init( mbedtls_keccak_f_context *ctx );

/**
 * \brief               Free and clear the internal structures of ctx.
 *                      Can be called at any time after mbedtls_keccak_f_init().
 */
void mbedtls_keccak_f_free( mbedtls_keccak_f_context *ctx );

/**
 * \brief               Clone (the state of) a Keccak-f[1600] context
 *
 * \param dst           The destination context
 * \param src           The context to be cloned
 */
void mbedtls_keccak_f_clone( mbedtls_keccak_f_context *dst,
                             const mbedtls_keccak_f_context *src );

/**
 * \brief               Apply the Keccak permutation to the ctx.
 *
 * \param ctx           The Keccak-f[1600] context to permute.
 *
 * \returns             MBEDTLS_ERR_KECCAKF_BAD_INPUT_DATA if the ctx is NULL.
 *                      Otherwise 0 is returned for success.
 */
int mbedtls_keccak_f_permute( mbedtls_keccak_f_context *ctx );

/**
 * \brief               XOR binary bits into the Keccak state.
 *
 *                      The bytes are XORed starting from the beginning of the
 *                      Keccak state.
 *
 * \param ctx           The Keccak-f[1600] context.
 * \param data          Buffer containing the bytes to XOR into the Keccak state.
 * \param size_bits     The number of bits to XOR into the state.
 *
 * \return              MBEDTLS_ERR_KECCAKF_BAD_INPUT_DATA is returned if \p ctx
 *                      or \p data are NULL, or if size_bits is larger than 1600.
 *                      Otherwise, 0 is returned for success.
 */
int mbedtls_keccak_f_xor_binary( mbedtls_keccak_f_context *ctx,
                                 const unsigned char *data,
                                 size_t size_bits );

/**
 * \brief               Read bytes from the Keccak state.
 *
 *                      The bytes are read starting from the beginning of the
 *                      Keccak state.
 *
 * \param ctx           The Keccak-f[1600] context.
 * \param data          The bytes are written to this buffer.
 * \param size          The number of bytes to read from the Keccak state.
 *
 * \return              MBEDTLS_ERR_KECCAKF_BAD_INPUT_DATA is returned if \p ctx
 *                      or \p data are NULL, or if size is larger than 200.
 *                      Otherwise, 0 is returned for success.
 */
int mbedtls_keccak_f_read_binary( mbedtls_keccak_f_context *ctx,
                                  unsigned char *data,
                                  size_t size );

#if !defined(MBEDTLS_KECCAK_SPONGE_ALT)
typedef struct
{
    mbedtls_keccak_f_context keccak_f_ctx;
    unsigned char queue[1600 / 8]; /** store partial block data (absorbing) or pending output data (squeezing) */
    size_t queue_len;              /** queue length (in bits) */
    size_t rate;                   /** sponge rate (in bits) */
    size_t suffix_len;             /** length of the suffix (in bits) (range 0..8) */
    int state;                     /** Current state (absorbing/ready to squeeze/squeezing) */
    unsigned char suffix;          /** suffix bits appended to message, before padding */
}
mbedtls_keccak_sponge_context;
#endif /* !defined(MBEDTLS_KECCAK_SPONGE_ALT) */

/**
 * \brief               Initialize a Keccak sponge context
 *
 * \param ctx           Context to be initialized
 */
void mbedtls_keccak_sponge_init( mbedtls_keccak_sponge_context *ctx );

/**
 * \brief               Clean a Keccak sponge context
 *
 * \param ctx           Context to be cleared.
 */
void mbedtls_keccak_sponge_free( mbedtls_keccak_sponge_context *ctx );

/**
 * \brief               Clone (the state of) a Keccak Sponge context
 *
 * \param dst           The destination context
 * \param src           The context to be cloned
 */
void mbedtls_keccak_sponge_clone( mbedtls_keccak_sponge_context *dst,
                                  const mbedtls_keccak_sponge_context *src );

/**
 * \brief               Comfigure the sponge context to start streaming.
 *
 * \note                This function can only be called after
 *                      mbedtls_keccak_sponge_init and before the absorb or
 *                      squeeze functions. Otherwise, MBEDTLS_ERR_KECCAK_BAD_STATE
 *                      is returned.
 *
 * \note                This function \b MUST be called after calling
 *                      mbedtls_keccak_sponge_init and before calling the
 *                      absorb or squeeze functions. If this function has not
 *                      been called then the absorb/squeeze functions will
 *                      return MBEDTLS_ERR_KECCAK_NOT_SETUP.
 *
 * \param ctx           The sponge context to setup.
 * \param capacity      The sponge's capacity parameter. This determines the
 *                      security of the sponge. The capacity should be double
 *                      the required security (in bits). For example, if 128 bits
 *                      of security are required then \p capacity should be set
 *                      to 256. This must be a multiple of 8. Must be less than
 *                      1600.
 * \param suffix        A byte containing the suffix bits that are absorbed
 *                      before the padding rule is applied.
 * \param suffix_len    The length (in bits) of the suffix. 8 is the maximum value.
 *
 * \return              MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA is returned if
 *                      ctx is NULL, capacity is too big/small or is not a multiple
 *                      of 8, or if suffix_len is greater than 8.
 *                      MBEDTLS_ERR_KECCAK_BAD_STATE is returned if the
 *                      sponge has not been initialized, or has not been
 *                      re-initialized since it was last used.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_keccak_sponge_starts( mbedtls_keccak_sponge_context *ctx,
                                  size_t capacity,
                                  unsigned char suffix,
                                  size_t suffix_len );

/**
 * \brief               Process input bits into the sponge.
 *
 * \note                This function can be called multiple times to stream
 *                      a large amount of data.
 *
 * \param ctx           The sponge context.
 * \param data          The buffer containing the bits to input into the sponge.
 * \param size          The number of bytes to input.
 *
 * \return              MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA is returned if
 *                      ctx or data is NULL.
 *                      MBEDTLS_ERR_KECCAK_BAD_STATE is returned if the
 *                      sponge can no longer accept data for absorption. This
 *                      occurs when mbedtls_keccak_sponge_squeeze has been previously
 *                      called.
 *                      MBEDTLS_ERR_KECCAK_NOT_SETUP is returned if
 *                      mbedtls_keccak_sponge_starts has not yet been called to
 *                      configure the context.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_keccak_sponge_absorb( mbedtls_keccak_sponge_context *ctx,
        const unsigned char* data,
        size_t size );

/**
 * \brief               Get output bytes from the sponge.
 *
 * \note                This function can be called multiple times to generate
 *                      arbitrary-length output.
 *
 *                      After calling this function it is no longer possible
 *                      to absorb bits into the sponge state.
 *
 * \param ctx           The sponge context.
 * \param data          The buffer to where output bytes are stored.
 * \param size          The number of output bytes to produce.
 *
 * \return              MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA is returned if
 *                      ctx or data is NULL.
 *                      MBEDTLS_ERR_KECCAK_NOT_SETUP is returned if
 *                      mbedtls_keccak_sponge_starts has not yet been called to
 *                      configure the context.
 *                      Otherwise, 0 is returned to indicate success.
 */
int mbedtls_keccak_sponge_squeeze( mbedtls_keccak_sponge_context *ctx,
        unsigned char* data,
        size_t size );

int mbedtls_keccak_sponge_process( mbedtls_keccak_sponge_context *ctx,
                                   const unsigned char *input );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_KECCAK_H */
