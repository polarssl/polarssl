/**
 * \file keccakf.h
 *
 * \brief Keccak-f[1600] permutation.
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
#ifndef MBEDTLS_KECCAKF_H
#define MBEDTLS_KECCAKF_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h>
#include <stddef.h>

#if !defined(MBEDTLS_KECCAKF_ALT)

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ERR_KECCAKF_BAD_INPUT_DATA (-1)


#define MBEDTLS_KECCAKF_STATE_SIZE_BITS  ( 1600U )
#define MBEDTLS_KECCAKF_STATE_SIZE_BYTES ( 1600U / 8U )

typedef struct
{
    uint64_t state[5][5];
}
mbedtls_keccakf_context;

/**
 * \brief               Initialize a Keccak-f[1600] context.
 *                      This should always be called first.
 *                      Prepares the context for other mbedtls_keccakf_* functions.
 *
 *                      By default the Keccak state is zeroed.
 */
void mbedtls_keccakf_init( mbedtls_keccakf_context *ctx );

/**
 * \brief               Free and clear the internal structures of ctx.
 *                      Can be called at any time after mbedtls_keccakf_init().
 */
void mbedtls_keccakf_free( mbedtls_keccakf_context *ctx );

/**
 * \brief               Clone (the state of) a Keccak-f[1600] context
 *
 * \param dst           The destination context
 * \param src           The context to be cloned
 */
void mbedtls_keccakf_clone( mbedtls_keccakf_context *dst,
                            const mbedtls_keccakf_context *src );

/**
 * \brief               Apply the Keccak permutation to the ctx.
 *
 * \param ctx           The Keccak-f[1600] context to permute.
 *
 * \returns             MBEDTLS_ERR_KECCAKF_BAD_INPUT_DATA if the ctx is NULL.
 *                      Otherwise 0 is returned for success.
 */
int mbedtls_keccakf_permute( mbedtls_keccakf_context *ctx );

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
int mbedtls_keccakf_xor_binary( mbedtls_keccakf_context *ctx,
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
int mbedtls_keccakf_read_binary( mbedtls_keccakf_context *ctx,
                                 unsigned char *data,
                                 size_t size );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_KECCAKF_ALT */

#endif /* keccakf.h */
