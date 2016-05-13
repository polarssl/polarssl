/**
 * \file sha3.h
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
#ifndef MBEDTLS_INCLUDE_MBEDTLS_SHA3_H_
#define MBEDTLS_INCLUDE_MBEDTLS_SHA3_H_

#include "keccak_sponge.h"

#if !defined(MBEDTLS_SHA3_ALT)
// Regular implementation

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ERR_SHA3_BAD_INPUT_DATA   MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA
#define MBEDTLS_ERR_SHA3_BAD_NOT_STARTED  MBEDTLS_ERR_KECCAK_SPONGE_NOT_SETUP
#define MBEDTLS_ERR_SHA3_BAD_STATE        MBEDTLS_ERR_KECCAK_SPONGE_BAD_STATE

typedef enum
{
    MBEDTLS_SHA3_224,
    MBEDTLS_SHA3_256,
    MBEDTLS_SHA3_384,
    MBEDTLS_SHA3_512
}
mbedtls_sha3_type_t;

typedef struct
{
    mbedtls_keccak_sponge_context sponge_ctx;
    size_t digest_size; /* digest size in bytes */
    size_t block_size;  /* block size in bytes */
}
mbedtls_sha3_context;

/**
 * \brief          Initialize a SHA-3 context
 *
 * \param ctx      SHA-3 context to be initialized.
 */
void mbedtls_sha3_init( mbedtls_sha3_context *ctx );

/**
 * \brief          Clear a SHA-3 context
 *
 * \param ctx      SHA-3 context to be cleared.
 */
void mbedtls_sha3_free( mbedtls_sha3_context *ctx );

/**
 * \brief          Clone (the state of) a SHA-3 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_sha3_clone( mbedtls_sha3_context *dst,
                         const mbedtls_sha3_context *src );

/**
 * \brief          Context setup.
 *
 * \param ctx      The SHA-3 context to setup.
 * \param type     Selects the SHA-3 variant (SHA3-224, SHA3-256, SHA3-384, or SHA3-512).
 *
 * \return         0 on success, otherwise an error code is returned.
 */
int mbedtls_sha3_starts( mbedtls_sha3_context *ctx, mbedtls_sha3_type_t type );

/**
 * \brief          Process a buffer with SHA-3
 *
 * \param ctx      The SHA-3 context.
 * \param input    The buffer to process.
 * \param size     The number of bytes to process from \p data.
 *
 * \return         0 on success, otherwise an error code is returned.
 */
int mbedtls_sha3_update( mbedtls_sha3_context *ctx,
        const unsigned char* input,
        size_t size_bits );

/**
 * \brief          Generate the SHA-3 hash.
 *
 * \param ctx      The SHA-3 context.
 * \param output   Pointer to the buffer to where the hash is written.
 *                 The required length of this buffer depends on the chosen SHA-3
 *                 variant:
 *                  * SHA3-224: 28 bytes
 *                  * SHA3-256: 32 bytes
 *                  * SHA3-384: 48 bytes
 *                  * SHA3-512: 64 bytes
 *
 * \return         0 on success, otherwise an error code is returned.
 */
int mbedtls_sha3_finish( mbedtls_sha3_context *ctx, unsigned char* output );

int mbedtls_sha3_process( mbedtls_sha3_context *ctx, const unsigned char* input );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_SHA3_ALT */
#include "sha3_alt.h"
#endif /* MBEDTLS_SHA3_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Generate the SHA-3 hash of a buffer.
 *
 * \param input    The buffer to process.
 * \param ilen     The length (in bytes) of the input buffer.
 * \param type     Selects the SHA-3 variant (SHA3-224, SHA3-256, SHA3-384, or SHA3-512).
 * \param output   Pointer to the buffer to where the hash is written.
 *                 The required length of this buffer depends on the chosen SHA-3
 *                 variant:
 *                  * SHA3-224: 28 bytes
 *                  * SHA3-256: 32 bytes
 *                  * SHA3-384: 48 bytes
 *                  * SHA3-512: 64 bytes
 *
 * \return         0 on success, otherwise an error code is returned.
 */
int mbedtls_sha3( const unsigned char* input,
                  size_t ilen,
                  mbedtls_sha3_type_t type,
                  unsigned char* output );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_sha3_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_INCLUDE_MBEDTLS_SHA3_H_ */
