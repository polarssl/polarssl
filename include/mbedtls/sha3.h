/**
 * \file sha3.h
 *
 * \brief SHA-3 cryptographic hash functions (SHA3-224, SHA3-256, SHA3-384, SHA3-512)
 *
 * Reference: National Institute of Standards and Technology (NIST).
 * _SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions._
 * FIPS PUB 202. August 2015.
 * https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
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
#ifndef MBEDTLS_SHA3_H
#define MBEDTLS_SHA3_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#define MBEDTLS_ERR_SHA3_BAD_INPUT_DATA                   -0x0053  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_SHA3_HW_ACCEL_FAILED                  -0x0055  /**< SHA3 hardware accelerator failed. */

#include "keccak.h"

/**
 * \brief Designators for algorithms in the SHA-3 family.
 */
typedef enum
{
    MBEDTLS_SHA3_224, /**< SHA3-224 */
    MBEDTLS_SHA3_256, /**< SHA3-256 */
    MBEDTLS_SHA3_384, /**< SHA3-384 */
    MBEDTLS_SHA3_512  /**< SHA3-512 */
}
mbedtls_sha3_type_t;

#if !defined(MBEDTLS_SHA3_ALT)
// Regular implementation

/**
 * \brief               The context structure for SHA-3 operations.
 *
 * \note                This structure may change in future versions of the
 *                      library. Hardware-accelerated implementations may
 *                      use different structures. Therefore applications
 *                      should not access the context directly, but instead
 *                      should use the functions in this module.
 */
typedef struct
{
    mbedtls_keccak_sponge_context sponge_ctx;
    size_t digest_size; /* digest size in bytes */
    size_t block_size;  /* block size in bytes */
}
mbedtls_sha3_context;

#else  /* MBEDTLS_SHA3_ALT */
#include "sha3_alt.h"
#endif /* MBEDTLS_SHA3_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Initialize a SHA-3 context.
 *
 * \param ctx      The SHA-3 context to initialize.
 */
void mbedtls_sha3_init( mbedtls_sha3_context *ctx );

/**
 * \brief          Clear a SHA-3 context.
 *
 * \param ctx      The SHA-3 context to clear.
 */
void mbedtls_sha3_free( mbedtls_sha3_context *ctx );

/**
 * \brief          Clone (the state of) a SHA-3 context.
 *
 * \param dst      The destination context.
 * \param src      The context to clone.
 */
void mbedtls_sha3_clone( mbedtls_sha3_context *dst,
                         const mbedtls_sha3_context *src );

/**
 * \brief          Start a SHA-3 calculation.
 *
 * \param ctx      The SHA-3 context to setup.
 * \param type     The SHA-3 variant to select
 *                 (SHA3-224, SHA3-256, SHA3-384, or SHA3-512).
 *
 * \retval 0       Success.
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                 \p ctx is \c NULL,
 *                 or \p type is invalid,
 *                 or this function was called without a prior call to
 *                 mbedtls_sha3_init() or after calling
 *                 mbedtls_sha3_update() or mbedtls_shake_process() or
 *                 mbedtls_sha3_finish(),
 */
int mbedtls_sha3_starts( mbedtls_sha3_context *ctx,
                         mbedtls_sha3_type_t type );

/**
 * \brief          Feed a buffer into an ongoing SHA-3 calculation.
 *
 * \param ctx      The SHA-3 context.
 * \param input    The buffer to process.
 * \param size     The number of bytes to process from \p data.
 *
 * \retval 0       Success.
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                 \p ctx is \c NULL,
 *                 or mbedtls_sha3_starts() has not been called previously,
 *                 or mbedtls_sha3_output() has been called on \p ctx.
 * \retval #MBEDTLS_ERR_SHA3_HW_ACCEL_FAILED
 *                 Failure reported by a hardware accelerator.
 */
int mbedtls_sha3_update( mbedtls_sha3_context *ctx,
                         const unsigned char* input,
                         size_t size );

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
 * \retval 0       Success.
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                 \p ctx or \p output is \c NULL,
 *                 or mbedtls_shake_starts() has not been called previously,
 * \retval #MBEDTLS_ERR_SHA3_HW_ACCEL_FAILED
 *                 Failure reported by a hardware accelerator.
 */
int mbedtls_sha3_finish( mbedtls_sha3_context *ctx,
                         unsigned char* output );

/**
 * \brief          Process a data block with SHA-3. For internal use only.
 *
 * \param ctx      The SHA-3 context.
 * \param input    The buffer containing bytes to process. The size of this
 *                 buffer is:
 *                 - 172 bytes for SHA3-224.
 *                 - 168 bytes for SHA3-256.
 *                 - 152 bytes for SHA3-384.
 *                 - 136 bytes for SHA3-512.
 *
 * \retval 0       Success.
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                 \p ctx or \p output is \c NULL,
 *                 or mbedtls_sha3_starts() has not been called previously,
 *                 or mbedtls_sha3_output() has been called on \p ctx.
 * \retval #MBEDTLS_ERR_SHA3_HW_ACCEL_FAILED
 *                 Failure reported by a hardware accelerator.
 */
int mbedtls_sha3_process( mbedtls_sha3_context *ctx,
                          const unsigned char* input );

/**
 * \brief          Calculate the SHA-3 hash of a buffer.
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
 * \retval 0       Success.
 * \retval #MBEDTLS_ERR_SHA3_BAD_INPUT_DATA
 *                 \p ctx or \p output is \c NULL.
 * \retval #MBEDTLS_ERR_SHA3_HW_ACCEL_FAILED
 *                 Failure reported by a hardware accelerator.
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

#endif /* MBEDTLS_SHA3_H */
