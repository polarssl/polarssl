/**
 * \file shake.h
 *
 * \brief SHA-3 eXtensible Output Functions (XOF) (SHAKE128, SHAKE256)
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
#ifndef MBEDTLS_SHAKE_H
#define MBEDTLS_SHAKE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#define MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA                  -0x0057  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_SHAKE_HW_ACCEL_FAILED                 -0x0059  /**< SHAKE hardware accelerator failed. */

#include "keccak.h"

/**
 * \brief Designators for algorithms in the SHA-3 family.
 */
typedef enum
{
    MBEDTLS_SHAKE128, /**< SHAKE128 */
    MBEDTLS_SHAKE256  /**< SHAKE256 */
}
mbedtls_shake_type_t;

#if !defined(MBEDTLS_SHAKE_ALT)
// Regular implementation

/**
 * \brief               The context structure for SHAKE operations.
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
    size_t block_size;  /* block size in bytes */
}
mbedtls_shake_context;

#else  /* MBEDTLS_SHAKE_ALT */
#include "shake_alt.h"
#endif /* MBEDTLS_SHAKE_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Initialize a SHAKE context.
 *
 * \param ctx      The SHAKE context to initialize.
 */
void mbedtls_shake_init( mbedtls_shake_context *ctx );

/**
 * \brief          Clear a SHAKE context.
 *
 * \param ctx      The SHAKE context to be clear.
 */
void mbedtls_shake_free( mbedtls_shake_context *ctx );

/**
 * \brief          Clone (the state of) a SHAKE context
 *
 * \param dst      The destination context.
 * \param src      The context to clone.
 */
void mbedtls_shake_clone( mbedtls_shake_context *dst,
                          const mbedtls_shake_context *src );

/**
 * \brief          Start a SHAKE calculation.
 *
 * \param ctx      The SHAKE context to set up.
 * \param type     The SHAKE variant to select (SHAKE128 or SHAKE256).
 *
 * \retval 0       Success.
 * \retval #MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA
 *                 \p ctx is \c NULL,
 *                 or \p type is invalid,
 *                 or this function was called without a prior call to
 *                 mbedtls_shake_init() or after calling
 *                 mbedtls_shake_update() or mbedtls_shake_process() or
 *                 mbedtls_shake_ouput(),
 * \retval #MBEDTLS_ERR_SHAKE_HW_ACCEL_FAILED
 *                 Failure reported by a hardware accelerator.
 */
int mbedtls_shake_starts( mbedtls_shake_context *ctx,
                          mbedtls_shake_type_t type );

/**
 * \brief          Feed a buffer into an ongoing SHAKE calculation.
 *
 * \param ctx      The SHAKE context.
 * \param input    The buffer to process.
 * \param size     The number of bytes to process from \p input.
 *
 * \retval 0       Success.
 * \retval #MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA
 *                 \p ctx is \c NULL,
 *                 or mbedtls_shake_starts() has not been called previously,
 *                 or mbedtls_shake_output() has been called on \p ctx.
 * \retval #MBEDTLS_ERR_SHAKE_HW_ACCEL_FAILED
 *                 Failure reported by a hardware accelerator.
 */
int mbedtls_shake_update( mbedtls_shake_context *ctx,
                          const unsigned char* input,
                          size_t size );

/**
 * \brief          Generate output bytes from a SHAKE calculation.
 *
 *                 This function can be called multiple times to generate an
 *                 arbitrary-length output.
 *
 * \param ctx      The SHAKE context.
 * \param output   Pointer to the buffer to where the output bytes are written.
 * \param olen     The number of bytes to output.
 *
 * \retval 0       Success.
 * \retval #MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA
 *                 \p ctx or \p output is \c NULL,
 *                 or mbedtls_shake_starts() has not been called previously,
 * \retval #MBEDTLS_ERR_SHAKE_HW_ACCEL_FAILED
 *                 Failure reported by a hardware accelerator.
 */
int mbedtls_shake_output( mbedtls_shake_context *ctx,
                          unsigned char* output,
                          size_t olen );

/**
 * \brief          Process a data block with SHAKE. For internal use only.
 *
 * \param ctx      The SHAKE context.
 * \param input    The buffer containing bytes to process. The size of this
 *                 buffer is:
 *                 - 168 bytes for SHAKE128.
 *                 - 136 bytes for SHAKE256.
 *
 * \retval 0       Success.
 * \retval #MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA
 *                 \p ctx or \p output is \c NULL.
 *                 or mbedtls_shake_starts() has not been called previously,
 *                 or mbedtls_shake_output() has been called on \p ctx.
 * \retval #MBEDTLS_ERR_SHAKE_HW_ACCEL_FAILED
 *                 Failure reported by a hardware accelerator.
 */
int mbedtls_shake_process( mbedtls_shake_context *ctx,
                           const unsigned char* input );

/**
 * \brief          Generate SHAKE output from some input bytes.
 *
 * \param input    The buffer to process.
 * \param ilen     The length (in bytes) of the input buffer.
 * \param type     The SHAKE variant to calculate (SHAKE128 or SHAKE256).
 * \param output   Pointer to the buffer to where the output data is written.
 * \param olen     The number of output bytes to generate and write to \p output.
 *
 * \retval 0       Success.
 * \retval #MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA
 *                 \p ctx or \p output is \c NULL,
 *                 or \c type is invalid.
 * \retval #MBEDTLS_ERR_SHAKE_HW_ACCEL_FAILED
 *                 Failure reported by a hardware accelerator.
 */
int mbedtls_shake( const unsigned char* input,
                   size_t ilen,
                   mbedtls_shake_type_t type,
                   unsigned char* output,
                   size_t olen );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_shake_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_SHAKE_H */
