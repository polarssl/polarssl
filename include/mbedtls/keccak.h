/**
 * \file keccak.h
 *
 * \brief The Keccak-f[1600] permutation and the corresponding sponge construction.
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
#ifndef MBEDTLS_KECCAK_H
#define MBEDTLS_KECCAK_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#define MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA                 -0x0054  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_KECCAK_BAD_STATE                      -0x0056  /**< The requested operation cannot be performed with the current context state. */
#define MBEDTLS_ERR_KECCAK_HW_ACCEL_FAILED                -0x0058  /**< SHAKE hardware accelerator failed. */

#define MBEDTLS_KECCAK_F_STATE_SIZE_BITS  ( 1600U )
#define MBEDTLS_KECCAK_F_STATE_SIZE_BYTES ( 1600U / 8U )

#include <stdint.h>
#include <stddef.h>

#if defined(MBEDTLS_KECCAK_F_ALT) || defined(MBEDTLS_KECCAK_SPONGE_ALT)
#include "keccak_alt.h"
#endif

#if !defined(MBEDTLS_KECCAK_F_ALT)
/**
 * \brief               The context structure for Keccak-f[1600] operations.
 *
 * \note                This structure may change in future versions of the
 *                      library. Hardware-accelerated implementations may
 *                      use different structures. Therefore applications
 *                      should not access the context directly, but instead
 *                      should use the functions in this module.
 */
typedef struct
{
    uint64_t state[5][5];
    uint64_t temp[5][5];
}
mbedtls_keccak_f_context;
#endif /* !defined(MBEDTLS_KECCAK_F_ALT) */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief               Initialize a Keccak-f[1600] context.
 *
 *                      This function should always be called first.
 *                      It prepares the context for other
 *                      mbedtls_keccak_f_xxx functions.
 *
 * \param ctx           The Keccak-f[1600] context to initialize.
 */
void mbedtls_keccak_f_init( mbedtls_keccak_f_context *ctx );

/**
 * \brief               Free and clear the internal structures of ctx.
 *
 *                      This function can be called at any time after
 *                      mbedtls_keccak_f_init().
 *
 * \param ctx           The Keccak-f[1600] context to clear.
 */
void mbedtls_keccak_f_free( mbedtls_keccak_f_context *ctx );

/**
 * \brief               Clone (the state of) a Keccak-f[1600] context
 *
 * \param dst           The destination context.
 * \param src           The context to clone.
 */
void mbedtls_keccak_f_clone( mbedtls_keccak_f_context *dst,
                             const mbedtls_keccak_f_context *src );

/**
 * \brief               Apply the Keccak permutation to the ctx.
 *
 * \param ctx           The Keccak-f[1600] context to permute.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA
 *                      \p ctx is \c NULL.
 * \retval #MBEDTLS_ERR_KECCAK_HW_ACCEL_FAILED
 *                      Failure reported by a hardware accelerator.
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
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA
 *                      \p ctx or \p data is \c NULL,
 *                      or \p size_bits is larger than 1600.
 * \retval #MBEDTLS_ERR_KECCAK_HW_ACCEL_FAILED
 *                      Failure reported by a hardware accelerator.
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
 * \param data          Output buffer.
 * \param size          The number of bytes to read from the Keccak state.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA
 *                      \p ctx or \p data is \c NULL,
 *                      or \p size is larger than 20.
 * \retval #MBEDTLS_ERR_KECCAK_HW_ACCEL_FAILED
 *                      Failure reported by a hardware accelerator.
 */
int mbedtls_keccak_f_read_binary( mbedtls_keccak_f_context *ctx,
                                  unsigned char *data,
                                  size_t size );

#ifdef __cplusplus
}
#endif

#if !defined(MBEDTLS_KECCAK_SPONGE_ALT)
/**
 * \brief               The context structure for Keccak sponge operations.
 *
 * \note                This structure may change in future versions of the
 *                      library. Hardware-accelerated implementations may
 *                      use different structures. Therefore applications
 *                      should not access the context directly, but instead
 *                      should use the functions in this module.
 */
typedef struct
{
    mbedtls_keccak_f_context keccak_f_ctx;
    unsigned char queue[1600 / 8]; /* store partial block data (absorbing) or pending output data (squeezing) */
    size_t queue_len;              /* queue length (in bits) */
    size_t rate;                   /* sponge rate (in bits) */
    size_t suffix_len;             /* length of the suffix (in bits) (range 0..8) */
    int state;                     /* Current state (absorbing/ready to squeeze/squeezing) */
    unsigned char suffix;          /* suffix bits appended to message, before padding */
}
mbedtls_keccak_sponge_context;
#endif /* !defined(MBEDTLS_KECCAK_SPONGE_ALT) */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief               Initialize a Keccak sponge context.
 *
 * \param ctx           The context to initialize.
 */
void mbedtls_keccak_sponge_init( mbedtls_keccak_sponge_context *ctx );

/**
 * \brief               Clean a Keccak sponge context.
 *
 * \param ctx           The context to be clear.
 */
void mbedtls_keccak_sponge_free( mbedtls_keccak_sponge_context *ctx );

/**
 * \brief               Clone (the state of) a Keccak Sponge context.
 *
 * \param dst           The destination context.
 * \param src           The context to clone.
 */
void mbedtls_keccak_sponge_clone( mbedtls_keccak_sponge_context *dst,
                                  const mbedtls_keccak_sponge_context *src );

/**
 * \brief               Comfigure the sponge context to start streaming.
 *
 * \note                You must call mbedtls_keccak_sponge_init() before
 *                      calling this function, and you may no longer call
 *                      it after calling mbedtls_keccak_sponge_absorb() or
 *                      mbedtls_keccak_sponge_squeeze().
 *
 * \note                This function \b MUST be called after calling
 *                      mbedtls_keccak_sponge_init() and before calling the
 *                      absorb or squeeze functions. If this function has not
 *                      been called then the absorb/squeeze functions will
 *                      return #MBEDTLS_ERR_KECCAK_BAD_STATE.
 *
 * \param ctx           The sponge context to set up.
 * \param capacity      The sponge's capacity parameter. This determines the
 *                      security of the sponge. The capacity should be double
 *                      the required security (in bits). For example, if 128 bits
 *                      of security are required then \p capacity should be set
 *                      to 256. This must be a multiple of 8. Must be less than
 *                      1600.
 * \param suffix        A byte containing the suffix bits that are absorbed
 *                      before the padding rule is applied.
 * \param suffix_len    The length (in bits) of the suffix.
 *                      8 is the maximum value.
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA
 *                      \p ctx is \c NULL,
 *                      or \p capacity is out of range or not a multiple of 8,
 *                      or \p suffix_len is greater than 8.
 * \retval #MBEDTLS_ERR_KECCAK_BAD_STATE
 *                      This function was called without a prior call to
 *                      mbedtls_keccak_sponge_init() or after calling
 *                      mbedtls_keccak_sponge_absorb() or
 *                      mbedtls_keccak_sponge_squeeze(),
 * \retval #MBEDTLS_ERR_KECCAK_HW_ACCEL_FAILED
 *                      Failure reported by a hardware accelerator.
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
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA
 *                      \p ctx or \p data is \c NULL.
 * \retval #MBEDTLS_ERR_KECCAK_BAD_STATE
 *                      The sponge can no longer accept data for absorption.
 *                      This occurs when mbedtls_keccak_sponge_squeeze() has
 *                      been previously called.
 *                      Alternatively, mbedtls_keccak_sponge_starts() has
 *                      not yet been called to set up the context.
 * \retval #MBEDTLS_ERR_KECCAK_HW_ACCEL_FAILED
 *                      Failure reported by a hardware accelerator.
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
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA
 *                      \p ctx or \p data is \c NULL.
 * \retval #MBEDTLS_ERR_KECCAK_BAD_STATE
 *                      mbedtls_keccak_sponge_starts() has not yet been called
 *                      to set up the context.
 * \retval #MBEDTLS_ERR_KECCAK_HW_ACCEL_FAILED
 *                      Failure reported by a hardware accelerator.
 */
int mbedtls_keccak_sponge_squeeze( mbedtls_keccak_sponge_context *ctx,
        unsigned char* data,
        size_t size );

/**
 * \brief               Absorb data through the sponge to capacity.
 *                      For internal use only.
 *
 * \note                You must call mbedtls_keccak_sponge_starts() before
 *                      calling this function. You must not call this function
 *                      after calling mbedtls_keccak_sponge_squeeze().
 *
 * \warning             This function does not protect against being called
 *                      in an invalid state. If in doubt, call
 *                      mbedtls_keccak_sponge_absorb() instead.
 *
 * \param ctx           The sponge context.
 * \param input         The buffer containing bytes to absorb. This function
 *                      reads 1600 - c bits (200 - ceiling(c/8) bytes) where
 *                      where c is the capacity set by
 *                      mbedtls_keccak_sponge_starts().
 *
 * \retval 0            Success.
 * \retval #MBEDTLS_ERR_KECCAK_BAD_INPUT_DATA
 *                      \p ctx or \p input is \c NULL.
 * \retval #MBEDTLS_ERR_KECCAK_HW_ACCEL_FAILED
 *                      Failure reported by a hardware accelerator.
 */
int mbedtls_keccak_sponge_process( mbedtls_keccak_sponge_context *ctx,
                                   const unsigned char *input );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_KECCAK_H */
