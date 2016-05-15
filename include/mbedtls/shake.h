/**
 * \file shake.h
 *
 * \brief SHA-3 eXtensible Output Functions (XOF) (SHAKE128, SHAKE256)
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
#ifndef MBEDTLS_SHAKE_H
#define MBEDTLS_SHAKE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if !defined(MBEDTLS_SHAKE_ALT)
// Regular implementation

#include "keccak_sponge.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ERR_SHAKE_BAD_INPUT_DATA   MBEDTLS_ERR_KECCAK_SPONGE_BAD_INPUT_DATA
#define MBEDTLS_ERR_SHAKE_BAD_NOT_STARTED  MBEDTLS_ERR_KECCAK_SPONGE_NOT_SETUP
#define MBEDTLS_ERR_SHAKE_BAD_STATE        MBEDTLS_ERR_KECCAK_SPONGE_BAD_STATE

typedef enum
{
    MBEDTLS_SHAKE128,
    MBEDTLS_SHAKE256
}
mbedtls_shake_type_t;

typedef struct
{
    mbedtls_keccak_sponge_context sponge_ctx;
    size_t block_size;  /* block size in bytes */
}
mbedtls_shake_context;

/**
 * \brief          Initialize a SHAKE context
 *
 * \param ctx      SHAKE context to be initialized.
 */
void mbedtls_shake_init( mbedtls_shake_context *ctx );

/**
 * \brief          Clear a SHAKE context
 *
 * \param ctx      SHAKE context to be cleared.
 */
void mbedtls_shake_free( mbedtls_shake_context *ctx );

/**
 * \brief          Clone (the state of) a SHAKE context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_shake_clone( mbedtls_shake_context *dst,
                          const mbedtls_shake_context *src );

/**
 * \brief          Context setup.
 *
 * \param ctx      The SHAKE context to setup.
 * \param type     Selects the SHAKE variant (SHAKE128 or SHAKE256).
 *
 * \return         0 on success, otherwise an error code is returned.
 */
int mbedtls_shake_starts( mbedtls_shake_context *ctx, mbedtls_shake_type_t type );

/**
 * \brief          Process a buffer with SHAKE
 *
 * \param ctx      The SHAKE context.
 * \param input    The buffer to process.
 * \param size     The number of bytes to process from \p data.
 *
 * \return         0 on success, otherwise an error code is returned.
 */
int mbedtls_shake_update( mbedtls_shake_context *ctx,
                          const unsigned char* input,
                          size_t size );

/**
 * \brief          Generate output bytes.
 *
 *                 This function can be called multiple times to generate an
 *                 arbitrary-length output.
 *
 * \param ctx      The SHAKE context.
 * \param output   Pointer to the buffer to where the output bytes are written.
 * \param olen     The number of bytes to output.
 *
 * \return         0 on success, otherwise an error code is returned.
 */
int mbedtls_shake_output( mbedtls_shake_context *ctx,
                          unsigned char* output,
                          size_t olen );

int mbedtls_shake_process( mbedtls_shake_context *ctx, const unsigned char* input );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_SHAKE_ALT */
#include "shake_alt.h"
#endif /* MBEDTLS_SHAKE_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Generate arbitrary SHAKE output from some input bytes.
 *
 * \param input    The buffer to process.
 * \param ilen     The length (in bytes) of the input buffer.
 * \param type     Selects the SHAKE variant (SHAKE128, or SHAKE256).
 * \param output   Pointer to the buffer to where the output data is written.
 * \param olen     The number of output bytes to generate and write to \p output.
 *
 * \return         0 on success, otherwise an error code is returned.
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
