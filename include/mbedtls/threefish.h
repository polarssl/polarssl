/**
 * \file threefish.h
 *
 * \brief Threefish block cipher
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_THREEFISH_H
#define MBEDTLS_THREEFISH_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h>
#include <stddef.h>

#define MBEDTLS_THREEFISH_ENCRYPT       1
#define MBEDTLS_THREEFISH_DECRYPT       0

#define MBEDTLS_ERR_THREEFISH_INVALID_KEY_LENGTH        -0x0080  /**< Invalid key length. */
#define MBEDTLS_ERR_THREEFISH_INVALID_INPUT_LENGTH      -0x0082  /**< Invalid input length. */

#if defined(MBEDTLS_THREEFISH_C)

#if !defined(MBEDTLS_THREEFISH_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Threefish context structure
 */
typedef struct
{
    unsigned int keybits;   /*!< Length of the key in bits */
    uint64_t key[16 + 1];   /*!< Threefish key and parity */
    uint64_t tweak[2 + 1];  /*!< Threefish 128-bit tweak and parity */
}
mbedtls_threefish_context;

/**
 * \brief          Initialize Threefish context
 *
 * \param ctx      Threefish context to be initialized
 */
void mbedtls_threefish_init( mbedtls_threefish_context *ctx );

/**
 * \brief          Clear Threefish context
 *
 * \param ctx      Threefish context to be cleared
 */
void mbedtls_threefish_free( mbedtls_threefish_context *ctx );

/**
 * \brief          Threefish key schedule
 *
 * \param ctx      Threefish context to be initialized
 * \param key      Encryption/decryption key
 * \param keybits  Length of the key in bits. Must be 256, 512 or 1024.
 *
 * \return         0 if successful, or MBEDTLS_ERR_THREEFISH_INVALID_KEY_LENGTH
 */
int mbedtls_threefish_setkey( mbedtls_threefish_context *ctx,
                              const unsigned char *key, unsigned int keybits );

/**
 * \brief          Set the Threefish 128-bit tweak
 *
 * \param ctx      Threefish context to be initialized
 * \param tweak    Encryption/decryption key
 *
 * \return         0 if successful
 */
int mbedtls_threefish_settweak( mbedtls_threefish_context *ctx,
                                const unsigned char *tweak );

/**
 * \brief          Threefish-ECB block encryption/decryption
 *
 * \param ctx      Threefish context
 * \param mode     MBEDTLS_THREEFISH_ENCRYPT or MBEDTLS_THREEFISH_DECRYPT
 * \param input    32, 64 or 128-byte input block depending on the key size
 * \param output   32, 64 or 128-byte output block depending on the key size
 *
 * \return         0 if successful
 */
int mbedtls_threefish_crypt_ecb( mbedtls_threefish_context *ctx, int mode,
                                 const unsigned char *input,
                                 unsigned char *output );

#if defined(MBEDTLS_CIPHER_MODE_CBC)
/**
 * \brief          Threefish-CBC buffer encryption/decryption
 *                 Length should be a multiple of the block
 *                 size (16 bytes)
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      Threefish context
 * \param mode     MBEDTLS_THREEFISH_ENCRYPT or MBEDTLS_THREEFISH_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful, or MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH
 */
int mbedtls_threefish_crypt_cbc( mbedtls_threefish_context *ctx,
                                 int mode, size_t length, unsigned char *iv,
                                 const unsigned char *input,
                                 unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)
/**
 * \brief          Threefish-CFB buffer encryption/decryption.
 *
 * \note           Upon exit, the content of the IV is updated so that you can
 *                 call the function same function again on the following
 *                 block(s) of data and get the same result as if it was
 *                 encrypted in one call. This allows a "streaming" usage.
 *                 If on the other hand you need to retain the contents of the
 *                 IV, you should either save it manually or use the cipher
 *                 module instead.
 *
 * \param ctx      Threefish context
 * \param mode     MBEDTLS_THREEFISH_ENCRYPT or MBEDTLS_THREEFISH_DECRYPT
 * \param length   length of the input data
 * \param iv_off   offset in IV (updated after use)
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 *
 * \return         0 if successful
 */
int mbedtls_threefish_crypt_cfb( mbedtls_threefish_context *ctx,
                                 int mode, size_t length, size_t *iv_off,
                                 unsigned char *iv, const unsigned char *input,
                                 unsigned char *output );
#endif /*MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)
/**
 * \brief               Threefish-CTR buffer encryption/decryption
 *
 * Warning: You have to keep the maximum use of your counter in mind!
 *
 * \param ctx           Threefish context
 * \param length        The length of the data
 * \param nc_off        The offset in the current stream_block (for resuming
 *                      within current cipher stream). The offset pointer to
 *                      should be 0 at the start of a stream.
 * \param nonce_counter The 256, 512 or 1024-bit nonce and counter.
 * \param stream_block  The saved stream-block for resuming. Is overwritten
 *                      by the function.
 * \param input         The input data stream
 * \param output        The output data stream
 *
 * \return         0 if successful
 */
int mbedtls_threefish_crypt_ctr( mbedtls_threefish_context *ctx,
                                 size_t length, size_t *nc_off,
                                 unsigned char *nonce_counter,
                                 unsigned char *stream_block,
                                 const unsigned char *input,
                                 unsigned char *output );
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_THREEFISH_ALT */
#include "threefish_alt.h"
#endif /* MBEDTLS_THREEFISH_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_threefish_self_test( int verbose );

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_THREEFISH_C */

#endif /* MBEDTLS_THREEFISH_H */
