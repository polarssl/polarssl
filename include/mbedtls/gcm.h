/**
 * \file gcm.h
 *
 * \brief Galois/Counter Mode (GCM) for 128-bit block ciphers, as defined
 * in <em>D. McGrew, J. Viega, The Galois/Counter Mode of Operation (GCM), 
 * Natl. Inst. Stand. Technol.</em>
 * 
 * For more information on GCM, see <em>NIST SP 800-38D: Recommendation for 
 * Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC</em>.
 * 
 */
 
/* 
 *  Copyright (C) 2006-2018, Arm Limited (or its affiliates), All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 */
 
#ifndef MBEDTLS_GCM_H
#define MBEDTLS_GCM_H

#include "cipher.h"

#include <stdint.h>

#define MBEDTLS_GCM_ENCRYPT     1
#define MBEDTLS_GCM_DECRYPT     0

#define MBEDTLS_ERR_GCM_AUTH_FAILED                       -0x0012  /**< Authenticated decryption failed. */
#define MBEDTLS_ERR_GCM_BAD_INPUT                         -0x0014  /**< Bad input parameters to function. */

#if !defined(MBEDTLS_GCM_ALT)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          The GCM context structure.
 */
typedef struct {
    mbedtls_cipher_context_t cipher_ctx;  /*!< The cipher context used. */
    uint64_t HL[16];                      /*!< Precalculated HTable low. */
    uint64_t HH[16];                      /*!< Precalculated HTable high. */
    uint64_t len;                         /*!< The total length of the data. */
    uint64_t add_len;                     /*!< The total length of the additional data. */
    unsigned char base_ectr[16];          /*!< The first ECTR for tag. */
    unsigned char y[16];                  /*!< The Y working value. */
    unsigned char buf[16];                /*!< The buf working value. */
    int mode;                             /*!< The operation to perform: 
	                                           #MBEDTLS_GCM_ENCRYPT or 
											   #MBEDTLS_GCM_DECRYPT. */
}
mbedtls_gcm_context;

/**
 * \brief           This function initializes the specified GCM context, 
 *                  to make references valid, and prepare the context 
 *                  for mbedtls_gcm_setkey() or mbedtls_gcm_free().
 *
 * \param ctx       The GCM context to initialize.
 */
void mbedtls_gcm_init( mbedtls_gcm_context *ctx );

/**
 * \brief           This function initializes the GCM context set in the 
 *                  \p ctx parameter and sets the encryption key.
 *
 * \param ctx       The GCM context to initialize.
 * \param cipher    The 128-bit block cipher to use.
 * \param key       The encryption key.
 * \param keybits   The key size in bits. Must be 128bits, 192bits or 256bits.
 *
 * \return          \c 0 on success, or a cipher specific error code
 */
int mbedtls_gcm_setkey( mbedtls_gcm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits );

/**
 * \brief           This function performs GCM encryption or decryption of a buffer.
 *
 * \note For encryption, the output buffer can be the same as the input buffer.
 *       For decryption, the output buffer cannot be the same as input buffer.
 *       If the buffers overlap, the output buffer must trail at least 8 Bytes
 *       behind the input buffer.
 *
 * \param ctx       The GCM context to encrypt or decrypt.
 * \param mode      The operation to perform: #MBEDTLS_GCM_ENCRYPT or 
 *                  #MBEDTLS_GCM_DECRYPT.
 * \param length    The length of the input data.
 * \param iv        The initialization vector.
 * \param iv_len    The length of the IV.
 * \param add       The additional data field.
 * \param add_len   The length of the additional data.
 * \param input     The buffer holding the input data.
 * \param output    The buffer for holding the output data.
 * \param tag_len   The length of the tag to generate.
 * \param tag       The buffer for holding the tag.
 *
 * \return         \c 0 on success.
 */
int mbedtls_gcm_crypt_and_tag( mbedtls_gcm_context *ctx,
                       int mode,
                       size_t length,
                       const unsigned char *iv,
                       size_t iv_len,
                       const unsigned char *add,
                       size_t add_len,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t tag_len,
                       unsigned char *tag );

/**
 * \brief           This function performs a GCM authenticated decryption of a 
 *                  buffer.
 *
 * \note For decryption, the output buffer cannot be the same as input buffer.
 *       If the buffers overlap, the output buffer must trail at least 8 Bytes
 *       behind the input buffer.
 *
 * \param ctx       The GCM context.
 * \param length    The length of the input data.
 * \param iv        The initialization vector.
 * \param iv_len    The length of the IV.
 * \param add       The additional data field.
 * \param add_len   The length of the additional data.
 * \param tag       The buffer holding the tag.
 * \param tag_len   The length of the tag.
 * \param input     The buffer holding the input data.
 * \param output    The buffer for holding the output data.
 *
 * \return         0 if successful and authenticated, or
 *                 #MBEDTLS_ERR_GCM_AUTH_FAILED if tag does not match.
 */
int mbedtls_gcm_auth_decrypt( mbedtls_gcm_context *ctx,
                      size_t length,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *add,
                      size_t add_len,
                      const unsigned char *tag,
                      size_t tag_len,
                      const unsigned char *input,
                      unsigned char *output );

/**
 * \brief           This function sets the GCM key, and prepares to authenticate 
 *                  the input data.
 *
 * \param ctx       The GCM context.
 * \param mode      The operation to perform: #MBEDTLS_GCM_ENCRYPT or 
 *                  #MBEDTLS_GCM_DECRYPT.
 * \param iv        The initialization vector.
 * \param iv_len    The length of the IV.
 * \param add       The additional data field, or NULL if \p add_len is 0.
 * \param add_len   The length of the additional data. If 0, \p  add is NULL.
 *
 * \return         \c 0 on success.
 */
int mbedtls_gcm_starts( mbedtls_gcm_context *ctx,
                int mode,
                const unsigned char *iv,
                size_t iv_len,
                const unsigned char *add,
                size_t add_len );

/**
 * \brief           This function encrypts or decrypts using the
 *                  given generic GCM context. 
 *
 *    `             The function expects input to be a multiple of 16
 *                  Bytes. Only the last call before calling 
 *                  mbedtls_gcm_finish() can be less than 16 Bytes. 
 *
 * \note For decryption, the output buffer cannot be the same as input buffer.
 *       If the buffers overlap, the output buffer must trail at least 8 Bytes
 *       behind the input buffer.
 *
 * \param ctx       The GCM context.
 * \param length    The length of the input data.
 * \param input     The buffer holding the input data.
 * \param output    The buffer for holding the output data.
 *
 * \return         \c 0 on success, or #MBEDTLS_ERR_GCM_BAD_INPUT on failure.
 */
int mbedtls_gcm_update( mbedtls_gcm_context *ctx,
                size_t length,
                const unsigned char *input,
                unsigned char *output );

/**
 * \brief           This function finishes the GCM operation, and writes
 *                  the result to the output buffer.
 *
 *                  It wraps up the GCM stream, and generates the 
 *                  tag. The tag can have a maximum length of 16 Bytes.
 *
 * \param ctx       The GCM context.
 * \param tag       The buffer for holding the tag.
 * \param tag_len   The length of the tag to generate. Must be at least four.
 *
 * \return          \c 0 on success, or #MBEDTLS_ERR_GCM_BAD_INPUT on failure.
 */
int mbedtls_gcm_finish( mbedtls_gcm_context *ctx,
                unsigned char *tag,
                size_t tag_len );

/**
 * \brief           This function frees a GCM context and the underlying cipher sub-context.
 *
 * \param ctx       The GCM context to free.
 */
void mbedtls_gcm_free( mbedtls_gcm_context *ctx );

#ifdef __cplusplus
}
#endif

#else  /* !MBEDTLS_GCM_ALT */
#include "gcm_alt.h"
#endif /* !MBEDTLS_GCM_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          The GCM checkup routine.
 *
 * \return         \c 0 on success, or \c 1 on failure.
 */
int mbedtls_gcm_self_test( int verbose );

#ifdef __cplusplus
}
#endif


#endif /* gcm.h */
