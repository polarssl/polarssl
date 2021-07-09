/*
 *  PSA AEAD driver entry points
 */
/*
 *  Copyright The Mbed TLS Contributors
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
 */

#ifndef PSA_CRYPTO_AEAD_H
#define PSA_CRYPTO_AEAD_H

#include <psa/crypto.h>

/**
 * \brief Process an authenticated encryption operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       aead_encrypt entry point. This function behaves as an aead_encrypt
 *       entry point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * \param[in]  attributes         The attributes of the key to use for the
 *                                operation.
 * \param[in]  key_buffer         The buffer containing the key context.
 * \param      key_buffer_size    Size of the \p key_buffer buffer in bytes.
 * \param      alg                The AEAD algorithm to compute.
 * \param[in]  nonce              Nonce or IV to use.
 * \param      nonce_length       Size of the nonce buffer in bytes. This must
 *                                be appropriate for the selected algorithm.
 *                                The default nonce size is
 *                                PSA_AEAD_NONCE_LENGTH(key_type, alg) where
 *                                key_type is the type of key.
 * \param[in]  additional_data    Additional data that will be authenticated
 *                                but not encrypted.
 * \param      additional_data_length  Size of additional_data in bytes.
 * \param[in]  plaintext          Data that will be authenticated and encrypted.
 * \param      plaintext_length   Size of plaintext in bytes.
 * \param[out] ciphertext         Output buffer for the authenticated and
 *                                encrypted data. The additional data is not
 *                                part of this output. For algorithms where the
 *                                encrypted data and the authentication tag are
 *                                defined as separate outputs, the
 *                                authentication tag is appended to the
 *                                encrypted data.
 * \param      ciphertext_size    Size of the ciphertext buffer in bytes. This
 *                                must be appropriate for the selected algorithm
 *                                and key:
 *                                - A sufficient output size is
 *                                  PSA_AEAD_ENCRYPT_OUTPUT_SIZE(key_type, alg,
 *                                  plaintext_length) where key_type is the type
 *                                  of key.
 *                                - PSA_AEAD_ENCRYPT_OUTPUT_MAX_SIZE(
 *                                  plaintext_length) evaluates to the maximum
 *                                  ciphertext size of any supported AEAD
 *                                  encryption.
 * \param[out] ciphertext_length  On success, the size of the output in the
 *                                ciphertext buffer.
 *
 * \retval #PSA_SUCCESS Success.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         ciphertext_size is too small.
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 */
psa_status_t mbedtls_psa_aead_encrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *plaintext, size_t plaintext_length,
    uint8_t *ciphertext, size_t ciphertext_size, size_t *ciphertext_length );

/**
 * \brief Process an authenticated decryption operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       aead_decrypt entry point. This function behaves as an aead_decrypt
 *       entry point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * \param[in]  attributes         The attributes of the key to use for the
 *                                operation.
 * \param[in]  key_buffer         The buffer containing the key context.
 * \param      key_buffer_size    Size of the \p key_buffer buffer in bytes.
 * \param      alg                The AEAD algorithm to compute.
 * \param[in]  nonce              Nonce or IV to use.
 * \param      nonce_length       Size of the nonce buffer in bytes. This must
 *                                be appropriate for the selected algorithm.
 *                                The default nonce size is
 *                                PSA_AEAD_NONCE_LENGTH(key_type, alg) where
 *                                key_type is the type of key.
 * \param[in]  additional_data    Additional data that has been authenticated
 *                                but not encrypted.
 * \param      additional_data_length  Size of additional_data in bytes.
 * \param[in]  ciphertext         Data that has been authenticated and
 *                                encrypted. For algorithms where the encrypted
 *                                data and the authentication tag are defined
 *                                as separate inputs, the buffer contains
 *                                encrypted data followed by the authentication
 *                                tag.
 * \param      ciphertext_length  Size of ciphertext in bytes.
 * \param[out] plaintext          Output buffer for the decrypted data.
 * \param      plaintext_size     Size of the plaintext buffer in bytes. This
 *                                must be appropriate for the selected algorithm
 *                                and key:
 *                                - A sufficient output size is
 *                                  PSA_AEAD_DECRYPT_OUTPUT_SIZE(key_type, alg,
 *                                  ciphertext_length) where key_type is the
 *                                  type of key.
 *                                - PSA_AEAD_DECRYPT_OUTPUT_MAX_SIZE(
 *                                  ciphertext_length) evaluates to the maximum
 *                                  plaintext size of any supported AEAD
 *                                  decryption.
 * \param[out] plaintext_length   On success, the size of the output in the
 *                                plaintext buffer.
 *
 * \retval #PSA_SUCCESS Success.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The cipher is not authentic.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         plaintext_size is too small.
 * \retval #PSA_ERROR_CORRUPTION_DETECTED
 */
psa_status_t mbedtls_psa_aead_decrypt(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    psa_algorithm_t alg,
    const uint8_t *nonce, size_t nonce_length,
    const uint8_t *additional_data, size_t additional_data_length,
    const uint8_t *ciphertext, size_t ciphertext_length,
    uint8_t *plaintext, size_t plaintext_size, size_t *plaintext_length );

/** Set the key for a multipart authenticated encryption operation.
 *
 *  \note The signature of this function is that of a PSA driver
 *       aead_encrypt_setup entry point. This function behaves as an
 *       aead_encrypt_setup entry point as defined in the PSA driver interface
 *       specification for transparent drivers.
 *
 * If an error occurs at any step after a call to
 * mbedtls_psa_aead_encrypt_setup(), the operation is reset by the PSA core by a
 * call to mbedtls_psa_aead_abort(). The PSA core may call
 * mbedtls_psa_aead_abort() at any time after the operation has been
 * initialized.
 *
 * After a successful call to mbedtls_psa_aead_encrypt_setup(), the PSA core
 * eventually terminates the operation by calling mbedtls_psa_aead_abort().
 *
 * \param[in,out] operation     The operation object to set up. It must have
 *                              been initialized as per the documentation for
 *                              #mbedtls_psa_aead_operation_t and not yet in
 *                              use.
 * \param[in]  attributes       The attributes of the key to use for the
 *                              operation.
 * \param[in]  key_buffer       The buffer containing the key context.
 * \param      key_buffer_size  Size of the \p key_buffer buffer in bytes.
 * \param alg                   The AEAD algorithm to compute
 *                              (\c PSA_ALG_XXX value such that
 *                              #PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p key is not compatible with \p alg.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not an AEAD algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *         Failed to allocate memory for key material
 */
psa_status_t mbedtls_psa_aead_encrypt_setup(
    mbedtls_psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg );

/** Set the key for a multipart authenticated decryption operation.
 *
 * \note The signature of this function is that of a PSA driver
 *       aead_decrypt_setup entry point. This function behaves as an
 *       aead_decrypt_setup entry point as defined in the PSA driver interface
 *       specification for transparent drivers.
 *
 * If an error occurs at any step after a call to
 * mbedtls_psa_aead_decrypt_setup(), the PSA core resets the operation by a
 * call to mbedtls_psa_aead_abort(). The PSA core may call
 * mbedtls_psa_aead_abort() at any time after the operation has been
 * initialized.
 *
 * After a successful call to mbedtls_psa_aead_decrypt_setup(), the PSA core
 * eventually terminates the operation by a call to mbedtls_psa_aead_abort().
 *
 * \param[in,out] operation     The operation object to set up. It must have
 *                              been initialized as per the documentation for
 *                              #mbedtls_psa_aead_operation_t and not yet in
 *                              use.
 * \param[in]  attributes       The attributes of the key to use for the
 *                              operation.
 * \param[in]  key_buffer       The buffer containing the key context.
 * \param      key_buffer_size  Size of the \p key_buffer buffer in bytes.
 * \param alg                   The AEAD algorithm to compute
 *                              (\c PSA_ALG_XXX value such that
 *                              #PSA_ALG_IS_AEAD(\p alg) is true).
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         \p key is not compatible with \p alg.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         \p alg is not supported or is not an AEAD algorithm.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *         Failed to allocate memory for key material
 */
psa_status_t mbedtls_psa_aead_decrypt_setup(
    mbedtls_psa_aead_operation_t *operation,
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer,
    size_t key_buffer_size,
    psa_algorithm_t alg );

/** Set the nonce for an authenticated encryption or decryption operation.
 *
 * \note The signature of this function is that of a PSA driver aead_set_nonce
 *       entry point. This function behaves as an aead_set_nonce entry point as
 *       defined in the PSA driver interface specification for transparent
 *       drivers.
 *
 * This function sets the nonce for the authenticated
 * encryption or decryption operation.
 *
 * The PSA core calls mbedtls_psa_aead_encrypt_setup() or
 * mbedtls_psa_aead_decrypt_setup() before calling this function.
 *
 * If this function returns an error status, the PSA core will call
 * mbedtls_psa_aead_abort().
 *
 * \param[in,out] operation     Active AEAD operation.
 * \param[in] nonce             Buffer containing the nonce to use.
 * \param nonce_length          Size of the nonce in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The size of \p nonce is not acceptable for the chosen algorithm.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         Algorithm previously set is not supported in this configuration of
 *         the library.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *         (GCM and CCM only) Unable to allocate buffer for nonce.
 */
psa_status_t mbedtls_psa_aead_set_nonce(
    mbedtls_psa_aead_operation_t *operation,
    const uint8_t *nonce,
    size_t nonce_length );

/** Declare the lengths of the message and additional data for AEAD.
 *
 * \note The signature of this function is that of a PSA driver aead_set_lengths
 *       entry point. This function behaves as an aead_set_lengths entry point
 *       as defined in the PSA driver interface specification for transparent
 *       drivers.
 *
 * The PSA core calls this function before calling mbedtls_psa_aead_update_ad()
 * or mbedtls_psa_aead_update() if the algorithm for the operation requires it.
 * If the algorithm does not require it, calling this function is optional, but
 * if this function is called then the implementation must enforce the lengths.
 *
 * The PSA core may call this function before or after setting the nonce with
 * mbedtls_psa_aead_set_nonce().
 *
 * - For #PSA_ALG_CCM, calling this function is required.
 * - For the other AEAD algorithms defined in this specification, calling
 *   this function is not required.
 * - For vendor-defined algorithm, refer to the vendor documentation.
 *
 * If this function returns an error status, the PSA core calls
 * mbedtls_psa_aead_abort().
 *
 * \param[in,out] operation     Active AEAD operation.
 * \param ad_length             Size of the non-encrypted additional
 *                              authenticated data in bytes.
 * \param plaintext_length      Size of the plaintext to encrypt in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         At least one of the lengths is not acceptable for the chosen
 *         algorithm.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         Algorithm previously set is not supported in this configuration of
 *         the library.
 */
psa_status_t mbedtls_psa_aead_set_lengths(
    mbedtls_psa_aead_operation_t *operation,
    size_t ad_length,
    size_t plaintext_length );

/** Pass additional data to an active AEAD operation.
 *
 *  \note The signature of this function is that of a PSA driver
 *       aead_update_ad entry point. This function behaves as an aead_update_ad
 *       entry point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * Additional data is authenticated, but not encrypted.
 *
 * The PSA core can call this function multiple times to pass successive
 * fragments of the additional data. It will not call this function after
 * passing data to encrypt or decrypt with mbedtls_psa_aead_update().
 *
 * Before calling this function, the PSA core will:
 *    1. Call either mbedtls_psa_aead_encrypt_setup() or
 *       mbedtls_psa_aead_decrypt_setup().
 *    2. Set the nonce with mbedtls_psa_aead_set_nonce().
 *
 * If this function returns an error status, the PSA core will call
 * mbedtls_psa_aead_abort().
 *
 * \warning When decrypting, until mbedtls_psa_aead_verify() has returned
 *          #PSA_SUCCESS, there is no guarantee that the input is valid.
 *          Therefore, until you have called mbedtls_psa_aead_verify() and it
 *          has returned #PSA_SUCCESS, treat the input as untrusted and prepare
 *          to undo any action that depends on the input if
 *          mbedtls_psa_aead_verify() returns an error status.
 *
 * \note    For the time being #PSA_ALG_CCM and #PSA_ALG_GCM require the entire
 *          additional data to be passed in in one go, i.e.
 *          mbedtls_psa_aead_update_ad() can only be called once.
 *
 * \param[in,out] operation     Active AEAD operation.
 * \param[in] input             Buffer containing the fragment of
 *                              additional data.
 * \param input_length          Size of the \p input buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The total input length overflows the additional data length that
 *         was previously specified with mbedtls_psa_aead_set_lengths().
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         (For GCM / CCM) PSA core attempted to call mbedtls_psa_update_ad()
 *         more than once.
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         Algorithm previously set is not supported in this configuration of
 *         the library.
 */
psa_status_t mbedtls_psa_aead_update_ad(
    mbedtls_psa_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length );

/** Encrypt or decrypt a message fragment in an active AEAD operation.
 *
 *  \note The signature of this function is that of a PSA driver
 *       aead_update entry point. This function behaves as an aead_update entry
 *       point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * Before calling this function, the PSA core will:
 *    1. Call either mbedtls_psa_aead_encrypt_setup() or
 *       mbedtls_psa_aead_decrypt_setup(). The choice of setup function
 *       determines whether this function encrypts or decrypts its input.
 *    2. Set the nonce with mbedtls_psa_aead_set_nonce().
 *    3. Call mbedtls_psa_aead_update_ad() to pass all the additional data.
 *
 * If this function returns an error status, the PSA core will call
 * mbedtls_psa_aead_abort().
 *
 * This function does not require the input to be aligned to any
 * particular block boundary. If the implementation can only process
 * a whole block at a time, it must consume all the input provided, but
 * it may delay the end of the corresponding output until a subsequent
 * call to mbedtls_psa_aead_update(), mbedtls_psa_aead_finish() or
 * mbedtls_psa_aead_verify() provides sufficient input. The amount of data that
 * can be delayed in this way is bounded by #PSA_AEAD_UPDATE_OUTPUT_SIZE.
 *
 * \note For the time being #PSA_ALG_CCM and #PSA_ALG_GCM require the entire
 *       data to be passed in in one go, i.e. mbedtls_psa_aead_update() can only
 *       be called once.
 *
 * \param[in,out] operation     Active AEAD operation.
 * \param[in] input             Buffer containing the message fragment to
 *                              encrypt or decrypt.
 * \param input_length          Size of the \p input buffer in bytes.
 * \param[out] output           Buffer where the output is to be written.
 * \param output_size           Size of the \p output buffer in bytes.
 *                              This must be appropriate for the selected
 *                                algorithm and key:
 *                                - A sufficient output size is
 *                                  #PSA_AEAD_UPDATE_OUTPUT_SIZE(\c key_type,
 *                                  \c alg, \p input_length) where
 *                                  \c key_type is the type of key and \c alg is
 *                                  the algorithm that were used to set up the
 *                                  operation.
 *                                - #PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(\p
 *                                  input_length) evaluates to the maximum
 *                                  output size of any supported AEAD
 *                                  algorithm.
 * \param[out] output_length    On success, the number of bytes
 *                              that make up the returned output.
 *
 * \retval #PSA_SUCCESS
 *         Success.

 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p output buffer is too small.
 *         #PSA_AEAD_UPDATE_OUTPUT_SIZE(\c key_type, \c alg, \p input_length) or
 *         #PSA_AEAD_UPDATE_OUTPUT_MAX_SIZE(\p input_length) can be used to
 *         determine the required buffer size.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The total length of input to mbedtls_psa_aead_update_ad() so far is
 *         less than the additional data length that was previously
 *         specified with mbedtls_psa_aead_set_lengths().
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The total input length overflows the plaintext length that
 *         was previously specified with mbedtls_psa_aead_set_lengths().
 * \retval #PSA_ERROR_NOT_SUPPORTED
 *         (GCM / CCM only) PSA core attempted to call mbedtls_psa_update() more
 *         than once.
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *         (CCM only) Unable to allocate memory for the tag or the body

 */
psa_status_t mbedtls_psa_aead_update(
    mbedtls_psa_aead_operation_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length );

/** Finish encrypting a message in an AEAD operation.
 *
 *  \note The signature of this function is that of a PSA driver
 *       aead_finish entry point. This function behaves as an aead_finish entry
 *       point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * The operation must have been set up by the PSA core with
 * mbedtls_psa_aead_encrypt_setup().
 *
 * This function finishes the authentication of the additional data
 * formed by concatenating the inputs passed to preceding calls to
 * mbedtls_psa_aead_update_ad() with the plaintext formed by concatenating the
 * inputs passed to preceding calls to mbedtls_psa_aead_update().
 *
 * This function has two output buffers:
 * - \p ciphertext contains trailing ciphertext that was buffered from
 *   preceding calls to mbedtls_psa_aead_update().
 * - \p tag contains the authentication tag.
 *
 * Whether or not this function returns successfuly, the PSA core subsequently
 * calls mbedtls_psa_aead_abort() to deactivate the operation.
 *
 * \param[in,out] operation     Active AEAD operation.
 * \param[out] ciphertext       Buffer where the last part of the ciphertext
 *                              is to be written.
 * \param ciphertext_size       Size of the \p ciphertext buffer in bytes.
 *                              This must be appropriate for the selected
 *                              algorithm and key:
 *                              - A sufficient output size is
 *                                #PSA_AEAD_FINISH_OUTPUT_SIZE(\c key_type,
 *                                \c alg) where \c key_type is the type of key
 *                                and \c alg is the algorithm that were used to
 *                                set up the operation.
 *                              - #PSA_AEAD_FINISH_OUTPUT_MAX_SIZE evaluates to
 *                                the maximum output size of any supported AEAD
 *                                algorithm.
 * \param[out] ciphertext_length On success, the number of bytes of
 *                              returned ciphertext.
 * \param[out] tag              Buffer where the authentication tag is
 *                              to be written.
 * \param tag_size              Size of the \p tag buffer in bytes.
 *                              This must be appropriate for the selected
 *                              algorithm and key:
 *                              - The exact tag size is #PSA_AEAD_TAG_LENGTH(\c
 *                                key_type, \c key_bits, \c alg) where
 *                                \c key_type and \c key_bits are the type and
 *                                bit-size of the key, and \c alg are the
 *                                algorithm that were used in the call to
 *                                mbedtls_psa_aead_encrypt_setup().
 *                              - #PSA_AEAD_TAG_MAX_SIZE evaluates to the
 *                                maximum tag size of any supported AEAD
 *                                algorithm.
 * \param[out] tag_length       On success, the number of bytes
 *                              that make up the returned tag.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be an active encryption
 *         operation with a nonce set).
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p ciphertext or \p tag buffer is too small.
 *         #PSA_AEAD_FINISH_OUTPUT_SIZE(\c key_type, \c alg) or
 *         #PSA_AEAD_FINISH_OUTPUT_MAX_SIZE can be used to determine the
 *         required \p ciphertext buffer size. #PSA_AEAD_TAG_LENGTH(\c key_type,
 *         \c key_bits, \c alg) or #PSA_AEAD_TAG_MAX_SIZE can be used to
 *         determine the required \p tag buffer size.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The total length of input to mbedtls_psa_aead_update_ad() so far is
 *         less than the additional data length that was previously
 *         specified with mbedtls_psa_aead_set_lengths().
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The total length of input to mbedtls_psa_aead_update() so far is
 *         less than the plaintext length that was previously
 *         specified with mbedtls_psa_aead_set_lengths().
 */
psa_status_t mbedtls_psa_aead_finish(
    mbedtls_psa_aead_operation_t *operation,
    uint8_t *ciphertext,
    size_t ciphertext_size,
    size_t *ciphertext_length,
    uint8_t *tag,
    size_t tag_size,
    size_t *tag_length );

/** Finish authenticating and decrypting a message in an AEAD operation.
 *
 *  \note The signature of this function is that of a PSA driver
 *       aead_verify entry point. This function behaves as an aead_verify entry
 *       point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * The operation must have been set up by the PSA core with
 * mbedtls_psa_aead_decrypt_setup().
 *
 * This function finishes the authenticated decryption of the message
 * components:
 *
 * -  The additional data consisting of the concatenation of the inputs
 *    passed to preceding calls to mbedtls_psa_aead_update_ad().
 * -  The ciphertext consisting of the concatenation of the inputs passed to
 *    preceding calls to mbedtls_psa_aead_update().
 * -  The tag passed to this function call.
 *
 * If the authentication tag is correct, this function outputs any remaining
 * plaintext and reports success. If the authentication tag is not correct,
 * this function returns #PSA_ERROR_INVALID_SIGNATURE.
 *
 * Whether or not this function returns successfully, the PSA core subsequently
 * calls mbedtls_psa_aead_abort() to deactivate the operation.
 *
 * \note Implementations shall make the best effort to ensure that the
 * comparison between the actual tag and the expected tag is performed
 * in constant time.
 *
 * \param[in,out] operation     Active AEAD operation.
 * \param[out] plaintext        Buffer where the last part of the plaintext
 *                              is to be written. This is the remaining data
 *                              from previous calls to mbedtls_psa_aead_update()
 *                              that could not be processed until the end
 *                              of the input.
 * \param plaintext_size        Size of the \p plaintext buffer in bytes.
 *                              This must be appropriate for the selected
 *                              algorithm and key:
 *                              - A sufficient output size is
 *                                #PSA_AEAD_VERIFY_OUTPUT_SIZE(\c key_type,
 *                                \c alg) where \c key_type is the type of key
 *                                and \c alg is the algorithm that were used to
 *                                set up the operation.
 *                              - #PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE evaluates to
 *                                the maximum output size of any supported AEAD
 *                                algorithm.
 * \param[out] plaintext_length On success, the number of bytes of
 *                              returned plaintext.
 * \param[in] tag               Buffer containing the authentication tag.
 * \param tag_length            Size of the \p tag buffer in bytes.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 * \retval #PSA_ERROR_INVALID_SIGNATURE
 *         The calculations were successful, but the authentication tag is
 *         not correct.
 * \retval #PSA_ERROR_BAD_STATE
 *         The operation state is not valid (it must be an active decryption
 *         operation with a nonce set).
 * \retval #PSA_ERROR_BUFFER_TOO_SMALL
 *         The size of the \p plaintext buffer is too small.
 *         #PSA_AEAD_VERIFY_OUTPUT_SIZE(\c key_type, \c alg) or
 *         #PSA_AEAD_VERIFY_OUTPUT_MAX_SIZE can be used to determine the
 *         required buffer size.
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The total length of input to mbedtls_psa_aead_update_ad() so far is
 *         less than the additional data length that was previously
 *         specified with mbedtls_psa_aead_set_lengths().
 * \retval #PSA_ERROR_INVALID_ARGUMENT
 *         The total length of input to mbedtls_psa_aead_update() so far is
 *         less than the plaintext length that was previously
 *         specified with mbedtls_psa_aead_set_lengths().
 * \retval #PSA_ERROR_INSUFFICIENT_MEMORY
 *         (CCM only) Failed to allocate temporary buffer
 */
psa_status_t mbedtls_psa_aead_verify(
    mbedtls_psa_aead_operation_t *operation,
    uint8_t *plaintext,
    size_t plaintext_size,
    size_t *plaintext_length,
    const uint8_t *tag,
    size_t tag_length );

/** Abort an AEAD operation.
 *
 *  \note The signature of this function is that of a PSA driver
 *       aead_abort entry point. This function behaves as an aead_abort entry
 *       point as defined in the PSA driver interface specification for
 *       transparent drivers.
 *
 * Aborting an operation frees all associated resources except for the
 * \p operation structure itself. Once aborted, the operation object
 * can be reused for another operation by the PSA core by it calling
 * mbedtls_psa_aead_encrypt_setup() or mbedtls_psa_aead_decrypt_setup() again.
 *
 * The PSA core may call this function any time after the operation object has
 * been initialized as described in #mbedtls_psa_aead_operation_t.
 *
 * In particular, calling mbedtls_psa_aead_abort() after the operation has been
 * terminated by a call to mbedtls_psa_aead_abort(), mbedtls_psa_aead_finish()
 * or mbedtls_psa_aead_verify() is safe and has no effect.
 *
 * \param[in,out] operation     Initialized AEAD operation.
 *
 * \retval #PSA_SUCCESS
 *         Success.
 */
psa_status_t mbedtls_psa_aead_abort(
    mbedtls_psa_aead_operation_t *operation );

#endif /* PSA_CRYPTO_AEAD */
