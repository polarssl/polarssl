/**
 * \file pkcs7_write.h
 *
 * \brief PKCS7 generic defines and structures
 *  https://tools.ietf.org/html/rfc2315
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
#ifndef MBEDTLS_PKCS7_WRITE_H
#define MBEDTLS_PKCS7_WRITE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#include "md.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief                   This function generates a PKCS7 containing SignedData (sect 9.1)
 *                          as described by RFC 2315 (https://tools.ietf.org/html/rfc2315).
 *                          It uses the given \p crts and \p keys to sign the \p data and
 *                          return a valid PKCS7 buffer, \p pkcs7.
 *
 * \param pkcs7             The resulting PKCS7, this is the output data.
 * \param pkcs7_size        The length of \p pkcs7.
 * \param data              The data that is to be the contents of the PKCS7.
 *                          This is what gets signed.
 *                          Pass \c NULL if data length is 0.
 * \param data_size         Length of \p data.
 *                          Pass 0 if \p data is \c NULL.
 * \param crts              Array of x509 certificates (DER).
 *                          These should have a corresponding private key
 *                          with same index in \p keys.
 * \param keys              Array of private keys (DER).
 * \param crt_sizes         Array of sizes for \p crts . Indexs should match
 * \param key_sizes         Array of sizes for \p keys.
 * \param key_pairs         Number or key pairs. Array length of key/crtFiles.
 * \param hash_funct        Hash function to use in digest, see mbedtls_md_type_t for
 *                          values in mbedtls/md.h
 *
 * \note                    NOTE: REMEMBER TO UNALLOC \p pkcs7 MEMORY
 *
 * \return 0 or err number
 */
int mbedtls_pkcs7_create( unsigned char **pkcs7, size_t *pkcs7_size,
                          const unsigned char *data, size_t data_size, const unsigned char **crts,
                          const unsigned char **keys, size_t *crt_sizes, size_t *key_sizes, int key_pairs,
                          mbedtls_md_type_t hash_funct );

/**
 * \brief                   This function recievces a buffer in PEM format and returns the DER.
 *
 * \param input             The input buffer in PEM format.
 * \param ilen              The length of the input buffer.
 * \param output            Pointer to the buffer that will be generated, not allocated yet.
 * \param olen              The output length.
 *
 * \note                    Taken from MBEDTLS, mbedtls-mbedtls2.23.0/programs/util/pem2der.c
 * \note                    THIS ALLOCATES MEMORY, REMEMBER TO FREE \p output
 *
 * \return 0 or err number
 */
int mbedtls_convert_pem_to_der( const unsigned char *input, size_t ilen,
                                unsigned char **output, size_t *olen );


#ifdef __cplusplus
}
#endif

#endif
