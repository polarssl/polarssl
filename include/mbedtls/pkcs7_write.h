/**
 * \file pkcs7.h
 *
 * \brief PKCS7 generic defines and structures
 *  https://tools.ietf.org/html/rfc2315
 */
/*
 *  Copyright (C) 2019,  IBM Corp, All Rights Reserved
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
#else
#include MBEDTLS_CONFIG_FILE
#endif


#ifdef __cplusplus
extern "C" {
#endif

/*
 * \brief   generates a PKCS7
 * \param pkcs7, the resulting PKCS7 
 * \param pkcs7_size, the length of pkcs7
 * \param data, data to be added to be used in digest
 * \param data_size , length of data
 * \param crts, array of x509 certificates (DER)
 * \param keys, array of private keys (DER)
 * \param key_pairs, array length of key/crtFiles
 * \param hash_funct, hash function to use in digest, see mbedtls_md_type_t for
 * values in mbedtls/md.h
 *
 * \note NOTE: REMEMBER TO UNALLOC THIS MEMORY
 *
 * \return 0 or err number
 */
int mbedtls_pkcs7_create(unsigned char **pkcs7, size_t *pkcs7_size,
            const unsigned char *data, size_t data_size, const unsigned char **crts,
            const unsigned char **keys, size_t *crt_sizes, size_t *key_sizes, int key_pairs,
            int hash_funct);

/*
 * \brief function inputs a buffer in PEM format and returns the DER
 * \param input, the input buffer in PEM format
 * \param ilen, the length of the input buffer
 * \param output, pointer to the buffer that will be generated, not allocated yet
 * \param olen, the output length
 *
 * \note Taken from MBEDTLS, mbedtls-mbedtls2.23.0/programs/util/pem2der.c many thanks
 *  to these great folks Some things were changed though, like memory allocation
 * \note THIS ALLOCATES MEMORY, FREE SOMETIME AFTER CALLING
 *
 * \return 0 or err number
 */
int mbedtls_convert_pem_to_der(const unsigned char *input, size_t ilen,
                       unsigned char **output, size_t *olen);


#ifdef __cplusplus
}
#endif

#endif
