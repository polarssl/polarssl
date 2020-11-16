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
#ifndef MBEDTLS_PKCS7_H
#define MBEDTLS_PKCS7_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "asn1.h"
#include "x509.h"
#include "x509_crt.h"

/**
 * \name PKCS7 Module Error codes
 * \{
 */
#define MBEDTLS_ERR_PKCS7_INVALID_FORMAT                   -0x5300  /**< The format is invalid, e.g. different type expected. */
#define MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE              -0x53F0  /**< Unavailable feature, e.g. anything other than signed data. */
#define MBEDTLS_ERR_PKCS7_INVALID_VERSION                  -0x5400  /**< The PKCS7 version element is invalid or cannot be parsed. */
#define MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO             -0x54F0  /**< The PKCS7 content info invalid or cannot be parsed. */
#define MBEDTLS_ERR_PKCS7_INVALID_ALG                      -0x5500  /**< The algorithm tag or value is invalid or cannot be parsed. */
#define MBEDTLS_ERR_PKCS7_INVALID_CERT                     -0x55F0  /**< The certificate tag or value is invalid or cannot be parsed. */
#define MBEDTLS_ERR_PKCS7_INVALID_SIGNATURE                -0x5600  /**< Error parsing the signature */
#define MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO              -0x56F0  /**< Error parsing the signer's info */
#define MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA                   -0x5700  /**< Input invalid. */
#define MBEDTLS_ERR_PKCS7_ALLOC_FAILED                     -0x57F0  /**< Allocation of memory failed. */
#define MBEDTLS_ERR_PKCS7_FILE_IO_ERROR                    -0x5800  /**< File Read/Write Error */
#define MBEDTLS_ERR_PKCS7_VERIFY_FAIL                      -0x58F0  /**< Verification Failed */
/* \} name */

/**
 * \name PKCS7 Supported Version
 * \{
 */
#define MBEDTLS_PKCS7_SUPPORTED_VERSION                           0x01
/* \} name */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Type-length-value structure that allows for ASN1 using DER.
 */
typedef mbedtls_asn1_buf mbedtls_pkcs7_buf;

/**
 * Container for ASN1 named information objects.
 * It allows for Relative Distinguished Names (e.g. cn=localhost,ou=code,etc.).
 */
typedef mbedtls_asn1_named_data mbedtls_pkcs7_name;

/**
 * Container for a sequence of ASN.1 items
 */
typedef mbedtls_asn1_sequence mbedtls_pkcs7_sequence;

/**
 * Structure holding PKCS7 signer info
 */
typedef struct mbedtls_pkcs7_signer_info
{
    int version;
    mbedtls_x509_buf serial;
    mbedtls_x509_name issuer;
    mbedtls_x509_buf issuer_raw;
    mbedtls_x509_buf alg_identifier;
    mbedtls_x509_buf sig_alg_identifier;
    mbedtls_x509_buf sig;
    struct mbedtls_pkcs7_signer_info *next;
}
mbedtls_pkcs7_signer_info;

/**
 * Structure holding attached data as part of PKCS7 signed data format
 */
typedef struct mbedtls_pkcs7_data
{
    mbedtls_pkcs7_buf oid;
    mbedtls_pkcs7_buf data;
}
mbedtls_pkcs7_data;

/**
 * Structure holding the signed data section
 */
typedef struct mbedtls_pkcs7_signed_data
{
    int version;
    mbedtls_pkcs7_buf digest_alg_identifiers;
    struct mbedtls_pkcs7_data content;
    int no_of_certs;
    mbedtls_x509_crt certs;
    int no_of_crls;
    mbedtls_x509_crl crl;
    int no_of_signers;
    mbedtls_pkcs7_signer_info signers;
}
mbedtls_pkcs7_signed_data;

/**
 * Structure holding PKCS7 structure, only signed data for now
 */
typedef struct mbedtls_pkcs7
{
    mbedtls_pkcs7_buf raw;
    mbedtls_pkcs7_buf content_type_oid;
    mbedtls_pkcs7_signed_data signed_data;
}
mbedtls_pkcs7;

/**
 * \brief          Initialize pkcs7 structure.
 *
 * \param pkcs7    pkcs7 structure.
 */
void mbedtls_pkcs7_init( mbedtls_pkcs7 *pkcs7 );

/**
 * \brief          Parse a single DER formatted pkcs7 content.
 *
 * \param buf      The buffer holding the DER encoded pkcs7.
 * \param buflen   The size in Bytes of \p buf.
 * \param pkcs7    The pkcs7 structure to be filled by parser for the output.
 *
 * \note           This function makes an internal copy of the PKCS7 buffer
 *                 \p buf. In particular, \p buf may be destroyed or reused
 *                 after this call returns.
 *
 * \return         \c 0, if successful.
 * \return         A negative error code on failure.
 */
int mbedtls_pkcs7_parse_der( const unsigned char *buf, const int buflen,
                             mbedtls_pkcs7 *pkcs7 );

/**
 * \brief          Verification of PKCS7 signature.
 *
 * \param pkcs7    PKCS7 structure containing signature.
 * \param cert     Certificate containing key to verify signature.
 * \param data     Plain data on which signature has to be verified.
 * \param datalen  Length of the data.
 *
 * \note           This function internally calculates the hash on the supplied
 *                 plain data for signature verification.
 *
 * \return         A negative error code on failure.
 */
int mbedtls_pkcs7_signed_data_verify( mbedtls_pkcs7 *pkcs7,
                                      mbedtls_x509_crt *cert,
                                      const unsigned char *data,
                                      size_t datalen );

/**
 * \brief          Verification of PKCS7 signature.
 *
 * \param pkcs7    PKCS7 structure containing signature.
 * \param cert     Certificate containing key to verify signature.
 * \param hash     Hash of the plain data on which signature has to be verified.
 * \param hashlen  Length of the hash.
 *
 * \note           This function is different from mbedtls_pkcs7_signed_data_verify()
 *                 in a way that it directly recieves the hash of the data.
 *
 * \return         A negative error code on failure.
 */
int mbedtls_pkcs7_signed_hash_verify( mbedtls_pkcs7 *pkcs7,
                                      mbedtls_x509_crt *cert,
                                      const unsigned char *hash, int hashlen);

/**
 * \brief          Reads the PKCS7 data from the file in a buffer.
 *
 * \param path     Path of the file.
 * \param buf      Buffer to store the PKCS7 contents from the file.
 * \param n        Size of the buffer (the contents read from the file).
 *
 * \return         A negative error code on failure.
 */
int mbedtls_pkcs7_load_file( const char *path, unsigned char **buf, size_t *n );

/**
 * \brief          Unallocate all PKCS7 data and zeroize the memory.
 *                 It doesn't free pkcs7 itself. It should be done by the caller.
 *
 * \param pkcs7    PKCS7 structure to free.
 */
void mbedtls_pkcs7_free(  mbedtls_pkcs7 *pkcs7 );

#ifdef __cplusplus
}
#endif

#endif /* pkcs7.h */
