/**
 * \file error_includes.h
 *
 * \brief Internal header for error to string translation
 *
 * \warning This file is generated by \c scripts/generate_errors.pl, do not
 * edit directly!
 *
 * \warning This file is internal, do not include it directly! You want to
 * include \c error.h instead.
 */
/*
 *  Copyright (C) 2006-2019, ARM Limited, All Rights Reserved
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

/*
 * NOTE: skip the usual ifndef double-include guards, as this is intended
 * to be included at a very specific place in a C file to provide part of its
 * code. Skip including config.h for the same reason.
 */

#if defined(MBEDTLS_AES_C)
#include "mbedtls/aes.h"
#endif

#if defined(MBEDTLS_ARC4_C)
#include "mbedtls/arc4.h"
#endif

#if defined(MBEDTLS_ARIA_C)
#include "mbedtls/aria.h"
#endif

#if defined(MBEDTLS_BASE64_C)
#include "mbedtls/base64.h"
#endif

#if defined(MBEDTLS_BIGNUM_C)
#include "mbedtls/bignum.h"
#endif

#if defined(MBEDTLS_BLOWFISH_C)
#include "mbedtls/blowfish.h"
#endif

#if defined(MBEDTLS_CAMELLIA_C)
#include "mbedtls/camellia.h"
#endif

#if defined(MBEDTLS_CCM_C)
#include "mbedtls/ccm.h"
#endif

#if defined(MBEDTLS_CHACHA20_C)
#include "mbedtls/chacha20.h"
#endif

#if defined(MBEDTLS_CHACHAPOLY_C)
#include "mbedtls/chachapoly.h"
#endif

#if defined(MBEDTLS_CIPHER_C)
#include "mbedtls/cipher.h"
#endif

#if defined(MBEDTLS_CMAC_C)
#include "mbedtls/cmac.h"
#endif

#if defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/ctr_drbg.h"
#endif

#if defined(MBEDTLS_DES_C)
#include "mbedtls/des.h"
#endif

#if defined(MBEDTLS_DHM_C)
#include "mbedtls/dhm.h"
#endif

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_ENTROPY_C)
#include "mbedtls/entropy.h"
#endif

#if defined(MBEDTLS_GCM_C)
#include "mbedtls/gcm.h"
#endif

#if defined(MBEDTLS_HKDF_C)
#include "mbedtls/hkdf.h"
#endif

#if defined(MBEDTLS_HMAC_DRBG_C)
#include "mbedtls/hmac_drbg.h"
#endif

#if defined(MBEDTLS_MD_C)
#include "mbedtls/md.h"
#endif

#if defined(MBEDTLS_MD2_C)
#include "mbedtls/md2.h"
#endif

#if defined(MBEDTLS_MD4_C)
#include "mbedtls/md4.h"
#endif

#if defined(MBEDTLS_MD5_C)
#include "mbedtls/md5.h"
#endif

#if defined(MBEDTLS_NET_C)
#include "mbedtls/net_sockets.h"
#endif

#if defined(MBEDTLS_OID_C)
#include "mbedtls/oid.h"
#endif

#if defined(MBEDTLS_PADLOCK_C)
#include "mbedtls/padlock.h"
#endif

#if defined(MBEDTLS_PEM_PARSE_C) || defined(MBEDTLS_PEM_WRITE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_PK_C)
#include "mbedtls/pk.h"
#endif

#if defined(MBEDTLS_PKCS12_C)
#include "mbedtls/pkcs12.h"
#endif

#if defined(MBEDTLS_PKCS5_C)
#include "mbedtls/pkcs5.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#endif

#if defined(MBEDTLS_POLY1305_C)
#include "mbedtls/poly1305.h"
#endif

#if defined(MBEDTLS_RIPEMD160_C)
#include "mbedtls/ripemd160.h"
#endif

#if defined(MBEDTLS_RSA_C)
#include "mbedtls/rsa.h"
#endif

#if defined(MBEDTLS_SHA1_C)
#include "mbedtls/sha1.h"
#endif

#if defined(MBEDTLS_SHA256_C)
#include "mbedtls/sha256.h"
#endif

#if defined(MBEDTLS_SHA512_C)
#include "mbedtls/sha512.h"
#endif

#if defined(MBEDTLS_SSL_TLS_C)
#include "mbedtls/ssl.h"
#endif

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

#if defined(MBEDTLS_X509_USE_C) || defined(MBEDTLS_X509_CREATE_C)
#include "mbedtls/x509.h"
#endif

#if defined(MBEDTLS_XTEA_C)
#include "mbedtls/xtea.h"
#endif
