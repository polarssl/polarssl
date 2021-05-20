/**
 * \file armv8ce_aes.h
 *
 * \brief ARMv8 Cryptography Extensions -- Optimized code for AES and GCM
 */

/*
 *
 *  Copyright (C) 2006-2017, ARM Limited, All Rights Reserved
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

#ifndef MBEDTLS_ARMV8CE_AES_H
#define MBEDTLS_ARMV8CE_AES_H

#include "aes.h"

/**
 * \brief          [ARMv8 Crypto Extensions] AES-ECB block en(de)cryption
 *
 * \param ctx      AES context
 * \param mode     MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT
 * \param input    16-byte input block
 * \param output   16-byte output block
 *
 * \return         0 on success (cannot fail)
 */

int mbedtls_armv8ce_aes_crypt_ecb( mbedtls_aes_context *ctx,
                                   int mode,
                                   const unsigned char input[16],
                                   unsigned char output[16] );

/**
 * \brief          [ARMv8 Crypto Extensions]  Multiply in GF(2^128) for GCM
 *
 * \param c        Result
 * \param a        First operand
 * \param b        Second operand
 *
 * \note           Both operands and result are bit strings interpreted as
 *                 elements of GF(2^128) as per the GCM spec.
 */

void mbedtls_armv8ce_gcm_mult( unsigned char c[16],
                               const unsigned char a[16],
                               const unsigned char b[16] );

#endif /* MBEDTLS_ARMV8CE_AES_H */
