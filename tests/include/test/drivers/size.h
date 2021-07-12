/*
 * Test driver for context size functions
 */
/*  Copyright The Mbed TLS Contributors
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

#ifndef PSA_CRYPTO_TEST_DRIVERS_SIZE_H
#define PSA_CRYPTO_TEST_DRIVERS_SIZE_H

#include "mbedtls/build_info.h"

#if defined(PSA_CRYPTO_DRIVER_TEST)
#include <psa/crypto_driver_common.h>

/*
 * In order to convert the plain text keys to Opaque, the size of the key is
 * padded up by PSA_CRYPTO_TEST_DRIVER_OPAQUE_PAD_PREFIX_SIZE in addition to xor mangling
 * the key. The pad prefix needs to be accounted for while sizing for the key.
 */
#define PSA_CRYPTO_TEST_DRIVER_OPAQUE_PAD_PREFIX           0xBEEFED00U
#define PSA_CRYPTO_TEST_DRIVER_OPAQUE_PAD_PREFIX_SIZE      sizeof( PSA_CRYPTO_TEST_DRIVER_OPAQUE_PAD_PREFIX )

size_t mbedtls_test_opaque_get_base_size();

size_t mbedtls_test_opaque_size_function(
    const psa_key_type_t key_type,
    const size_t key_bits );

#endif /* PSA_CRYPTO_DRIVER_TEST */
#endif /* PSA_CRYPTO_TEST_DRIVERS_SIZE_H */
