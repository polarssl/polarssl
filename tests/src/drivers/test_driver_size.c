/*
 * Test driver for retrieving key context size.
 * Only used by opaque drivers.
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

#include <test/helpers.h>

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS) && defined(PSA_CRYPTO_DRIVER_TEST)

#include "test/drivers/size.h"
#include "psa/crypto.h"

/*
 * This macro returns the base size for the key context when SE does not support storage.
 * It is the size of the metadata that gets added to the wrapped key.
 * In its test functionality the metadata is just some padded prefixing to the key.
 */
#define TEST_DRIVER_KEY_CONTEXT_BASE_SIZE  PSA_CRYPTO_TEST_DRIVER_OPAQUE_PAD_PREFIX_SIZE


size_t mbedtls_test_opaque_size_function(
    const psa_key_type_t key_type,
    const size_t key_bits )
{
    size_t key_buffer_size = 0;

    if( key_bits != 0 )
    {
        key_buffer_size = PSA_EXPORT_KEY_OUTPUT_SIZE( key_type, key_bits );
        if( key_buffer_size == 0 )
            return( key_buffer_size );
        /* Include spacing for base size overhead over the key size
         * */
        key_buffer_size += TEST_DRIVER_KEY_CONTEXT_BASE_SIZE;
    }
    return( key_buffer_size );
}

size_t mbedtls_test_opaque_get_base_size()
{
    return TEST_DRIVER_KEY_CONTEXT_BASE_SIZE;
}
#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
