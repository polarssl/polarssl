/*
 *  Functions to delegate cryptographic operations to an available
 *  and appropriate accelerator.
 *  Warning: This file will be auto-generated in the future.
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

#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers.h"
#include "mbedtls/platform.h"

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS)

/* Include test driver definition when running tests */
#if defined(PSA_CRYPTO_DRIVER_TEST)
#ifndef PSA_CRYPTO_DRIVER_PRESENT
#define PSA_CRYPTO_DRIVER_PRESENT
#endif
#ifndef PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#define PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT
#endif
#include "test/drivers/test_driver.h"
#endif /* PSA_CRYPTO_DRIVER_TEST */

/* Repeat above block for each JSON-declared driver during autogeneration */

/* Auto-generated values depending on which drivers are registered. ID 0 is
 * reserved for unallocated operations. */
#if defined(PSA_CRYPTO_DRIVER_TEST)
#define PSA_CRYPTO_TRANSPARENT_TEST_DRIVER_ID (1)
#define PSA_CRYPTO_OPAQUE_TEST_DRIVER_ID (2)
#endif /* PSA_CRYPTO_DRIVER_TEST */
#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS */

/* Support the 'old' SE interface when asked to */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
/* PSA_CRYPTO_DRIVER_PRESENT is defined when either a new-style or old-style
 * SE driver is present, to avoid unused argument errors at compile time. */
#ifndef PSA_CRYPTO_DRIVER_PRESENT
#define PSA_CRYPTO_DRIVER_PRESENT
#endif
#include "psa_crypto_se.h"
#endif

/* Start delegation functions */
psa_status_t psa_driver_wrapper_sign_hash( psa_key_slot_t *slot,
                                           psa_algorithm_t alg,
                                           const uint8_t *hash,
                                           size_t hash_length,
                                           uint8_t *signature,
                                           size_t signature_size,
                                           size_t *signature_length )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT)
    /* Try dynamically-registered SE interface first */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if( psa_get_se_driver( slot->attr.lifetime, &drv, &drv_context ) )
    {
        if( drv->asymmetric == NULL ||
            drv->asymmetric->p_sign == NULL )
        {
            /* Key is defined in SE, but we have no way to exercise it */
            return( PSA_ERROR_NOT_SUPPORTED );
        }
        return( drv->asymmetric->p_sign( drv_context,
                                         slot->data.se.slot_number,
                                         alg,
                                         hash, hash_length,
                                         signature, signature_size,
                                         signature_length ) );
    }
#endif /* PSA_CRYPTO_SE_C */

    /* Then try accelerator API */
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(PSA_CRYPTO_DRIVER_TEST)
            status = test_transparent_signature_sign_hash( &attributes,
                                                           slot->data.key.data,
                                                           slot->data.key.bytes,
                                                           alg,
                                                           hash,
                                                           hash_length,
                                                           signature,
                                                           signature_size,
                                                           signature_length );
            /* Declared with fallback == true */
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */
            /* Fell through, meaning no accelerator supports this operation */
            return( PSA_ERROR_NOT_SUPPORTED );
        /* Add cases for opaque driver here */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LIFETIME:
            return( test_opaque_signature_sign_hash( &attributes,
                                                     slot->data.key.data,
                                                     slot->data.key.bytes,
                                                     alg,
                                                     hash,
                                                     hash_length,
                                                     signature,
                                                     signature_size,
                                                     signature_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is declared with a lifetime not known to us */
            return( status );
    }
#else /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void)slot;
    (void)alg;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_size;
    (void)signature_length;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_verify_hash( psa_key_slot_t *slot,
                                             psa_algorithm_t alg,
                                             const uint8_t *hash,
                                             size_t hash_length,
                                             const uint8_t *signature,
                                             size_t signature_length )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT)
    /* Try dynamically-registered SE interface first */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if( psa_get_se_driver( slot->attr.lifetime, &drv, &drv_context ) )
    {
        if( drv->asymmetric == NULL ||
            drv->asymmetric->p_verify == NULL )
        {
            /* Key is defined in SE, but we have no way to exercise it */
            return( PSA_ERROR_NOT_SUPPORTED );
        }
        return( drv->asymmetric->p_verify( drv_context,
                                           slot->data.se.slot_number,
                                           alg,
                                           hash, hash_length,
                                           signature, signature_length ) );
    }
#endif /* PSA_CRYPTO_SE_C */

    /* Then try accelerator API */
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(PSA_CRYPTO_DRIVER_TEST)
            status = test_transparent_signature_verify_hash( &attributes,
                                                             slot->data.key.data,
                                                             slot->data.key.bytes,
                                                             alg,
                                                             hash,
                                                             hash_length,
                                                             signature,
                                                             signature_length );
            /* Declared with fallback == true */
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */
            /* Fell through, meaning no accelerator supports this operation */
            return( PSA_ERROR_NOT_SUPPORTED );
        /* Add cases for opaque driver here */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LIFETIME:
            return( test_opaque_signature_verify_hash( &attributes,
                                                       slot->data.key.data,
                                                       slot->data.key.bytes,
                                                       alg,
                                                       hash,
                                                       hash_length,
                                                       signature,
                                                       signature_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is declared with a lifetime not known to us */
            return( status );
    }
#else /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void)slot;
    (void)alg;
    (void)hash;
    (void)hash_length;
    (void)signature;
    (void)signature_length;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
/** Calculate the size to allocate for buffering a key with given attributes.
 *
 * This function provides a way to get the expected size for storing a key with
 * the given attributes. This will be the size of the export representation for
 * cleartext keys, and a driver-defined size for keys stored by opaque drivers.
 *
 * \param[in] attributes        The key attribute structure of the key to store.
 * \param[out] expected_size    On success, a byte size large enough to contain
 *                              the declared key.
 *
 * \retval #PSA_SUCCESS
 * \retval #PSA_ERROR_NOT_SUPPORTED
 */
static psa_status_t get_expected_key_size( const psa_key_attributes_t *attributes,
                                           size_t *expected_size )
{
    size_t buffer_size = 0;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION( attributes->core.lifetime );
    psa_key_type_t key_type = attributes->core.type;
    size_t key_bits = attributes->core.bits;

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            buffer_size = PSA_KEY_EXPORT_MAX_SIZE( key_type, key_bits );

            if( buffer_size == 0 )
                return( PSA_ERROR_NOT_SUPPORTED );

            *expected_size = buffer_size;
            return( PSA_SUCCESS );

#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LIFETIME:
#ifdef TEST_DRIVER_KEY_CONTEXT_SIZE_FUNCTION
            *expected_size = test_size_function( key_type, key_bits );
            return( PSA_SUCCESS );
#else /* TEST_DRIVER_KEY_CONTEXT_SIZE_FUNCTION */
            if( PSA_KEY_TYPE_IS_KEY_PAIR( key_type ) )
            {
                int public_key_overhead = ( ( TEST_DRIVER_KEY_CONTEXT_STORE_PUBLIC_KEY == 1 ) ?
                                           PSA_KEY_EXPORT_MAX_SIZE( key_type, key_bits ) : 0 );
                *expected_size = TEST_DRIVER_KEY_CONTEXT_BASE_SIZE
                                 + TEST_DRIVER_KEY_CONTEXT_PUBLIC_KEY_SIZE
                                 + public_key_overhead;
            }
            else if( PSA_KEY_TYPE_IS_PUBLIC_KEY( attributes->core.type ) )
            {
                *expected_size = TEST_DRIVER_KEY_CONTEXT_BASE_SIZE
                                 + TEST_DRIVER_KEY_CONTEXT_PUBLIC_KEY_SIZE;
            }
            else if ( !PSA_KEY_TYPE_IS_KEY_PAIR( key_type ) &&
                      !PSA_KEY_TYPE_IS_PUBLIC_KEY ( attributes->core.type ) )
            {
                *expected_size = TEST_DRIVER_KEY_CONTEXT_BASE_SIZE
                                 + TEST_DRIVER_KEY_CONTEXT_SYMMETRIC_FACTOR
                                 * ( ( key_bits + 7 ) / 8 );
            }
            else
            {
                return( PSA_ERROR_NOT_SUPPORTED );
            }
            return( PSA_SUCCESS );
#endif /* TEST_DRIVER_KEY_CONTEXT_SIZE_FUNCTION */
#endif /* PSA_CRYPTO_DRIVER_TEST */

        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }
}
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */

psa_status_t psa_driver_wrapper_generate_key( const psa_key_attributes_t *attributes,
                                              psa_key_slot_t *slot )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT)
    /* Try dynamically-registered SE interface first */
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)
    const psa_drv_se_t *drv;
    psa_drv_se_context_t *drv_context;

    if( psa_get_se_driver( slot->attr.lifetime, &drv, &drv_context ) )
    {
        size_t pubkey_length = 0; /* We don't support this feature yet */
        if( drv->key_management == NULL ||
            drv->key_management->p_generate == NULL )
        {
            /* Key is defined as being in SE, but we have no way to generate it */
            return( PSA_ERROR_NOT_SUPPORTED );
        }
        return( drv->key_management->p_generate(
            drv_context,
            slot->data.se.slot_number, attributes,
            NULL, 0, &pubkey_length ) );
    }
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */

    /* Then try accelerator API */
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    size_t export_size = 0;

    status = get_expected_key_size( attributes, &export_size );
    if( status != PSA_SUCCESS )
        return( status );

    slot->data.key.data = mbedtls_calloc(1, export_size);
    if( slot->data.key.data == NULL )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    slot->data.key.bytes = export_size;

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */

            /* Transparent drivers are limited to generating asymmetric keys */
            if( ! PSA_KEY_TYPE_IS_ASYMMETRIC( slot->attr.type ) )
            {
                status = PSA_ERROR_NOT_SUPPORTED;
                break;
            }
#if defined(PSA_CRYPTO_DRIVER_TEST)
            status = test_transparent_generate_key( attributes,
                                                    slot->data.key.data,
                                                    slot->data.key.bytes,
                                                    &slot->data.key.bytes );
            /* Declared with fallback == true */
            if( status != PSA_ERROR_NOT_SUPPORTED )
                break;
#endif /* PSA_CRYPTO_DRIVER_TEST */
            /* Fell through, meaning no accelerator supports this operation */
            status = PSA_ERROR_NOT_SUPPORTED;
            break;
        /* Add cases for opaque driver here */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LIFETIME:
            status = test_opaque_generate_key( attributes,
                                               slot->data.key.data,
                                               slot->data.key.bytes,
                                               &slot->data.key.bytes );
            break;
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is declared with a lifetime not known to us */
            status = PSA_ERROR_INVALID_ARGUMENT;
            break;
    }

    if( status != PSA_SUCCESS )
    {
        /* free allocated buffer */
        mbedtls_free( slot->data.key.data );
        slot->data.key.data = NULL;
        slot->data.key.bytes = 0;
    }

    return( status );
#else /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void) attributes;
    (void) slot;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_validate_key( const psa_key_attributes_t *attributes,
                                              const uint8_t *data,
                                              size_t data_length,
                                              size_t *bits )
{
#if defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    /* Try accelerators in turn */
#if defined(PSA_CRYPTO_DRIVER_TEST)
    status = test_transparent_validate_key( attributes,
                                            data,
                                            data_length,
                                            bits );
    /* Declared with fallback == true */
    if( status != PSA_ERROR_NOT_SUPPORTED )
        return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */

    return( PSA_ERROR_NOT_SUPPORTED );
#else /* PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
    (void) attributes;
    (void) data;
    (void) data_length;
    (void) bits;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

/*
 * Cipher functions
 */
psa_status_t psa_driver_wrapper_cipher_encrypt(
    psa_key_slot_t *slot,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT) && defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(PSA_CRYPTO_DRIVER_TEST)
            status = test_transparent_cipher_encrypt( &attributes,
                                                      slot->data.key.data,
                                                      slot->data.key.bytes,
                                                      alg,
                                                      input,
                                                      input_length,
                                                      output,
                                                      output_size,
                                                      output_length );
            /* Declared with fallback == true */
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */
            /* Fell through, meaning no accelerator supports this operation */
            return( PSA_ERROR_NOT_SUPPORTED );
        /* Add cases for opaque driver here */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LIFETIME:
            return( test_opaque_cipher_encrypt( &attributes,
                                                slot->data.key.data,
                                                slot->data.key.bytes,
                                                alg,
                                                input,
                                                input_length,
                                                output,
                                                output_size,
                                                output_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is declared with a lifetime not known to us */
            return( status );
    }
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void) slot;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_cipher_decrypt(
    psa_key_slot_t *slot,
    psa_algorithm_t alg,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT) && defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(PSA_CRYPTO_DRIVER_TEST)
            status = test_transparent_cipher_decrypt( &attributes,
                                                      slot->data.key.data,
                                                      slot->data.key.bytes,
                                                      alg,
                                                      input,
                                                      input_length,
                                                      output,
                                                      output_size,
                                                      output_length );
            /* Declared with fallback == true */
            if( status != PSA_ERROR_NOT_SUPPORTED )
                return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */
            /* Fell through, meaning no accelerator supports this operation */
            return( PSA_ERROR_NOT_SUPPORTED );
        /* Add cases for opaque driver here */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LIFETIME:
            return( test_opaque_cipher_decrypt( &attributes,
                                                slot->data.key.data,
                                                slot->data.key.bytes,
                                                alg,
                                                input,
                                                input_length,
                                                output,
                                                output_size,
                                                output_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is declared with a lifetime not known to us */
            return( status );
    }
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void) slot;
    (void) alg;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_size;
    (void) output_length;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_cipher_encrypt_setup(
    psa_operation_driver_context_t *operation,
    psa_key_slot_t *slot,
    psa_algorithm_t alg )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT) && defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(PSA_CRYPTO_DRIVER_TEST)
            operation->ctx = mbedtls_calloc( 1, sizeof(test_transparent_cipher_operation_t) );
            if( operation->ctx == NULL )
                return PSA_ERROR_INSUFFICIENT_MEMORY;

            status = test_transparent_cipher_encrypt_setup( operation->ctx,
                                                            &attributes,
                                                            slot->data.key.data,
                                                            slot->data.key.bytes,
                                                            alg );
            /* Declared with fallback == true */
            if( status == PSA_SUCCESS )
                operation->id = PSA_CRYPTO_TRANSPARENT_TEST_DRIVER_ID;
            else
            {
                mbedtls_platform_zeroize(
                    operation->ctx,
                    sizeof( test_transparent_cipher_operation_t ) );
                mbedtls_free( operation->ctx );
                operation->ctx = NULL;
            }

            return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */
            /* Fell through, meaning no accelerator supports this operation */
            return( PSA_ERROR_NOT_SUPPORTED );
        /* Add cases for opaque driver here */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LIFETIME:
            operation->ctx = mbedtls_calloc( 1, sizeof(test_opaque_cipher_operation_t) );
            if( operation->ctx == NULL )
                return( PSA_ERROR_INSUFFICIENT_MEMORY );

            status = test_opaque_cipher_encrypt_setup( operation->ctx,
                                                       &attributes,
                                                       slot->data.key.data,
                                                       slot->data.key.bytes,
                                                       alg );
            if( status == PSA_SUCCESS )
                operation->id = PSA_CRYPTO_OPAQUE_TEST_DRIVER_ID;
            else
            {
                mbedtls_platform_zeroize(
                    operation->ctx,
                    sizeof( test_opaque_cipher_operation_t ) );
                mbedtls_free( operation->ctx );
                operation->ctx = NULL;
            }

            return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is declared with a lifetime not known to us */
            return( PSA_ERROR_NOT_SUPPORTED );
    }
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void)slot;
    (void)alg;
    (void)operation;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_cipher_decrypt_setup(
    psa_operation_driver_context_t *operation,
    psa_key_slot_t *slot,
    psa_algorithm_t alg )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT) && defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime);
    psa_key_attributes_t attributes = {
      .core = slot->attr
    };

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* Key is stored in the slot in export representation, so
             * cycle through all known transparent accelerators */
#if defined(PSA_CRYPTO_DRIVER_TEST)
            operation->ctx = mbedtls_calloc( 1, sizeof(test_transparent_cipher_operation_t) );
            if( operation->ctx == NULL )
                return( PSA_ERROR_INSUFFICIENT_MEMORY );

            status = test_transparent_cipher_decrypt_setup( operation->ctx,
                                                            &attributes,
                                                            slot->data.key.data,
                                                            slot->data.key.bytes,
                                                            alg );
            /* Declared with fallback == true */
            if( status == PSA_SUCCESS )
                operation->id = PSA_CRYPTO_TRANSPARENT_TEST_DRIVER_ID;
            else
            {
                mbedtls_platform_zeroize(
                    operation->ctx,
                    sizeof( test_transparent_cipher_operation_t ) );
                mbedtls_free( operation->ctx );
                operation->ctx = NULL;
            }

            return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */
            /* Fell through, meaning no accelerator supports this operation */
            return( PSA_ERROR_NOT_SUPPORTED );
        /* Add cases for opaque driver here */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TEST_DRIVER_LIFETIME:
            operation->ctx = mbedtls_calloc( 1, sizeof(test_opaque_cipher_operation_t) );
            if( operation->ctx == NULL )
                return PSA_ERROR_INSUFFICIENT_MEMORY;

            status = test_opaque_cipher_decrypt_setup( operation->ctx,
                                                       &attributes,
                                                       slot->data.key.data,
                                                       slot->data.key.bytes,
                                                       alg );
            if( status == PSA_SUCCESS )
                operation->id = PSA_CRYPTO_OPAQUE_TEST_DRIVER_ID;
            else
            {
                mbedtls_platform_zeroize(
                    operation->ctx,
                    sizeof( test_opaque_cipher_operation_t ) );
                mbedtls_free( operation->ctx );
                operation->ctx = NULL;
            }

            return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is declared with a lifetime not known to us */
            return( PSA_ERROR_NOT_SUPPORTED );
    }
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void)slot;
    (void)alg;
    (void)operation;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_cipher_generate_iv(
    psa_operation_driver_context_t *operation,
    uint8_t *iv,
    size_t iv_size,
    size_t *iv_length )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT) && defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    switch( operation->id )
    {
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TRANSPARENT_TEST_DRIVER_ID:
            return( test_transparent_cipher_generate_iv( operation->ctx,
                                                         iv,
                                                         iv_size,
                                                         iv_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_OPAQUE_TEST_DRIVER_ID:
            return( test_opaque_cipher_generate_iv( operation->ctx,
                                                    iv,
                                                    iv_size,
                                                    iv_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is attached to a driver not known to us */
            return( PSA_ERROR_BAD_STATE );
    }
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void) operation;
    (void) iv;
    (void) iv_size;
    (void) iv_length;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_cipher_set_iv(
    psa_operation_driver_context_t *operation,
    const uint8_t *iv,
    size_t iv_length )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT) && defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    switch( operation->id )
    {
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TRANSPARENT_TEST_DRIVER_ID:
            return( test_transparent_cipher_set_iv( operation->ctx,
                                                    iv,
                                                    iv_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_OPAQUE_TEST_DRIVER_ID:
            return( test_opaque_cipher_set_iv( operation->ctx,
                                               iv,
                                               iv_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is attached to a driver not known to us */
            return( PSA_ERROR_BAD_STATE );
    }
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void) operation;
    (void) iv;
    (void) iv_length;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_cipher_update(
    psa_operation_driver_context_t *operation,
    const uint8_t *input,
    size_t input_length,
    uint8_t *output,
    size_t output_size,
    size_t *output_length )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT) && defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    switch( operation->id )
    {
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TRANSPARENT_TEST_DRIVER_ID:
            return( test_transparent_cipher_update( operation->ctx,
                                                    input,
                                                    input_length,
                                                    output,
                                                    output_size,
                                                    output_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_OPAQUE_TEST_DRIVER_ID:
            return( test_opaque_cipher_update( operation->ctx,
                                               input,
                                               input_length,
                                               output,
                                               output_size,
                                               output_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is attached to a driver not known to us */
            return( PSA_ERROR_BAD_STATE );
    }
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void) operation;
    (void) input;
    (void) input_length;
    (void) output;
    (void) output_length;
    (void) output_size;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_cipher_finish(
    psa_operation_driver_context_t *operation,
    uint8_t *output,
    size_t output_size,
    size_t *output_length )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT) && defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    switch( operation->id )
    {
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TRANSPARENT_TEST_DRIVER_ID:
            return( test_transparent_cipher_finish( operation->ctx,
                                                    output,
                                                    output_size,
                                                    output_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_OPAQUE_TEST_DRIVER_ID:
            return( test_opaque_cipher_finish( operation->ctx,
                                               output,
                                               output_size,
                                               output_length ) );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Key is attached to a driver not known to us */
            return( PSA_ERROR_BAD_STATE );
    }
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void) operation;
    (void) output;
    (void) output_size;
    (void) output_length;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_cipher_abort(
    psa_operation_driver_context_t *operation )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT) && defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;

    /* The object has (apparently) been initialized but it is not in use. It's
     * ok to call abort on such an object, and there's nothing to do. */
    if( operation->ctx == NULL && operation->id == 0 )
        return( PSA_SUCCESS );

    switch( operation->id )
    {
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_TRANSPARENT_TEST_DRIVER_ID:
            status = test_transparent_cipher_abort( operation->ctx );
            mbedtls_platform_zeroize(
                operation->ctx,
                sizeof( test_transparent_cipher_operation_t ) );
            mbedtls_free( operation->ctx );
            operation->ctx = NULL;
            operation->id = 0;

            return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */
#if defined(PSA_CRYPTO_DRIVER_TEST)
        case PSA_CRYPTO_OPAQUE_TEST_DRIVER_ID:
            status = test_opaque_cipher_abort( operation->ctx );
            mbedtls_platform_zeroize(
                operation->ctx,
                sizeof( test_opaque_cipher_operation_t ) );
            mbedtls_free( operation->ctx );
            operation->ctx = NULL;
            operation->id = 0;

            return( status );
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            /* Operation is attached to a driver not known to us */
            return( PSA_ERROR_BAD_STATE );
    }
#else /* PSA_CRYPTO_DRIVER_PRESENT */
    (void)operation;

    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT */
}

psa_status_t psa_driver_wrapper_opaque_key_derivation_oneshot(
    psa_algorithm_t alg,
    psa_key_slot_t *secret_key_slot,
    psa_key_derivation_input_buffer_t *input_array,
    size_t input_count,
    const psa_key_attributes_t *output_key_attributes,
    psa_key_slot_t *output_key_slot )
{
#if defined(PSA_CRYPTO_DRIVER_PRESENT) && defined(PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT)
    psa_key_location_t location = PSA_KEY_LIFETIME_GET_LOCATION(
        secret_key_slot->attr.lifetime );

    switch( location )
    {
        case PSA_KEY_LOCATION_LOCAL_STORAGE:
            /* This is a dedicated opaque wrapper. Should never be called for
             * transparent keys */
            return( PSA_ERROR_NOT_SUPPORTED );
#if defined(PSA_CRYPTO_DRIVER_TEST)
        /* TODO: Add test driver case here */
#endif /* PSA_CRYPTO_DRIVER_TEST */
        default:
            return( PSA_ERROR_INVALID_ARGUMENT );
    }
    (void)alg;
    (void)input_array;
    (void)input_count;
    (void)output_key_attributes;
    (void)output_key_slot;
    return( PSA_ERROR_NOT_SUPPORTED );
#else
    (void)alg;
    (void)secret_key_slot;
    (void)input_array;
    (void)input_count;
    (void)output_key_attributes;
    (void)output_key_slot;
    return( PSA_ERROR_NOT_SUPPORTED );
#endif /* PSA_CRYPTO_DRIVER_PRESENT && PSA_CRYPTO_ACCELERATOR_DRIVER_PRESENT */
}

/* End of automatically generated file. */
