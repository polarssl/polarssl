/*
 * Test driver for generating and verifying keys.
 * Currently only supports generating and verifying ECC keys.
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
#include "psa/crypto.h"
#include "psa_crypto_core.h"
#include "psa_crypto_ecp.h"
#include "psa_crypto_rsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/error.h"

#include "test/drivers/key_management.h"
#include "test/drivers/size.h"

#include "test/random.h"

#include <string.h>

mbedtls_test_driver_key_management_hooks_t
    mbedtls_test_driver_key_management_hooks = MBEDTLS_TEST_DRIVER_KEY_MANAGEMENT_INIT;

const uint8_t mbedtls_test_driver_aes_key[16] =
    { 0x36, 0x77, 0x39, 0x7A, 0x24, 0x43, 0x26, 0x46,
      0x29, 0x4A, 0x40, 0x4E, 0x63, 0x52, 0x66, 0x55 };
const uint8_t mbedtls_test_driver_ecdsa_key[32] =
    { 0xdc, 0x7d, 0x9d, 0x26, 0xd6, 0x7a, 0x4f, 0x63,
      0x2c, 0x34, 0xc2, 0xdc, 0x0b, 0x69, 0x86, 0x18,
      0x38, 0x82, 0xc2, 0x06, 0xdf, 0x04, 0xcd, 0xb7,
      0xd6, 0x9a, 0xab, 0xe2, 0x8b, 0xe4, 0xf8, 0x1a };
const uint8_t mbedtls_test_driver_ecdsa_pubkey[65] =
    { 0x04,
      0x85, 0xf6, 0x4d, 0x89, 0xf0, 0x0b, 0xe6, 0x6c,
      0x88, 0xdd, 0x93, 0x7e, 0xfd, 0x6d, 0x7c, 0x44,
      0x56, 0x48, 0xdc, 0xb7, 0x01, 0x15, 0x0b, 0x8a,
      0x95, 0x09, 0x29, 0x58, 0x50, 0xf4, 0x1c, 0x19,
      0x31, 0xe5, 0x71, 0xfb, 0x8f, 0x8c, 0x78, 0x31,
      0x7a, 0x20, 0xb3, 0x80, 0xe8, 0x66, 0x58, 0x4b,
      0xbc, 0x25, 0x16, 0xc3, 0xd2, 0x70, 0x2d, 0x79,
      0x2f, 0x13, 0x1a, 0x92, 0x20, 0x95, 0xfd, 0x6c };

psa_status_t mbedtls_test_transparent_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length )
{
    ++mbedtls_test_driver_key_management_hooks.hits;

    if( mbedtls_test_driver_key_management_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_key_management_hooks.forced_status );

    if( mbedtls_test_driver_key_management_hooks.forced_output != NULL )
    {
        if( mbedtls_test_driver_key_management_hooks.forced_output_length >
            key_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( key, mbedtls_test_driver_key_management_hooks.forced_output,
                mbedtls_test_driver_key_management_hooks.forced_output_length );
        *key_length = mbedtls_test_driver_key_management_hooks.forced_output_length;
        return( PSA_SUCCESS );
    }

    /* Copied from psa_crypto.c */
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR)
    if ( PSA_KEY_TYPE_IS_ECC( psa_get_key_type( attributes ) )
         && PSA_KEY_TYPE_IS_KEY_PAIR( psa_get_key_type( attributes ) ) )
    {
        return( mbedtls_transparent_test_driver_ecp_generate_key(
                    attributes, key, key_size, key_length ) );
    }
    else
#endif /* defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) */

#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR)
    if ( psa_get_key_type( attributes ) == PSA_KEY_TYPE_RSA_KEY_PAIR )
        return( mbedtls_transparent_test_driver_rsa_generate_key(
                    attributes, key, key_size, key_length ) );
    else
#endif /* defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR) */
    {
        (void)attributes;
        return( PSA_ERROR_NOT_SUPPORTED );
    }
}

static psa_status_t mbedtls_test_validate_raw_key_bits( psa_key_type_t type,
                                                 size_t bits)
{
    /* Check that the bit size is acceptable for the key type */
    switch( type )
    {
        case PSA_KEY_TYPE_RAW_DATA:
        case PSA_KEY_TYPE_HMAC:
        case PSA_KEY_TYPE_DERIVE:
            break;
#if defined(PSA_WANT_KEY_TYPE_AES)
        case PSA_KEY_TYPE_AES:
            if( bits != 128 && bits != 192 && bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_CAMELLIA)
        case PSA_KEY_TYPE_CAMELLIA:
            if( bits != 128 && bits != 192 && bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_DES)
        case PSA_KEY_TYPE_DES:
            if( bits != 64 && bits != 128 && bits != 192 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_ARC4)
        case PSA_KEY_TYPE_ARC4:
            if( bits < 8 || bits > 2048 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
#if defined(PSA_WANT_KEY_TYPE_CHACHA20)
        case PSA_KEY_TYPE_CHACHA20:
            if( bits != 256 )
                return( PSA_ERROR_INVALID_ARGUMENT );
            break;
#endif
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }
    if( bits % 8 != 0 )
        return( PSA_ERROR_INVALID_ARGUMENT );

    return( PSA_SUCCESS );
}

psa_status_t mbedtls_test_opaque_generate_key(
    const psa_key_attributes_t *attributes,
    uint8_t *key, size_t key_size, size_t *key_length )
{
    (void) attributes;
    (void) key;
    (void) key_size;
    (void) key_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_transparent_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits)
{
    ++mbedtls_test_driver_key_management_hooks.hits;

    if( mbedtls_test_driver_key_management_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_key_management_hooks.forced_status );

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t type = psa_get_key_type( attributes );

#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
    if( PSA_KEY_TYPE_IS_ECC( type ) )
    {
        status = mbedtls_test_driver_ecp_import_key(
                     attributes,
                     data, data_length,
                     key_buffer, key_buffer_size,
                     key_buffer_length, bits );
    }
    else
#endif
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY)
    if( PSA_KEY_TYPE_IS_RSA( type ) )
    {
        status = mbedtls_test_driver_rsa_import_key(
                     attributes,
                     data, data_length,
                     key_buffer, key_buffer_size,
                     key_buffer_length, bits );
    }
    else
#endif
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        (void)data;
        (void)data_length;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)key_buffer_length;
        (void)bits;
        (void)type;
    }

    return( status );
}


psa_status_t mbedtls_test_opaque_import_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *data,
    size_t data_length,
    uint8_t *key_buffer,
    size_t key_buffer_size,
    size_t *key_buffer_length,
    size_t *bits)
{

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t type = psa_get_key_type( attributes );
    /* This buffer will be used as an intermediate placeholder for the clear
     * key till we wrap it */
    uint8_t *key_buffer_temp;

    key_buffer_temp = mbedtls_calloc( 1, key_buffer_size );
    if( !key_buffer_temp )
        return( PSA_ERROR_INSUFFICIENT_MEMORY );
    if( PSA_KEY_TYPE_IS_UNSTRUCTURED( type ) )
    {
        *bits = PSA_BYTES_TO_BITS( data_length );

        /* Ensure that the bytes-to-bits conversion hasn't overflown. */
        if( data_length > SIZE_MAX / 8 )
            goto exit;

        /* Enforce a size limit, and in particular ensure that the bit
         * size fits in its representation type. */
        if( ( *bits ) > PSA_MAX_KEY_BITS )
            goto exit;

        status = mbedtls_test_validate_raw_key_bits( attributes->core.type, *bits );
        if( status != PSA_SUCCESS )
            goto exit;

        /* Copy the key material accounting for opaque key padding. */
        memcpy( key_buffer_temp, data, data_length );
        status = mbedtls_test_opaque_wrap_key( key_buffer_temp, data_length,
                      key_buffer, key_buffer_size, key_buffer_length );
    }
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
    else if( PSA_KEY_TYPE_IS_ECC( type ) )
    {
        status = mbedtls_test_driver_ecp_import_key(
                     attributes,
                     data, data_length,
                     key_buffer_temp,
                     key_buffer_size,
                     key_buffer_length, bits );
        if( status != PSA_SUCCESS )
           goto exit;
        status = mbedtls_test_opaque_wrap_key( key_buffer_temp, data_length,
                      key_buffer, key_buffer_size, key_buffer_length );
    }
    else
#endif
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY)
    if( PSA_KEY_TYPE_IS_RSA( type ) )
    {
        status = mbedtls_test_driver_rsa_import_key(
                     attributes,
                     data, data_length,
                     key_buffer_temp,
                     key_buffer_size,
                     key_buffer_length, bits );
        if( status != PSA_SUCCESS )
           goto exit;
        status = mbedtls_test_opaque_wrap_key( key_buffer_temp, data_length,
                      key_buffer, key_buffer_size, key_buffer_length );
    }
    else
#endif
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        (void)data;
        (void)data_length;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)key_buffer_length;
        (void)bits;
        (void)type;
    }
exit:
    free( key_buffer_temp );
    return( status );
}

psa_status_t mbedtls_test_opaque_export_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    if( key_length == sizeof( psa_drv_slot_number_t ) )
    {
        /* Assume this is a builtin key based on the key material length. */
        psa_drv_slot_number_t slot_number = *( ( psa_drv_slot_number_t* ) key );

        switch( slot_number )
        {
            case PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT:
                /* This is the ECDSA slot. Verify the key's attributes before
                 * returning the private key. */
                if( psa_get_key_type( attributes ) !=
                    PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 ) )
                    return( PSA_ERROR_CORRUPTION_DETECTED );
                if( psa_get_key_bits( attributes ) != 256 )
                    return( PSA_ERROR_CORRUPTION_DETECTED );
                if( psa_get_key_algorithm( attributes ) !=
                    PSA_ALG_ECDSA( PSA_ALG_ANY_HASH ) )
                    return( PSA_ERROR_CORRUPTION_DETECTED );
                if( ( psa_get_key_usage_flags( attributes ) &
                      PSA_KEY_USAGE_EXPORT ) == 0 )
                    return( PSA_ERROR_CORRUPTION_DETECTED );

                if( data_size < sizeof( mbedtls_test_driver_ecdsa_key ) )
                    return( PSA_ERROR_BUFFER_TOO_SMALL );

                memcpy( data, mbedtls_test_driver_ecdsa_key,
                        sizeof( mbedtls_test_driver_ecdsa_key ) );
                *data_length = sizeof( mbedtls_test_driver_ecdsa_key );
                return( PSA_SUCCESS );

            case PSA_CRYPTO_TEST_DRIVER_BUILTIN_AES_KEY_SLOT:
                /* This is the AES slot. Verify the key's attributes before
                 * returning the key. */
                if( psa_get_key_type( attributes ) != PSA_KEY_TYPE_AES )
                    return( PSA_ERROR_CORRUPTION_DETECTED );
                if( psa_get_key_bits( attributes ) != 128 )
                    return( PSA_ERROR_CORRUPTION_DETECTED );
                if( psa_get_key_algorithm( attributes ) != PSA_ALG_CTR )
                    return( PSA_ERROR_CORRUPTION_DETECTED );
                if( ( psa_get_key_usage_flags( attributes ) &
                      PSA_KEY_USAGE_EXPORT ) == 0 )
                    return( PSA_ERROR_CORRUPTION_DETECTED );

                if( data_size < sizeof( mbedtls_test_driver_aes_key ) )
                    return( PSA_ERROR_BUFFER_TOO_SMALL );

                memcpy( data, mbedtls_test_driver_aes_key,
                        sizeof( mbedtls_test_driver_aes_key ) );
                *data_length = sizeof( mbedtls_test_driver_aes_key );
                return( PSA_SUCCESS );

            default:
                return( PSA_ERROR_DOES_NOT_EXIST );
        }
    }
    else
    {
        /* This buffer will be used as an intermediate placeholder for the opaque key
         * till we unwrap the key into key_buffer */
        uint8_t *key_buffer_temp;
        size_t status = PSA_ERROR_BUFFER_TOO_SMALL;
        psa_key_type_t type = psa_get_key_type( attributes );

        if( PSA_KEY_TYPE_IS_UNSTRUCTURED( type ) ||
            PSA_KEY_TYPE_IS_RSA( type )   ||
            PSA_KEY_TYPE_IS_ECC( type ) )
        {
            key_buffer_temp = mbedtls_calloc( 1, key_length );
            if( !key_buffer_temp )
                return( PSA_ERROR_INSUFFICIENT_MEMORY );
            memcpy( key_buffer_temp, key, key_length );
            status = mbedtls_test_opaque_unwrap_key( key_buffer_temp, key_length,
                                         data, data_size, data_length );
            mbedtls_free( key_buffer_temp );
            return( status );
        }
    }
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t mbedtls_test_transparent_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key_buffer, size_t key_buffer_size,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    ++mbedtls_test_driver_key_management_hooks.hits;

    if( mbedtls_test_driver_key_management_hooks.forced_status != PSA_SUCCESS )
        return( mbedtls_test_driver_key_management_hooks.forced_status );

    if( mbedtls_test_driver_key_management_hooks.forced_output != NULL )
    {
        if( mbedtls_test_driver_key_management_hooks.forced_output_length >
            data_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( data, mbedtls_test_driver_key_management_hooks.forced_output,
                mbedtls_test_driver_key_management_hooks.forced_output_length );
        *data_length = mbedtls_test_driver_key_management_hooks.forced_output_length;
        return( PSA_SUCCESS );
    }

    psa_status_t status = PSA_ERROR_CORRUPTION_DETECTED;
    psa_key_type_t key_type = psa_get_key_type( attributes );

#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
    if( PSA_KEY_TYPE_IS_ECC( key_type ) )
    {
        status = mbedtls_test_driver_ecp_export_public_key(
                      attributes,
                      key_buffer, key_buffer_size,
                      data, data_size, data_length );
    }
    else
#endif
#if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY)
    if( PSA_KEY_TYPE_IS_RSA( key_type ) )
    {
        status = mbedtls_test_driver_rsa_export_public_key(
                      attributes,
                      key_buffer, key_buffer_size,
                      data, data_size, data_length );
    }
    else
#endif
    {
        status = PSA_ERROR_NOT_SUPPORTED;
        (void)key_buffer;
        (void)key_buffer_size;
        (void)key_type;
    }

    return( status );
}

psa_status_t mbedtls_test_opaque_export_public_key(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    uint8_t *data, size_t data_size, size_t *data_length )
{
    if( key_length != sizeof( psa_drv_slot_number_t ) )
    {
        psa_status_t status = PSA_ERROR_NOT_SUPPORTED;
        psa_key_type_t key_type = psa_get_key_type( attributes );
        uint8_t *key_buffer_temp;
        key_buffer_temp = mbedtls_calloc( 1, key_length );
        if( !key_buffer_temp )
            return( PSA_ERROR_INSUFFICIENT_MEMORY );
    #if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_ECC_PUBLIC_KEY)
        if( PSA_KEY_TYPE_IS_ECC( key_type ) )
        {
            status = mbedtls_test_opaque_unwrap_key( key, key_length,
                                         key_buffer_temp, key_length, data_length );
            if( status == PSA_SUCCESS )
                status = mbedtls_test_driver_ecp_export_public_key(
                              attributes,
                              key_buffer_temp, *data_length,
                              data, data_size, data_length );
        }
        else
    #endif
    #if defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_KEY_PAIR) || \
    defined(MBEDTLS_PSA_ACCEL_KEY_TYPE_RSA_PUBLIC_KEY)
        if( PSA_KEY_TYPE_IS_RSA( key_type ) )
        {
            status = mbedtls_test_opaque_unwrap_key( key, key_length,
                                         key_buffer_temp, key_length, data_length );
            if( status == PSA_SUCCESS )
                status = mbedtls_test_driver_rsa_export_public_key(
                              attributes,
                              key_buffer_temp, *data_length,
                              data, data_size, data_length );
        }
        else
    #endif
        {
            status = PSA_ERROR_NOT_SUPPORTED;
            (void)key;
            (void)key_length;
            (void)key_type;
        }
        mbedtls_free( key_buffer_temp );
        return( status );
    }

    /* Assume this is a builtin key based on the key material length. */
    psa_drv_slot_number_t slot_number = *( ( psa_drv_slot_number_t* ) key );
    switch( slot_number )
    {
        case PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT:
            /* This is the ECDSA slot. Verify the key's attributes before
             * returning the public key. */
            if( psa_get_key_type( attributes ) !=
                PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 ) )
                return( PSA_ERROR_CORRUPTION_DETECTED );
            if( psa_get_key_bits( attributes ) != 256 )
                return( PSA_ERROR_CORRUPTION_DETECTED );
            if( psa_get_key_algorithm( attributes ) !=
                PSA_ALG_ECDSA( PSA_ALG_ANY_HASH ) )
                return( PSA_ERROR_CORRUPTION_DETECTED );

            if( data_size < sizeof( mbedtls_test_driver_ecdsa_pubkey ) )
                return( PSA_ERROR_BUFFER_TOO_SMALL );

            memcpy( data, mbedtls_test_driver_ecdsa_pubkey,
                    sizeof( mbedtls_test_driver_ecdsa_pubkey ) );
            *data_length = sizeof( mbedtls_test_driver_ecdsa_pubkey );
            return( PSA_SUCCESS );

        default:
            return( PSA_ERROR_DOES_NOT_EXIST );
    }
}

/* The opaque test driver exposes two built-in keys when builtin key support is
 * compiled in.
 * The key in slot #PSA_CRYPTO_TEST_DRIVER_BUILTIN_AES_KEY_SLOT is an AES-128
 * key which allows CTR mode.
 * The key in slot #PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT is a secp256r1
 * private key which allows ECDSA sign & verify.
 * The key buffer format for these is the raw format of psa_drv_slot_number_t
 * (i.e. for an actual driver this would mean 'builtin_key_size' =
 * sizeof(psa_drv_slot_number_t)).
 */
psa_status_t mbedtls_test_opaque_get_builtin_key(
    psa_drv_slot_number_t slot_number,
    psa_key_attributes_t *attributes,
    uint8_t *key_buffer, size_t key_buffer_size, size_t *key_buffer_length )
{
    switch( slot_number )
    {
        case PSA_CRYPTO_TEST_DRIVER_BUILTIN_AES_KEY_SLOT:
            psa_set_key_type( attributes, PSA_KEY_TYPE_AES );
            psa_set_key_bits( attributes, 128 );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_ENCRYPT |
                PSA_KEY_USAGE_DECRYPT |
                PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm( attributes, PSA_ALG_CTR );

            if( key_buffer_size < sizeof( psa_drv_slot_number_t ) )
                return( PSA_ERROR_BUFFER_TOO_SMALL );

            *( (psa_drv_slot_number_t*) key_buffer ) =
                PSA_CRYPTO_TEST_DRIVER_BUILTIN_AES_KEY_SLOT;
            *key_buffer_length = sizeof( psa_drv_slot_number_t );
            return( PSA_SUCCESS );
        case PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT:
            psa_set_key_type(
                attributes,
                PSA_KEY_TYPE_ECC_KEY_PAIR( PSA_ECC_FAMILY_SECP_R1 ) );
            psa_set_key_bits( attributes, 256 );
            psa_set_key_usage_flags(
                attributes,
                PSA_KEY_USAGE_SIGN_HASH |
                PSA_KEY_USAGE_VERIFY_HASH |
                PSA_KEY_USAGE_EXPORT );
            psa_set_key_algorithm(
                attributes, PSA_ALG_ECDSA( PSA_ALG_ANY_HASH ) );

            if( key_buffer_size < sizeof( psa_drv_slot_number_t ) )
                return( PSA_ERROR_BUFFER_TOO_SMALL );

            *( (psa_drv_slot_number_t*) key_buffer ) =
                PSA_CRYPTO_TEST_DRIVER_BUILTIN_ECDSA_KEY_SLOT;
            *key_buffer_length = sizeof( psa_drv_slot_number_t );
            return( PSA_SUCCESS );
        default:
            return( PSA_ERROR_DOES_NOT_EXIST );
    }
}

psa_status_t mbedtls_test_opaque_copy_key(
    psa_key_attributes_t *attributes,
    const uint8_t *source_key, size_t source_key_size,
    uint8_t *target_key_buffer, size_t target_buffer_size, size_t *key_length )
{
    /* This is a case where the opaque test driver emulates an SE without storage.
     * With that all key context is stored in the wrapped buffer.
     * So no additional house keeping is necessary to reference count the
     * copied keys. This could change when the opaque test driver is extended
     * to support SE with storage, or to emulate an SE without storage but
     * still holding some slot references */
    if( source_key_size > target_buffer_size )
        return( PSA_ERROR_BUFFER_TOO_SMALL );
    memcpy( target_key_buffer, source_key, source_key_size );
    *key_length = source_key_size;
    (void)attributes;
    return( PSA_SUCCESS );
}

/*
 * The wrap function mbedtls_test_opaque_wrap_key pads and wraps the clear key.
 * It expects the clear and wrap buffers to be passed in.
 * clear_key_size is the size of the clear key to be wrapped.
 * wrap_buffer_size is the size of the output buffer wrap_key.
 * The argument key_size is filled with the wrapped key_size on success.
 * */
psa_status_t mbedtls_test_opaque_wrap_key(
    const uint8_t *clear_key,
    size_t clear_key_size,
    uint8_t *wrap_key,
    size_t wrap_buffer_size,
    size_t *key_size )
{
   size_t opaque_key_base_size = mbedtls_test_opaque_get_base_size();
   uint64_t prefix = PSA_CRYPTO_TEST_DRIVER_OPAQUE_PAD_PREFIX;
   if( clear_key_size + opaque_key_base_size > wrap_buffer_size )
      return( PSA_ERROR_BUFFER_TOO_SMALL );
   /* Write in the opaque pad prefix */
   memcpy( wrap_key, &prefix, opaque_key_base_size);
   wrap_key += opaque_key_base_size;
   *key_size = clear_key_size + opaque_key_base_size;
   while( clear_key_size-- )
      *( wrap_key + clear_key_size ) = *( clear_key + clear_key_size ) ^ 0xFF;
   return( PSA_SUCCESS );
}

/*
 * The unwrap function mbedtls_test_opaque_unwrap_key removes a pad prefix and unwraps
 * the wrapped key. It expects the clear and wrap buffers to be passed in.
 * wrap_key_size is the size of the wrapped key,
 * clear_buffer_size is the size of the output buffer clear_key.
 * The argument key_size is filled with the unwrapped(clear) key_size on success.
 * */
psa_status_t mbedtls_test_opaque_unwrap_key(
    const uint8_t *wrap_key,
    size_t wrap_key_size,
    uint8_t *clear_key,
    size_t clear_buffer_size,
    size_t *key_size )
{
   /* Remove the pad prefis from the wrapped key */
   size_t opaque_key_base_size = mbedtls_test_opaque_get_base_size();
   size_t clear_key_size = wrap_key_size - opaque_key_base_size;
   wrap_key += opaque_key_base_size;
   if( ( clear_key_size > clear_buffer_size ) )
      return( PSA_ERROR_INVALID_ARGUMENT );
   *key_size = clear_key_size;
   while( clear_key_size-- )
      *( clear_key + clear_key_size ) = *( wrap_key + clear_key_size ) ^ 0xFF;
   return( PSA_SUCCESS );
}
#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
