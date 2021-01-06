/*
 * Test driver for signature functions.
 * Currently supports signing and verifying precalculated hashes, using
 * only deterministic ECDSA on curves secp256r1, secp384r1 and secp521r1.
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PSA_CRYPTO_DRIVERS) && defined(PSA_CRYPTO_DRIVER_TEST)
#include "psa/crypto.h"
#include "psa_crypto_core.h"

#include "test/drivers/signature.h"

#if defined(PSA_CRYPTO_DRIVER_TEST_LOOPBACK)
#include "libcopy1/psa/crypto.h"
#else
#include "mbedtls/md.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#endif

#include "test/random.h"

#include <string.h>

test_driver_signature_hooks_t test_driver_signature_sign_hooks = TEST_DRIVER_SIGNATURE_INIT;
test_driver_signature_hooks_t test_driver_signature_verify_hooks = TEST_DRIVER_SIGNATURE_INIT;

psa_status_t test_transparent_signature_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    ++test_driver_signature_sign_hooks.hits;

    if( test_driver_signature_sign_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_signature_sign_hooks.forced_status );

    if( test_driver_signature_sign_hooks.forced_output != NULL )
    {
        if( test_driver_signature_sign_hooks.forced_output_length > signature_size )
            return( PSA_ERROR_BUFFER_TOO_SMALL );
        memcpy( signature, test_driver_signature_sign_hooks.forced_output,
                test_driver_signature_sign_hooks.forced_output_length );
        *signature_length = test_driver_signature_sign_hooks.forced_output_length;
        return( PSA_SUCCESS );
    }

    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

#if defined(PSA_CRYPTO_DRIVER_TEST_LOOPBACK)
    status = libcopy1_psa_crypto_init( );
    if( status != PSA_SUCCESS )
        goto exit;

    libcopy1_psa_key_attributes_t lo_attributes = libcopy1_psa_key_attributes_init( );
    libcopy1_psa_key_id_t lo_id = 0;
    libcopy1_psa_set_key_type( &lo_attributes, psa_get_key_type( attributes ) );
    libcopy1_psa_set_key_bits( &lo_attributes, psa_get_key_bits( attributes ) );
    libcopy1_psa_set_key_usage_flags( &lo_attributes, PSA_KEY_USAGE_SIGN_HASH );
    libcopy1_psa_set_key_algorithm( &lo_attributes, alg );
    status = libcopy1_psa_import_key( &lo_attributes, key, key_length, &lo_id );
    if( status != PSA_SUCCESS )
        goto exit;
    status = libcopy1_psa_sign_hash( lo_id, alg,
                                     hash, hash_length,
                                     signature, signature_size,
                                     signature_length );
    if( status != PSA_SUCCESS )
        goto exit;

exit:
    libcopy1_psa_destroy_key( lo_id );
    libcopy1_mbedtls_psa_crypto_free( );

#elif defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
    defined(MBEDTLS_SHA256_C)
    if( alg != PSA_ALG_DETERMINISTIC_ECDSA( PSA_ALG_SHA_256 ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    mbedtls_ecp_group_id grp_id;
    switch( psa_get_key_type( attributes ) )
    {
        case PSA_ECC_CURVE_SECP_R1:
            switch( psa_get_key_bits( attributes ) )
            {
                case 256:
                    grp_id = MBEDTLS_ECP_DP_SECP256R1;
                    break;
                case 384:
                    grp_id = MBEDTLS_ECP_DP_SECP384R1;
                    break;
                case 521:
                    grp_id = MBEDTLS_ECP_DP_SECP521R1;
                    break;
                default:
                    return( PSA_ERROR_NOT_SUPPORTED );
            }
            break;
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    /* Beyond this point, the driver is actually doing the work of
     * calculating the signature. */

    status = PSA_ERROR_GENERIC_ERROR;
    int ret = 0;
    mbedtls_mpi r, s;
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );
    mbedtls_ecp_keypair ecp;
    mbedtls_ecp_keypair_init( &ecp );
    size_t curve_bytes = PSA_BITS_TO_BYTES( ecp.grp.pbits );

    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &ecp.grp, grp_id ) );
    MBEDTLS_MPI_CHK( mbedtls_ecp_point_read_binary( &ecp.grp, &ecp.Q,
                                                    key, key_length ) );

    /* Code adapted from psa_ecdsa_sign() in psa_crypto.c. */
    mbedtls_md_type_t md_alg = MBEDTLS_MD_SHA256;
    if( signature_size < 2 * curve_bytes )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }
    MBEDTLS_MPI_CHK( mbedtls_ecdsa_sign_det( &ecp.grp, &r, &s, &ecp.d,
                                  hash, hash_length, md_alg ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &r,
                                               signature,
                                               curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_write_binary( &s,
                                               signature + curve_bytes,
                                               curve_bytes ) );
cleanup:
    status = mbedtls_to_psa_error( ret );
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    mbedtls_ecp_keypair_free( &ecp );
    if( status == PSA_SUCCESS )
        *signature_length = 2 * curve_bytes;
#else /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
         defined(MBEDTLS_SHA256_C) */
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
#endif /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
          defined(MBEDTLS_SHA256_C) */

    return( status );
}

psa_status_t test_opaque_signature_sign_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    uint8_t *signature, size_t signature_size, size_t *signature_length )
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_size;
    (void) signature_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

psa_status_t test_transparent_signature_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length )
{
    ++test_driver_signature_verify_hooks.hits;

    if( test_driver_signature_verify_hooks.forced_status != PSA_SUCCESS )
        return( test_driver_signature_verify_hooks.forced_status );

    psa_status_t status = PSA_ERROR_NOT_SUPPORTED;

#if defined(PSA_CRYPTO_DRIVER_TEST_LOOPBACK)
    status = libcopy1_psa_crypto_init( );
    if( status != PSA_SUCCESS )
        goto exit;

    libcopy1_psa_key_attributes_t lo_attributes = libcopy1_psa_key_attributes_init( );
    libcopy1_psa_key_id_t lo_id = 0;
    libcopy1_psa_set_key_type( &lo_attributes, psa_get_key_type( attributes ) );
    libcopy1_psa_set_key_bits( &lo_attributes, psa_get_key_bits( attributes ) );
    libcopy1_psa_set_key_usage_flags( &lo_attributes, PSA_KEY_USAGE_VERIFY_HASH );
    libcopy1_psa_set_key_algorithm( &lo_attributes, alg );
    status = libcopy1_psa_import_key( &lo_attributes, key, key_length, &lo_id );
    if( status != PSA_SUCCESS )
        goto exit;
    status = libcopy1_psa_verify_hash( lo_id, alg,
                                       hash, hash_length,
                                       signature, signature_length );
    if( status != PSA_SUCCESS )
        goto exit;

exit:
    libcopy1_psa_destroy_key( lo_id );
    libcopy1_mbedtls_psa_crypto_free( );

#elif defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
    defined(MBEDTLS_SHA256_C)
    if( alg != PSA_ALG_DETERMINISTIC_ECDSA( PSA_ALG_SHA_256 ) )
        return( PSA_ERROR_NOT_SUPPORTED );
    mbedtls_ecp_group_id grp_id;
    switch( psa_get_key_type( attributes ) )
    {
        case PSA_ECC_CURVE_SECP_R1:
            switch( psa_get_key_bits( attributes ) )
            {
                case 256:
                    grp_id = MBEDTLS_ECP_DP_SECP256R1;
                    break;
                case 384:
                    grp_id = MBEDTLS_ECP_DP_SECP384R1;
                    break;
                case 521:
                    grp_id = MBEDTLS_ECP_DP_SECP521R1;
                    break;
                default:
                    return( PSA_ERROR_NOT_SUPPORTED );
            }
            break;
        default:
            return( PSA_ERROR_NOT_SUPPORTED );
    }

    /* Beyond this point, the driver is actually doing the work of
     * calculating the signature. */

    status = PSA_ERROR_GENERIC_ERROR;
    int ret = 0;
    mbedtls_mpi r, s;
    mbedtls_mpi_init( &r );
    mbedtls_mpi_init( &s );
    mbedtls_ecp_keypair ecp;
    mbedtls_ecp_keypair_init( &ecp );
    mbedtls_test_rnd_pseudo_info rnd_info;
    memset( &rnd_info, 0x5A, sizeof( mbedtls_test_rnd_pseudo_info ) );
    size_t curve_bytes = PSA_BITS_TO_BYTES( ecp.grp.pbits );

    MBEDTLS_MPI_CHK( mbedtls_ecp_group_load( &ecp.grp, grp_id ) );

    /* Code adapted from psa_ecdsa_verify() in psa_crypto.c. */
    if( signature_length < 2 * curve_bytes )
    {
        status = PSA_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &r,
                                              signature,
                                              curve_bytes ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &s,
                                              signature + curve_bytes,
                                              curve_bytes ) );

    if( PSA_KEY_TYPE_IS_PUBLIC_KEY( psa_get_key_type( attributes ) ) )
        MBEDTLS_MPI_CHK( mbedtls_ecp_point_read_binary( &ecp.grp, &ecp.Q,
                                                    key, key_length ) );
    else
    {
        MBEDTLS_MPI_CHK( mbedtls_mpi_read_binary( &ecp.d, key, key_length ) );
        MBEDTLS_MPI_CHK(
            mbedtls_ecp_mul( &ecp.grp, &ecp.Q, &ecp.d, &ecp.grp.G,
                             &mbedtls_test_rnd_pseudo_rand,
                             &rnd_info ) );
    }

    MBEDTLS_MPI_CHK( mbedtls_ecdsa_verify( &ecp.grp, hash, hash_length,
                                &ecp.Q, &r, &s ) );
cleanup:
    status = mbedtls_to_psa_error( ret );
    mbedtls_mpi_free( &r );
    mbedtls_mpi_free( &s );
    mbedtls_ecp_keypair_free( &ecp );
#else /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
         defined(MBEDTLS_SHA256_C) */
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_length;
#endif /* defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_DETERMINISTIC) && \
          defined(MBEDTLS_SHA256_C) */

    return( status );
}

psa_status_t test_opaque_signature_verify_hash(
    const psa_key_attributes_t *attributes,
    const uint8_t *key, size_t key_length,
    psa_algorithm_t alg,
    const uint8_t *hash, size_t hash_length,
    const uint8_t *signature, size_t signature_length )
{
    (void) attributes;
    (void) key;
    (void) key_length;
    (void) alg;
    (void) hash;
    (void) hash_length;
    (void) signature;
    (void) signature_length;
    return( PSA_ERROR_NOT_SUPPORTED );
}

#endif /* MBEDTLS_PSA_CRYPTO_DRIVERS && PSA_CRYPTO_DRIVER_TEST */
