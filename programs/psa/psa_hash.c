#include "psa/crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define TEST_SHA256_HASH {                                                 \
   0x5a, 0x09, 0xe8, 0xfa, 0x9c, 0x77, 0x80, 0x7b, 0x24, 0xe9, 0x9c, 0x9c, \
   0xf9, 0x99, 0xde, 0xbf, 0xad, 0x84, 0x41, 0xe2, 0x69, 0xeb, 0x96, 0x0e, \
   0x20, 0x1f, 0x61, 0xfc, 0x3d, 0xe2, 0x0d, 0x5a                          \
}

const uint8_t mbedtls_test_sha256_hash[] = TEST_SHA256_HASH;

const size_t mbedtls_test_sha256_hash_len =
    sizeof( mbedtls_test_sha256_hash );

#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_SHA256_C)
int main( void )
{
    printf( "MBEDTLS_PSA_CRYPTO_C and MBEDTLS_SHA256_C"
            "not defined.\r\n" );
    return( EXIT_SUCCESS );
}
#else

int main( void )
{
    uint8_t buf[] = "Hello World!";
    psa_status_t status;
    uint8_t hash[PSA_HASH_MAX_SIZE];
    size_t hash_size;
    psa_hash_operation_t sha256_psa = PSA_HASH_OPERATION_INIT;
    psa_hash_operation_t cloned_sha256 = PSA_HASH_OPERATION_INIT;

    printf( "PSA Crypto API: SHA-256 example\n\n" );

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_crypto_init failed\n" );
        return( EXIT_FAILURE );
    }

    status = psa_hash_setup( &sha256_psa, PSA_ALG_SHA_256 );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_hash_setup failed\n" );
        return( EXIT_FAILURE );
    }

    status = psa_hash_update( &sha256_psa, buf, sizeof( buf ) );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_hash_update failed\n" );
        return( EXIT_FAILURE );
    }

    status = psa_hash_clone( &sha256_psa, &cloned_sha256 );
    if( status != PSA_SUCCESS )
    {
        printf( "PSA hash clone failed" );
        return( EXIT_FAILURE );
    }

    status = psa_hash_finish( &sha256_psa, hash, sizeof( hash ), &hash_size );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_hash_finish failed\n" );
        return( EXIT_FAILURE );
    }

    status = psa_hash_verify( &cloned_sha256, mbedtls_test_sha256_hash, mbedtls_test_sha256_hash_len );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_hash_verify failed\n" );
        return( EXIT_FAILURE );
    }

    printf( "SHA-256(%s):\n", buf );

    for( size_t j = 0; j < hash_size; j++ )
    {
        if( j % 8 == 0 ) printf( "\n    " );
        printf( "%02x ", hash[j] );
    }

    printf( "\n" );

    mbedtls_psa_crypto_free( );
    return( EXIT_SUCCESS );
}
#endif /* MBEDTLS_PSA_CRYPTO_C && MBEDTLS_SHA256_C */
