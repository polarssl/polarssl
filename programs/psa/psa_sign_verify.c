#include "psa/crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_ECDSA_C)
int main( void )
{
    printf( "MBEDTLS_PSA_CRYPTO_C and MBEDTLS_ECDSA_C"
            "not defined.\r\n" );
    return( 0 );
}
#else
int main( void )
{
    psa_status_t status;
    psa_key_handle_t key_handle = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t signature[PSA_SIGNATURE_MAX_SIZE] = {0};
    size_t signature_length;
    const uint8_t key_bytes[] = {
         0x49, 0xc9, 0xa8, 0xc1, 0x8c, 0x4b, 0x88, 0x56, 0x38, 0xc4, 0x31, 0xcf,
         0x1d, 0xf1, 0xc9, 0x94, 0x13, 0x16, 0x09, 0xb5, 0x80, 0xd4, 0xfd, 0x43,
         0xa0, 0xca, 0xb1, 0x7d, 0xb2, 0xf1, 0x3e, 0xee
    };
    uint8_t plaintext[] = "Hello World!";
    const uint8_t hash[] = { /* SHA-256(plaintext) */
       0x5a, 0x09, 0xe8, 0xfa, 0x9c, 0x77, 0x80, 0x7b, 0x24, 0xe9, 0x9c, 0x9c, \
       0xf9, 0x99, 0xde, 0xbf, 0xad, 0x84, 0x41, 0xe2, 0x69, 0xeb, 0x96, 0x0e, \
       0x20, 0x1f, 0x61, 0xfc, 0x3d, 0xe2, 0x0d, 0x5a                          \
    };

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_crypto_init failed\n" );
        return( EXIT_FAILURE );
    }
  
    psa_set_key_usage_flags( &attributes,
                             PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_VERIFY_HASH );
    psa_set_key_algorithm( &attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256) );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1) );

    status = psa_import_key( &attributes, key_bytes, sizeof( key_bytes ), &key_handle );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_import_key failed\n" );
        return( EXIT_FAILURE );
    }

    status = psa_sign_hash( key_handle,                     // key handle 
                            PSA_ALG_ECDSA(PSA_ALG_SHA_256), // signature algorithm
                            hash, sizeof( hash ),           // hash of the message
                            signature, sizeof( signature ), // signature (as output)
                            &signature_length );            // length of signature output
    if( status != PSA_SUCCESS )
    {
        printf( "psa_sign_hash failed\n" );
        return( EXIT_FAILURE );
    }

    printf( "ECDSA-SHA256 signature of SHA-256('%s'):\n", plaintext );

    for( size_t j = 0; j < signature_length; j++ )
    {
        if( j % 8 == 0 ) printf( "\n    " );
        printf( "%02x ", signature[j] );
    }

    printf( "\n" );

    status = psa_verify_hash( key_handle,                     // key handle
                              PSA_ALG_ECDSA(PSA_ALG_SHA_256), // signature algorithm
                              hash, sizeof( hash ),           // hash of message
                              signature, signature_length );  // signature
    if( status != PSA_SUCCESS )
    {
        printf( "psa_verify_hash failed\n" );
        return( EXIT_FAILURE );
    } 
    else
    {
        printf( "\nSignature verification successful!\n" );
    }

    psa_destroy_key( key_handle );
    mbedtls_psa_crypto_free( );
    return( 0 );
}
#endif /* MBEDTLS_PSA_CRYPTO_C && MBEDTLS_ECDSA_C */
