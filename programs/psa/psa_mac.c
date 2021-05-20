    #include "psa/crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_SHA256_C)
int main( void )
{
    printf( "MBEDTLS_PSA_CRYPTO_C and MBEDTLS_SHA256_C"
            "not defined.\r\n" );
    return( 0 );
}
#else
int main( void )
{
    uint8_t input[] = "Hello World!";
    psa_status_t status;
    size_t mac_size_real = 0;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t key_handle = 0;
    uint8_t mac[32];
    psa_mac_operation_t operation = PSA_MAC_OPERATION_INIT;
    const uint8_t key_bytes[16] = "kkkkkkkkkkkkkkkk";
    uint8_t incorrect_mac = 0; 
    const uint8_t mbedtls_test_hmac_sha256[] = {
        0xae, 0x72, 0x34, 0x5a, 0x10, 0x36, 0xfb, 0x71,
        0x35, 0x3c, 0x7d, 0x6c, 0x81, 0x98, 0x52, 0x86,
        0x00, 0x4a, 0x43, 0x7c, 0x2d, 0xb3, 0x1a, 0xd8,
        0x67, 0xb1, 0xad, 0x11, 0x4d, 0x18, 0x49, 0x8b
     };

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_crypto_init failed\n" );
        return( EXIT_FAILURE );
    }
  
    psa_set_key_usage_flags( &attributes, PSA_KEY_USAGE_SIGN_HASH );
    psa_set_key_algorithm( &attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256) );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_HMAC );

    status = psa_import_key( &attributes, key_bytes, sizeof( key_bytes ), &key_handle );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_import_key failed\n" );
        return( EXIT_FAILURE );
    }
    
    status = psa_mac_sign_setup( &operation, key_handle, PSA_ALG_HMAC(PSA_ALG_SHA_256) );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_mac_sign_setup failed\n" );
        return( EXIT_FAILURE );
    }
 
    status = psa_mac_update( &operation, input, sizeof( input ) );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_mac_update failed\n" );
        return( EXIT_FAILURE );
    }

    status = psa_mac_sign_finish( &operation, mac, sizeof( mac ), &mac_size_real );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_mac_sign_finish failed\n" );
        return( EXIT_FAILURE );
    }

    printf( "HMAC-SHA-256(%s):\n", input );

    for( size_t j = 0; j < mac_size_real; j++ )
    {
        if( j % 8 == 0 ) printf( "\n    " );
        printf( "%02x ", mac[j] );
        if( mac[j] != mbedtls_test_hmac_sha256[j] )
        {
            incorrect_mac = 1; 
        }
    }

    printf( "\n" );

    if( incorrect_mac == 1 )
    {
        printf( "\nMAC verified incorrectly!\n" );
    }
    else
    {
        printf( "\nMAC verified correctly!\n" );
    }

    psa_destroy_key( key_handle );
    mbedtls_psa_crypto_free( );
    return( EXIT_SUCCESS );
}
#endif /* MBEDTLS_PSA_CRYPTO_C && MBEDTLS_SHA256_C */
