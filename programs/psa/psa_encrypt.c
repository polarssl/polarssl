#include "psa/crypto.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define BUFFER_SIZE 500


#if !defined(MBEDTLS_PSA_CRYPTO_C) || !defined(MBEDTLS_AES_C) || \
    !defined(MBEDTLS_CCM_C)
int main( void )
{
    printf( "MBEDTLS_PSA_CRYPTO_C and/or MBEDTLS_AES_C and/or "
            "MBEDTLS_CCM_C not defined.\r\n" );
    return( 0 );
}
#else
int main( void )
{
    psa_status_t status;
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_handle_t key_handle = 0;
    uint8_t encrypt[BUFFER_SIZE] = {0};
    uint8_t decrypt[BUFFER_SIZE] = {0};
    const uint8_t plaintext[] = "Hello World!";
    const uint8_t key_bytes[32] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    unsigned char nonce[16] = {0};
    size_t nonce_length = 13; 
    size_t ciphertext_length;
    size_t plaintext_length;

    status = psa_crypto_init( );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_crypto_init failed\n" );
        return( EXIT_FAILURE );
    }
  
    psa_set_key_usage_flags( &attributes,
                             PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT );
    psa_set_key_algorithm( &attributes, PSA_ALG_CCM );
    psa_set_key_type( &attributes, PSA_KEY_TYPE_AES );
    psa_set_key_bits( &attributes, 256 );

    status = psa_import_key( &attributes, key_bytes, sizeof( key_bytes ), &key_handle );
    if( status != PSA_SUCCESS )
    {
        printf( "psa_import_key failed\n" );
        return( EXIT_FAILURE );
    }

    status = psa_aead_encrypt( key_handle,                       // key
                               PSA_ALG_CCM,                      // algorithm
                               nonce, nonce_length,              // nonce
                               NULL, 0,                          // additional data
                               plaintext, sizeof( plaintext ),   // plaintext
                               encrypt, sizeof( encrypt ),       // ciphertext
                               &ciphertext_length );             // length of output
    if( status != PSA_SUCCESS )
    {
        printf( "psa_aead_encrypt failed\n" );
        return( EXIT_FAILURE );
    }

    printf( "AES-CCM encryption of '%s':\n", plaintext );

    for( size_t j = 0; j < ciphertext_length; j++ )
    {
        if( j % 8 == 0 ) printf( "\n    " );
        printf( "%02x ", encrypt[j] );
    }

    printf( "\n" );

    status = psa_aead_decrypt( key_handle,                  // key
                               PSA_ALG_CCM,                 // algorithm
                               nonce, nonce_length,         // nonce
                               NULL, 0,                     // additional data
                               encrypt, ciphertext_length,  // ciphertext
                               decrypt, sizeof( decrypt ),  // plaintext
                               &plaintext_length );         // length of output
    if( status != PSA_SUCCESS )
    {
        printf( "psa_aead_decrypt failed\n" );
        return( EXIT_FAILURE );
    }

    if( memcmp( plaintext, decrypt, sizeof( plaintext ) ) != 0 )
    {
        printf( "\nEncryption/Decryption failed!\n" );
    }
    else
    {
        printf( "\nEncryption/Decryption successful!\n" );
    }

    psa_destroy_key( key_handle );
    mbedtls_psa_crypto_free( );
    return( 0 );
}
#endif /* MBEDTLS_PSA_CRYPTO_C && MBEDTLS_AES_C && MBEDTLS_CCM_C */
