/*
 *  Password-based file encryption program
 *
 *  Copyright (C) 2018, ARM Limited, All Rights Reserved
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

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#define mbedtls_calloc     calloc
#define mbedtls_free       free
#define mbedtls_fprintf    fprintf
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs12.h"

#define PBCRYPT_SALT_LENGTH 32

#if !defined(MBEDTLS_CIPHER_C) || !defined(MBEDTLS_CTR_DRBG_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_MD_C) || !defined(MBEDTLS_PKCS12_C)
int main( void )
{
    mbedtls_fprintf( stderr,
                     "MBEDTLS_CIPHER_C and/or MBEDTLS_CTR_DRBG_C and/or "
                     "MBEDTLS_ENTROPY_C and/or MBEDTLS_FS_IO and/or "
                     "MBEDTLS_MD_C and/or MBEDTLS_PKCS12_C not defined.\n" );
    return( MBEDTLS_EXIT_FAILURE );
}
#elif ! ( defined(MBEDTLS_GCM_C) )
int main( void )
{
    mbedtls_fprintf( stderr,
                     "No streaming AEAD algorithm enabled.\n" );
    return( MBEDTLS_EXIT_FAILURE );
}
#else

#define PBCRYPT_ERR ( -127 )

static void mbedtls_fprint_error( FILE* stream, int ret )
{
#if defined(MBEDTLS_ERROR_C)
    char buf[100];
    mbedtls_strerror( ret, buf, sizeof( buf ) );
    mbedtls_fprintf( stream, "%s", buf );
#else
    mbedtls_fprintf( stream, "%d", ret );
#endif
}

#define CHECK( expr )                                           \
    do {                                                        \
        ret = ( expr );                                         \
        if( ret == -1 )                                         \
        {                                                       \
            perror( #expr );                                    \
            goto exit;                                          \
        }                                                       \
        else if( ret == PBCRYPT_ERR )                           \
        {                                                       \
            mbedtls_fprintf( stderr, "Error: %s\n", #expr );    \
            goto exit;                                          \
        }                                                       \
        else if( ret != 0 )                                     \
        {                                                       \
            mbedtls_fprintf( stderr, "Error: %s -> ", #expr );  \
            mbedtls_fprint_error( stderr, ret );                \
            mbedtls_fprintf( stderr, "\n" );                    \
            goto exit;                                          \
        }                                                       \
    }                                                           \
    while( 0 )

#define CHECK_NONNULL( expr ) CHECK( - ! ( expr ) )

#define ASSERT( expr )                                       \
    do {                                                     \
        if( ! ( expr ) ) {                                   \
            mbedtls_fprintf( stderr, "Internal error: %s\n", \
                             #expr );                        \
            ret = PBCRYPT_ERR;                               \
            goto exit;                                       \
        }                                                    \
    }                                                        \
    while( 0 )

#define CHECK_FWRITE( data, size, file )                                \
        do                                                              \
        {                                                               \
            size_t CHECK_WRITE__size = fwrite( data, 1, size, file );   \
            if( CHECK_WRITE__size != size )                             \
            {                                                           \
                perror( "fwrite" );                                     \
                ret = -1;                                               \
                goto exit;                                              \
            }                                                           \
        }                                                               \
        while ( 0 )
#define CHECK_FREAD( data, size, file )                                 \
        do                                                              \
        {                                                               \
            size_t CHECK_READ__size = fread( data, 1, size, file );     \
            if( CHECK_READ__size == (size_t)( -1 ) )                    \
            {                                                           \
                perror( "fread" );                                      \
                ret = -1;                                               \
                goto exit;                                              \
            }                                                           \
            else if( CHECK_READ__size != size )                         \
            {                                                           \
                mbedtls_fprintf( stderr,                                \
                                 "fread: short read at line %d\n",      \
                                 __LINE__ );                            \
                ret = PBCRYPT_ERR;                                      \
                goto exit;                                              \
            }                                                           \
        }                                                               \
        while ( 0 )

/* File format:
 * - header
 *     - magic (8 bytes)
 *     - version (1 byte)
 *     - md (1 byte)
 *     - cipher (1 byte)
 *     - salt size (1 byte)
 *     - iterations (4 bytes)
 *     - payload size (8 bytes)
 * - salt
 * - payload
 * - tag of AEAD(header+salt, payload)
 */
#define PBCRYPT_HEADER_SIZE 24

static const char magic[8] = "pbcrypt\000";

typedef struct
{
    const mbedtls_md_info_t *md;
    const mbedtls_cipher_info_t *cipher;
    unsigned char salt_length;
    unsigned iterations;
    size_t payload_size;
} pbcrypt_metadata_t;

typedef struct
{
    const char *md_name;
    const char *cipher_name;
    unsigned char salt_length;
    unsigned iterations;
} pbcrypt_configuration_t;

static const pbcrypt_configuration_t pbcrypt_default_configuration =
{
#if defined(MBEDTLS_SHA512_C)
    "SHA512",
#else
    "SHA256",
#endif
#if defined(MBEDTLS_CHACHAPOLY_C)
    "CHACHA20-POLY1305",
#else
    "AES-256-GCM",
#endif
    16,
    10000,
};


static int cipher_is_aead( const mbedtls_cipher_info_t *info )
{
    switch( info->mode )
    {
        case MBEDTLS_MODE_GCM:
            return( 1 );
        case MBEDTLS_MODE_CCM:
            /* CCM is an AEAD cipher, but it doesn't support the multipart
             * interface, so skip it. */
            return( 0 );
        case MBEDTLS_MODE_CHACHAPOLY:
            return( 1 );
        default:
            return( 0 );
    }
}

static int check_metadata( const pbcrypt_metadata_t *metadata )
{
    if( metadata->md == NULL )
    {
        mbedtls_fprintf( stderr, "Hash algorithm not supported.\n" );
        return( PBCRYPT_ERR );
    }
    if( metadata->cipher == NULL )
    {
        mbedtls_fprintf( stderr, "Cipher algorithm not supported.\n" );
        return( PBCRYPT_ERR );
    }
    if( !cipher_is_aead( metadata->cipher ) )
    {
        mbedtls_fprintf( stderr, "Cipher algorithm is not authenticated.\n" );
        return( PBCRYPT_ERR );
    }
    if( metadata->iterations > INT_MAX )
    {
        mbedtls_fprintf( stderr, "Number of iterations too large.\n" );
        return( PBCRYPT_ERR );
    }
    if( metadata->salt_length > PBCRYPT_SALT_LENGTH )
    {
        mbedtls_fprintf( stderr, "Salt length too large.\n" );
        return( PBCRYPT_ERR );
    }
    return( 0 );
}

static int pbcrypt_serialize_header( const pbcrypt_metadata_t *metadata,
                                     unsigned char *header )
{
    int ret = 0;
    mbedtls_md_type_t md = mbedtls_md_get_type( metadata->md );
    mbedtls_cipher_type_t cipher = metadata->cipher->type;

    memcpy( header, magic, sizeof( magic ) );
    header += sizeof( magic );
    *header++ = 0; /* version */

    /* We know that mbedtls_md_type_t values fit in 1 byte. */
    *header++ = md;
    /* We know that mbedtls_cipher_type_t values fit in 1 byte. */
    *header++ = cipher;
    /* salt_length is a 1-byte type. */
    *header++ = metadata->salt_length;
#if UINT_MAX > 0xffffffff
    ASSERT( metadata->iterations <= 0xffffffff );
#endif
    *header++ = ( metadata->iterations >> 24 ) & 0xff;
    *header++ = ( metadata->iterations >> 16 ) & 0xff;
    *header++ = ( metadata->iterations >> 8 ) & 0xff;
    *header++ = ( metadata->iterations ) & 0xff;

#if SIZE_MAX > 0xffffffff
    *header++ = ( metadata->payload_size >> 56 ) & 0xff;
    *header++ = ( metadata->payload_size >> 48 ) & 0xff;
    *header++ = ( metadata->payload_size >> 40 ) & 0xff;
    *header++ = ( metadata->payload_size >> 32 ) & 0xff;
#else
    memset( header, 0, 4 );
    header += 4;
#endif
    *header++ = ( metadata->payload_size >> 24 ) & 0xff;
    *header++ = ( metadata->payload_size >> 16 ) & 0xff;
    *header++ = ( metadata->payload_size >> 8 ) & 0xff;
    *header++ = ( metadata->payload_size ) & 0xff;

    return( ret );
}

#define DESERIALIZE_CHECK( size, expr, cond, message )  \
    do                                                  \
    {                                                   \
        (void) ( expr );                                \
        if( ! ( cond ) )                                \
        {                                               \
            mbedtls_fprintf( stderr, "%s\n", message ); \
            return( PBCRYPT_ERR );                      \
        }                                               \
        header += ( size );                             \
    }                                                   \
    while( 0 )
#define DESERIALIZE( size, expr )               \
    DESERIALIZE_CHECK( size, expr, 1, "" )
static int pbcrypt_deserialize_header( pbcrypt_metadata_t *metadata,
                                       unsigned char *header )
{
    unsigned long iterations;
    unsigned long long payload_size;
    DESERIALIZE_CHECK( sizeof( magic ), 0,
                       memcmp( header, magic, sizeof( magic ) ) == 0,
                       "File format error: invalid magic header" );
    DESERIALIZE_CHECK( 1, 0, *header == 0,
                       "File format error: invalid version" );
    DESERIALIZE( 1, metadata->md = mbedtls_md_info_from_type( *header ) );
    DESERIALIZE( 1,
                 metadata->cipher = mbedtls_cipher_info_from_type( *header ) );
    DESERIALIZE( 1, metadata->salt_length = *header );
    DESERIALIZE( 4, iterations = ( (unsigned long) header[0] << 24 |
                                   (unsigned long) header[1] << 16 |
                                   (unsigned long) header[2] << 8 |
                                   (unsigned long) header[3] ) );
    if( iterations <= INT_MAX )
        metadata->iterations = iterations;
    else
        metadata->iterations = -1;
    DESERIALIZE_CHECK( 8,
                       payload_size = ( (unsigned long long) header[0] << 56 |
                                        (unsigned long long) header[1] << 48 |
                                        (unsigned long long) header[2] << 40 |
                                        (unsigned long long) header[3] << 32 |
                                        (unsigned long long) header[4] << 24 |
                                        (unsigned long long) header[5] << 16 |
                                        (unsigned long long) header[6] << 8 |
                                        (unsigned long long) header[7] ),
                       payload_size <= SIZE_MAX,
                       "Payload too large" );
    metadata->payload_size = (size_t) payload_size;
    return( 0 );
}

static char *make_temp_file_name( mbedtls_ctr_drbg_context *drbg,
                                  const char *final_name )
{
    size_t n;
    char *temp_file_name = NULL;
    unsigned char random[16];
    if( mbedtls_ctr_drbg_random( drbg, random, sizeof( random ) ) != 0 )
        return( NULL );
    for( n = 0; n < sizeof( random ); n++ )
        random[n] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"[random[n] & 0x1f];
    n = strlen( final_name );
    while( --n != 0 )
    {
        if( final_name[n] == '/' || final_name[n] == '\\' )
        {
            ++n;
            break;
        }
    }
    temp_file_name = mbedtls_calloc( 1, n + sizeof( random ) + 5 );
    if( temp_file_name != NULL )
    {
        memcpy( temp_file_name, final_name, n );
        memcpy( temp_file_name + n, random, sizeof( random ) );
        memcpy( temp_file_name + sizeof( random ), ".tmp", 5 );
    }
    return( temp_file_name );
}

static int pbcrypt_cipher( const mbedtls_cipher_info_t *info,
                           const unsigned char *key, size_t key_size,
                           mbedtls_operation_t operation,
                           const unsigned char *ad, size_t ad_size,
                           size_t plaintext_size,
                           FILE *input_file, FILE *output_file )
{
    mbedtls_cipher_context_t ctx;
    size_t block_size, input_size, output_size, tag_size;
    unsigned char input[256];
    unsigned char output[256];
    size_t offset = 0;
    int ret;
    int key_bits = (int) ( key_size * 8 );

    /* Set up the cipher operation. */
    mbedtls_cipher_init( &ctx );
    CHECK( mbedtls_cipher_setup( &ctx, info ) );
    CHECK( mbedtls_cipher_setkey( &ctx, key, key_bits, operation ) );
    block_size = mbedtls_cipher_get_block_size( &ctx );
    ASSERT( block_size < sizeof( input ) );
    ASSERT( block_size < sizeof( output ) );
    tag_size = 16; /* only support one tag size for now */

    /* Use an all-bit-zero IV. This is ok only because the key is
     * single-use! You must never reuse the same IV with the same key. */
    input_size = mbedtls_cipher_get_iv_size( &ctx );
    ASSERT( input_size <= sizeof( input ) );
    memset( input, 0, input_size );
    CHECK( mbedtls_cipher_set_iv( &ctx, input, input_size ) );

    /* Pass the additional data (which is the file header). */
    CHECK( mbedtls_cipher_update_ad( &ctx, ad, ad_size ) );

    /* Process the payload. */
    while( offset < plaintext_size )
    {
        input_size = sizeof( input ) - block_size;
        if( input_size > plaintext_size - offset )
            input_size = plaintext_size - offset;
        CHECK_FREAD( input, input_size, input_file );
        offset += input_size;
        CHECK( mbedtls_cipher_update( &ctx, input, input_size,
                                      output, &output_size ) );
        ASSERT( output_size <= sizeof( output ) );
        CHECK_FWRITE( output, output_size, output_file );
    }
    CHECK( mbedtls_cipher_finish( &ctx, output, &output_size ) );
    CHECK_FWRITE( output, output_size, output_file );

    if( operation == MBEDTLS_ENCRYPT )
    {
        /* Calculate and write the authentication tag. */
        CHECK( mbedtls_cipher_write_tag( &ctx, output, tag_size ) );
        CHECK_FWRITE( output, tag_size, output_file );
    }
    else
    {
        /* Read and verify the authentication tag. */
        CHECK_FREAD( input, tag_size, input_file );
        CHECK( mbedtls_cipher_check_tag( &ctx, input, tag_size ) );
        /* Note that the location of the tag only depends on public data,
         * namely the payload size in the cleartext header. */
        /* Reject trailing garbage. This isn't a security check, just a
         * sanity check. */
        if( fread( input, 1, 1, input_file ) == 1 )
        {
            fprintf( stderr, "Trailing garbage in the encrypted file.\n" );
            ret = PBCRYPT_ERR;
            goto exit;
        }
    }

exit:
    mbedtls_cipher_free( &ctx );
    return( ret );
}

static int pbcrypt_file( mbedtls_ctr_drbg_context *drbg,
                         const pbcrypt_configuration_t *configuration,
                         char *password,
                         const char *input_file_name,
                         const char *output_file_name )
{
    int ret;
    char *temp_file_name = NULL;
    FILE *input_file = NULL;
    FILE *output_file = NULL;
    unsigned char header[PBCRYPT_HEADER_SIZE + PBCRYPT_SALT_LENGTH];
    pbcrypt_metadata_t metadata;
    unsigned char *salt = header + PBCRYPT_HEADER_SIZE;
    unsigned char key[32];
    size_t key_size;
    mbedtls_operation_t operation;

    CHECK_NONNULL(
        temp_file_name = make_temp_file_name( drbg, output_file_name ) );
    CHECK_NONNULL( input_file = fopen( input_file_name, "rb" ) );
    CHECK_NONNULL( output_file = fopen( temp_file_name, "wb" ) );

    if( configuration != NULL )
    {
        operation = MBEDTLS_ENCRYPT;
        metadata.md = mbedtls_md_info_from_string( configuration->md_name );
        metadata.cipher =
            mbedtls_cipher_info_from_string( configuration->cipher_name );
        metadata.salt_length = PBCRYPT_SALT_LENGTH;
        metadata.iterations = configuration->iterations;
        CHECK( check_metadata( &metadata ) );

        CHECK( fseek( input_file, 0, SEEK_END ) );
        metadata.payload_size = ftell( input_file );
        CHECK( fseek( input_file, 0, SEEK_SET ) );
        CHECK( pbcrypt_serialize_header( &metadata, header ) );
        CHECK_FWRITE( header, PBCRYPT_HEADER_SIZE, output_file );
        CHECK( mbedtls_ctr_drbg_random( drbg, salt, metadata.salt_length ) );
        CHECK_FWRITE( salt, metadata.salt_length, output_file );
    }
    else
    {
        operation = MBEDTLS_DECRYPT;
        CHECK_FREAD( header, PBCRYPT_HEADER_SIZE, input_file );
        CHECK( pbcrypt_deserialize_header( &metadata, header ) );
        CHECK_FREAD( salt, metadata.salt_length, input_file );
        CHECK( check_metadata( &metadata ) );
    }

    key_size = ( metadata.cipher->key_bitlen + 7 ) / 8;

    /* Calculate the key from the password and salt. */
    CHECK( mbedtls_pkcs12_derivation( key, key_size,
                                      (const unsigned char *) password,
                                      strlen( password ),
                                      salt, metadata.salt_length,
                                      mbedtls_md_get_type( metadata.md ),
                                      MBEDTLS_PKCS12_DERIVE_KEY,
                                      metadata.iterations ) );
    /* Zeroize the password as soon as possible. */
    mbedtls_platform_zeroize( password, strlen( password ) );
    password = NULL;

    /* Encrypt-and-authenticate/decrypt-and-verify the data. */
    CHECK( pbcrypt_cipher( metadata.cipher, key, key_size, operation,
                           header, PBCRYPT_HEADER_SIZE + metadata.salt_length,
                           metadata.payload_size,
                           input_file, output_file ) );

    CHECK( fclose( input_file ) );
    input_file = NULL;
    CHECK( fclose( output_file ) );
    output_file = NULL;
    CHECK( rename( temp_file_name, output_file_name ) );

exit:
    if( password != NULL )
        mbedtls_platform_zeroize( password, strlen( password ) );
    mbedtls_platform_zeroize( key, sizeof( key ) );
    if( input_file != NULL )
        fclose( input_file );
    if( output_file != NULL )
        fclose( output_file );
    if( temp_file_name != NULL )
    {
        remove( temp_file_name );
        mbedtls_free( temp_file_name );
    }
    return( ret );
}

#define DESCRIPTION                             \
    "Mbed TLS password-based authenticated encryption demonstration program.\n" \
    "\n"                                                                \
    "COMMON-OPTIONs:\n"                                                 \
    "  input=INPUT-FILE-NAME (mandatory)\n"                             \
    "  output=OUTPUT-FILE-NAME (mandatory)\n"                           \
    "  password=PASSWORD (mandatory)\n"                                 \
    "\n"                                                                \
    "ENCRYPT-OPTIONs:\n"                                                \
    "  md=HASH-ALGORITHM\n"                                             \
    "  cipher=AEAD-ALGORITHM\n"                                         \
    "  iterations=ITERATION-COUNT\n"                                    \
    "\n"                                                                \
    "Note: this program takes a password on the command line to keep it simple\n" \
    "and portable. On many operating systems, command-line arguments are easily\n" \
    "exposed and should not be used for sensitive data. If you wish to adapt\n" \
    "this program to real-world scenarios, please research options for secure\n" \
    "password input on your platform.\n"                                  \
    /* the end */
void help( const char *argv0, FILE *stream )
{
    const char *program_name = argv0 == NULL ? "pbcrypt" : argv0;
    const int *types;
    mbedtls_fprintf( stream,
                     "Usage: %s encrypt {COMMON-OPTION|ENCRYPT-OPTION}...\n",
                     program_name );
    mbedtls_fprintf( stream,
                     "       %s decrypt COMMON-OPTION...\n",
                     program_name );
    mbedtls_fprintf( stream, "%s", DESCRIPTION );
    mbedtls_fprintf( stream, "\nSupported HASH-ALGORITHM values:\n" );
    for( types = mbedtls_md_list( ); *types != 0; types++ )
    {
        const mbedtls_md_info_t *info = mbedtls_md_info_from_type( *types );
        mbedtls_fprintf( stream, "  %s\n", mbedtls_md_get_name( info ) );
    }
    mbedtls_fprintf( stream, "\nSupported CIPHER-ALGORITHM values:\n" );
    for( types = mbedtls_cipher_list( ); *types != 0; types++ )
    {
        const mbedtls_cipher_info_t *info =
            mbedtls_cipher_info_from_type( *types );
        if( ! cipher_is_aead( info ) )
            continue;
        mbedtls_fprintf( stream, "  %s\n", info->name );
    }
}

int main( int argc, char *argv[] )
{
    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    char *password = NULL;
    const char *input_file_name = NULL;
    const char *output_file_name = NULL;
    pbcrypt_configuration_t configuration = pbcrypt_default_configuration;
    int i;
    int encrypting;

    /* Parse the command line. */
    if( argc <= 1 ||
        ! strcmp( argv[1], "help" ) ||
        ! strcmp( argv[1], "-help" ) ||
        ! strcmp( argv[1], "--help" ) )
    {
        help( argv[0], stdout );
        return( MBEDTLS_EXIT_SUCCESS );
    }
    if( argc <= 2 )
    {
        mbedtls_fprintf( stderr,
                         "%s: missing mandatory argument (encrypt|decrypt)\n",
                         argv[0] );
        return( MBEDTLS_EXIT_FAILURE );
    }
    if( ! strcmp( argv[1], "encrypt" ) )
    {
        encrypting = 1;
    }
    else if( ! strcmp( argv[1], "decrypt" ) )
    {
        encrypting = 0;
    }
    else
    {
        mbedtls_fprintf( stderr,
                         "%s: missing mandatory argument (encrypt|decrypt)\n",
                         argv[0] );
        return( MBEDTLS_EXIT_FAILURE );
    }
    for( i = 2; i < argc; i++ )
    {
        char *value = strchr( argv[i], '=' );
        if( value == NULL )
        {
            mbedtls_fprintf( stderr,
                             "%s: missing value for argument %d: %s\n",
                             argv[0], i, argv[i] );
            return( MBEDTLS_EXIT_FAILURE );
        }
        ++value;
        value[-1] = 0;
        if( ! strcmp( argv[i], "input" ) )
            input_file_name = value;
        else if( ! strcmp( argv[i], "output" ) )
            output_file_name = value;
        else if( ! strcmp( argv[i], "password" ) )
        {
            size_t len = strlen( value );
            /* Make a copy of the password, then zeroize it from the command
             * line arguments. On some platforms, this reduces the length of
             * time during which the password is exposed. */
            password = mbedtls_calloc( 1, len + 1 );
            if( password == NULL )
            {
                mbedtls_fprintf( stderr, "%s: out of memory\n", argv[0] );
                return( MBEDTLS_EXIT_FAILURE );
            }
            memcpy( password, value, len + 1 );
            mbedtls_platform_zeroize( value, strlen( value ) );
        }
        else if( encrypting && ! strcmp( argv[i], "md" ) )
            configuration.md_name = value;
        else if( encrypting && ! strcmp( argv[i], "cipher" ) )
            configuration.cipher_name = value;
        else if( encrypting && ! strcmp( argv[i], "iterations" ) )
        {
            unsigned long n = strtoul( value, NULL, 0 );
            if( n == 0 )
            {
                mbedtls_fprintf( stderr,
                                 "%s: invalid iteration count: %s\n",
                                 argv[0], value );
                return( MBEDTLS_EXIT_FAILURE );
            }
            if( n > INT_MAX )
            {
                mbedtls_fprintf( stderr,
                                 "%s: iteration count too large (max %u)\n",
                                 argv[0], INT_MAX );
                return( MBEDTLS_EXIT_FAILURE );
            }
            configuration.iterations = n;
        }
        else
        {
            mbedtls_fprintf( stderr,
                             "%s: unknown parameter %d: %s\n",
                             argv[0], i, argv[i] );
            return( MBEDTLS_EXIT_FAILURE );
        }
        value[-1] = '=';
    }
    if( input_file_name == NULL )
    {
        mbedtls_fprintf( stderr, "%s: missing mandatory argument input=...\n", argv[0] );
        return( MBEDTLS_EXIT_FAILURE );
    }
    if( output_file_name == NULL )
    {
        mbedtls_fprintf( stderr, "%s: missing mandatory argument output=...\n", argv[0] );
        return( MBEDTLS_EXIT_FAILURE );
    }
    if( password == NULL )
    {
        mbedtls_fprintf( stderr, "%s: missing mandatory argument password=...\n", argv[0] );
        return( MBEDTLS_EXIT_FAILURE );
    }

    /* Initialize the random generator. */
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &drbg );
    CHECK( mbedtls_ctr_drbg_seed( &drbg,
                                  mbedtls_entropy_func, &entropy,
                                  NULL, 0 ) );

    /* Process the file. */
    CHECK( pbcrypt_file( &drbg,
                         encrypting ? &configuration : NULL,
                         password, input_file_name, output_file_name ) );

exit:
    if( password != NULL )
    {
        mbedtls_platform_zeroize( password, strlen( password ) );
        mbedtls_free( password );
    }
    mbedtls_entropy_free( &entropy );
    mbedtls_ctr_drbg_free( &drbg );
    return( ret == 0 ? MBEDTLS_EXIT_SUCCESS : MBEDTLS_EXIT_FAILURE );
}

#endif

