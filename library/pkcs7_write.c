/*
 *  PKCS7 Generation Writing
 *
 *  Copyright The Mbed TLS Contributors
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

#include "common.h"

#if defined(MBEDTLS_PKCS7_WRITE_C)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mbedtls/asn1write.h"
#include "mbedtls/base64.h"
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/pkcs7.h"
#include "mbedtls/pkcs7_write.h"
#include "mbedtls/x509_crt.h"
#if defined(MBEDTLS_FS_IO)
#include <sys/stat.h>
#include <sys/types.h>
#endif
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free free
#define mbedtls_calloc calloc
#define mbedtls_printf printf
#define mbedtls_snprintf snprintf
#endif

/* STRUCTURE OF PKCS7 AND CORRESPONDING FUNCTIONS THAT HANDLE THEM:
 *PKCS7 {
 *    CONSTRUCTED | SEQUENCE                                         ->pkcs7_set_pkcs7_oid
 *        OID (Signed Data)                                          ->^
 *        CONSTRUCTED | CONTEXT SPECIFIC                             ->pkcs7_set_signed_data
 *            CONSTRUCTED | SEQUENCE                                 ->pkcs7_set_version
 *                INTEGER (version)                                  ->^
 *                CONSTRUCTED |SET                                   ->pkcs7_set_algo_id
 *                    OID (hash Alg)                                 ->^
 *                CONSTRUCTED | SEQUENCE                             ->pkcs7_set_signed_data_oid
 *                    OID (PKCS7 Data)                               ->^
 *                CONSTRUCTED | CONTEXT SPECIFIC                     ->pkcs7_set_signer_certs
 *                    entire certificate for each signer             ->^
 *                CONSTRUCTED | SET                                  ->pkcs7_set_signers_data
 *                    CONSTRUCTED | SEQUENCE (for each signer)       ->pkcs7_set_each_signer_data
 *                        INTEGER (signedInfoVersion)                ->pkcs7_set_signer_cert_data
 *                        CONSTRUCTED | SEQUENCE                     ->^
 *                            certificate issuer info                ->^
 *                            certificate serial                     ->^
 *                        CONSTRUCTED | SEQUENCE                     ->pkcs7_set_algorithm_ids
 *                            OID (hash Alg)                         ->^
 *                        CONSTRUCTED | SEQUENCE                     ->^
 *                            OID (Signature Alg (RSA))              ->^
 *                        OCTET STRING (signature)                   ->pkcs7_set_signature
 * }
 */

/* struct for containing information needed to generate the pkcs7
 * used for less function arguments */
typedef struct mbedtls_pkcs7_info {
    unsigned char **crts;
    size_t *crt_sizes;
    unsigned char **keys;
    size_t *key_sizes;
    int key_pairs;
    const unsigned char *data;
    size_t data_size;
    mbedtls_md_type_t hash_funct;
    const char *hash_funct_oid;

} mbedtls_pkcs7_info;


int mbedtls_convert_pem_to_der(const unsigned char *input, size_t ilen,
                               unsigned char **output, size_t *olen)
{
    int ret;
    const unsigned char *s1, *s2, *end = input + ilen;
    size_t len = 0;

    s1 = (unsigned char *) strstr( (const char *) input, "-----BEGIN" );
    if( s1 == NULL ) return (-1);

    s2 = (unsigned char *) strstr( (const char *) input, "-----END" );
    if( s2 == NULL ) return (-1);

    s1 += 10;
    while( s1 < end && *s1 != '-')
        s1++;
    while( s1 < end && *s1 == '-')
        s1++;
    if( *s1 == '\r')
        s1++;
    if( *s1 == '\n')
        s1++;

    if( s2 <= s1 || s2 > end)
        return ( -1 );

    ret = mbedtls_base64_decode( NULL, 0, &len, (const unsigned char *) s1,
                                 s2 - s1);
    if( ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER ) {
        return ( ret );
    }
    /* free this ouside of function */
    *output = mbedtls_calloc( 1, len );
    if( *output == NULL ) {
        return ( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );
    }
    *olen = len;

    if( ( ret = mbedtls_base64_decode( *output, len, &len,
                                       (const unsigned char *) s1, s2 - s1 ) ) != 0 ) {
        return ( ret );
    }

    return ( 0 );
}

static size_t get_leading_whitespace( unsigned char *data, size_t data_size )
{
    size_t white_space_size = 0;
    while( white_space_size < data_size && data[white_space_size] == 0x00 )
        white_space_size++;
    return ( white_space_size );
}


static int pkcs7_hash_create( const unsigned char *data, size_t size,
                              int hash_funct,
                              char **out_hash, size_t *out_hash_size )
{
    const mbedtls_md_info_t *md_info;
    mbedtls_md_context_t ctx;
    int ret;

    md_info = mbedtls_md_info_from_type( hash_funct );

    mbedtls_md_init( &ctx );

    ret = mbedtls_md_setup( &ctx, md_info, 0 );
    if( ret )
        goto out;

    ret = mbedtls_md_starts( &ctx );
    if( ret )
        goto out;

    ret = mbedtls_md_update( &ctx, data, size );
    if( ret )
        goto out;


    *out_hash = mbedtls_calloc( 1, md_info->size );
    if( *out_hash == NULL ) {
        goto out;
    }

    ret = mbedtls_md_finish( &ctx, (unsigned char *) *out_hash );
    if( ret ) {
        mbedtls_free( *out_hash );
        *out_hash = NULL;
        goto out;
    }

    *out_hash_size = md_info->size;
    mbedtls_printf( "Hash generation successful, %s: ", md_info->name );

    ret = 0;

out:
    mbedtls_md_free( &ctx );
    return ( ret );
}

static int alloc_more_mem( unsigned char **start, size_t *size,
                           unsigned char **ptr )
{
    unsigned char *new_start = NULL, *new_ptr = NULL;
    size_t curr_len;
    /* new buffer is double the size of the old buffer, cant realloc bc new data
     * must be infront of old data */
    new_start = mbedtls_calloc( 1, *size * 2 );
    if( new_start == NULL )
        return ( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );

    /* number of bytes to copy is the number of bytes between ptr and the end of
     * the buffer */
    curr_len = ( *start ) + ( *size ) - ( *ptr );
    /* new buffer will be the same as the old one only there will be 'size' number
     * of bytes padded to the front, remember we are writing the buffer from
     * highest memory address to lowest so new data will go in the front */
    new_ptr = new_start + ( *size ) + ( ( *ptr ) - ( *start ) );
    memcpy( new_ptr, *ptr, curr_len );
    /* free old buffer */
    mbedtls_free( *start );
    /* update values */
    *start = new_start;
    *ptr = new_ptr;
    *size = 2 * ( *size );
    return ( 0 );
}

/* helps to determine the appropriate mbedtls_asn1_write function */
enum pkcs7_data_types {
    WRITE_VERSION,
    WRITE_TAG,
    WRITE_OID,
    WRITE_OID_NO_NULL_TAG,
    WRITE_SIGNATURE,
    WRITE_RAW_BUFFER,
    WRITE_SERIAL
};

/**
 * \brief               A general way to add data to the pkcs7 buffer from a given data type.
 * \param start         Start of the pkcs7 data buffer.
 * \param size          Size allocated to start.
 * \param ptr           Points to the current location of where the data has been written
 *                      to. memory from start to pointer should be unused.
 *                      REMEMBER mbedtls writes their buffers from the end of a buffer to
 *                      the start.
 * \param data_type     The type of data that is trying to be written,
 *                      see pkcs7_data_types enum for possible values.
 * \param value         The new data to be added to the pkcs7.
 * \param value_size    The length of the new value, if data_type = tag then it
 *                      is length of data contained in the tag
 *                      (not the length of the tag itself).
 * \param param         Extra argument if adding algorthm identifier (data_type = WRITE_OID)
 *                      to show the size of the param buffer, ignored for other data types.
 * \return              0 for success, else errno.
 */
static int pkcs7_write_data( unsigned char **start, size_t *size,
                             unsigned char **ptr, int data_type, const void *value,
                             size_t value_size, size_t param )
{
    int ret;
    /* pointer for current spot in data, in case it fails but ptr changes */
    unsigned char *ptr_tmp = *ptr;
    do {
        /* do function depending on data type */
        switch ( data_type ) {
            case WRITE_VERSION :
                ret = mbedtls_asn1_write_int( ptr, *start, *(int *) value );
                break;

            case WRITE_TAG :
                ret = mbedtls_asn1_write_len( ptr, *start, value_size );
                if( ret >= 0 )
                    ret = mbedtls_asn1_write_tag( ptr, *start, *(unsigned char *) value );
                break;

            case WRITE_OID :
                ret = mbedtls_asn1_write_algorithm_identifier(
                          ptr, *start, (const char *) value, value_size, param );
                break;

            case WRITE_OID_NO_NULL_TAG :
                ret = mbedtls_asn1_write_oid( ptr, *start, (const char *) value, value_size );
                if( ret >= 0 ) {
                    ret = mbedtls_asn1_write_len( ptr, *start, ptr_tmp - *ptr );
                    if( ret >= 0 )
                        ret = mbedtls_asn1_write_tag( ptr, *start,
                                                      ( MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) );
                }
                break;

            case WRITE_SIGNATURE :
                ret = mbedtls_asn1_write_octet_string( ptr, *start, value, value_size );
                break;

            case WRITE_RAW_BUFFER :
                ret = mbedtls_asn1_write_raw_buffer( ptr, *start, value, value_size );
                break;

            case WRITE_SERIAL :
                ret = mbedtls_asn1_write_tagged_string( ptr, *start, MBEDTLS_ASN1_INTEGER,
                                                        (const char *) value, value_size );
                break;
            default:
                ret = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
        }
        /* if setting data failed, allocate more data */
        if( ret == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL ) {
            /* set ptr back to old one, could have changed when function failed */
            *ptr = ptr_tmp;

            if( alloc_more_mem( start, size, ptr ) )
                return ( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );

            /* reset ptr_tmp because ptr was allacated to some other place in memory */
            ptr_tmp = *ptr;
        } else if( ret < 0 ) {
            return ( MBEDTLS_ERR_ASN1_INVALID_DATA );
        }

    } while( ret == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    return ( 0 );
}

static int pkcs7_set_signature( unsigned char **start, size_t *size,
                                unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info,
                                mbedtls_x509_crt *pub, unsigned char *priv,
                                size_t priv_size )
{
    int ret;
    size_t sig_size, hash_size, sig_size_bits;
    char *hash = NULL, *signature = NULL, *sig_type = NULL;
    mbedtls_pk_context *priv_key;

    priv_key = mbedtls_calloc( 1, sizeof( *priv_key ) );
    if( priv_key == NULL )
        return ( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );

    mbedtls_pk_init( priv_key );
    /* make sure private key parses into private key format */
    ret = mbedtls_pk_parse_key( priv_key, priv, priv_size, NULL, 0 );
    if( ret != 0 )
        goto out;

    /* make sure private key is matched with public key */
    ret = mbedtls_pk_check_pair( &( pub->pk ), priv_key );
    if( ret != 0 )
        goto out;

    /* make sure private key is RSA, otherwise quit */
    sig_type = (char *) priv_key->pk_info->name;
    if( strcmp( sig_type, "RSA" ) ) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO;
        goto out;
    }
    /* get size of RSA signature, ex 2048, 4096 ... */
    sig_size_bits = priv_key->pk_info->get_bitlen( priv_key->pk_ctx );

    /* at this point we know pub and priv are valid, now we need the data to sign */
    ret = pkcs7_hash_create( pkcs7_info->data, pkcs7_info->data_size,
                             pkcs7_info->hash_funct,
                             &hash, &hash_size );
    if( ret != 0 )
        goto out;

    signature = mbedtls_calloc( 1, sig_size_bits / 8 );
    if( signature == NULL ) {
        ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
        goto out;
    }


    ret = mbedtls_pk_sign( priv_key, pkcs7_info->hash_funct,
                           (const unsigned char *) hash, 0,
                           (unsigned char *) signature, &sig_size, 0, NULL );
    if( ret != 0 ) {
        goto out;
    }
    ret = pkcs7_write_data( start, size, ptr, WRITE_SIGNATURE, signature,
                            sig_size, 0 );
    if( ret != 0 ) {
        mbedtls_printf(
            "Failed to add signature to PKCS7 (signature generation was successful "
            "however)\n" );
    }
out:
    mbedtls_pk_free( priv_key );
    mbedtls_free( priv_key );
    mbedtls_free( hash );
    mbedtls_free( signature );

    return ( ret );
}

static int pkcs7_set_algorithm_ids( unsigned char **start, size_t *size,
                                    unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info,
                                    mbedtls_x509_crt *pub, unsigned char *priv,
                                    size_t priv_size )
{
    int ret;
    char *sig_type = NULL;

    ret = pkcs7_set_signature( start, size, ptr, pkcs7_info, pub, priv, priv_size );
    if( ret != 0 )
        return ( ret );

    /* make sure it is rsa encryption, that is all we support right now */
    sig_type = (char *) pub->pk.pk_info->name;
    if( strcmp( sig_type, "RSA" ) ) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_CERT;
        mbedtls_printf( "ERROR: Public Key is of type %s expected RSA\n", sig_type );
        return ret;
    }
    ret = pkcs7_write_data(
              start, size, ptr, WRITE_OID, (void *) MBEDTLS_OID_PKCS1_RSA,
              strlen( MBEDTLS_OID_PKCS1_RSA ), 0 );
    if( ret == 0 ) {
        ret = pkcs7_write_data(
                  start, size, ptr, WRITE_OID, (void *) pkcs7_info->hash_funct_oid,
                  strlen( pkcs7_info->hash_funct_oid ), 0 );
    }

    return ( ret );
}

static int pkcs7_set_signer_cert_data( unsigned char **start, size_t *size,
                                       unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info,
                                       mbedtls_x509_crt *pub, unsigned char *priv,
                                       size_t priv_size )
{
    int ret, signed_info_version = 1;
    size_t bytes_written_in_step, curr_len;
    unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

    ret = pkcs7_set_algorithm_ids( start, size, ptr, pkcs7_info, pub, priv,
                                   priv_size );
    if( ret != 0 )
        return ( ret );

    /* add serial */
    curr_len = *size - ( *ptr - *start );
    ret = pkcs7_write_data( start, size, ptr,
                            WRITE_SERIAL,
                            pub->serial.p, pub->serial.len, 0 );
    if( ret != 0 ) {
        mbedtls_printf(
            "ERROR: Failed to add certificate serial number to Signer info of PKCS7\n" );

        return ( ret );
    }
    ret = pkcs7_write_data( start, size, ptr, WRITE_RAW_BUFFER,
                            pub->issuer_raw.p, pub->issuer_raw.len, 0 );
    if( ret != 0 ) {
        mbedtls_printf( "ERROR: Failed to add issuer data to Signer info of PKCS7\n" );

        return ( ret );
    }
    /* add info */
    bytes_written_in_step = *size - ( *ptr - *start ) - curr_len;
    ret = pkcs7_write_data( start, size, ptr,
                            WRITE_TAG, &tag,
                            bytes_written_in_step, 0 );
    if( ret == 0 ) {
        /* add signed info version, see https:// tools.ietf.org/html/rfc2315
         * section 9.2 */
        ret = pkcs7_write_data( start, size, ptr, WRITE_VERSION,
                                &signed_info_version, sizeof( signed_info_version ), 0 );
    }
    if( ret )
        mbedtls_printf( "ERROR: Failed to add owner flag to Signer Info of PKCS7\n" );

    return ( ret );
}

static int pkcs7_set_each_signer_data( unsigned char **start, size_t *size,
                                       unsigned char **ptr,
                                       mbedtls_pkcs7_info *pkcs7_info )
{
    int ret;
    size_t bytes_written_in_step, curr_len;
    unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;
    mbedtls_x509_crt *x509 = NULL;
    /* if no signers than quit */
    if( pkcs7_info->key_pairs < 1 ) {
        ret = MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO;
        mbedtls_printf( "ERROR: No keys given to sign with\n" );
    }

    for( int i = 0; i < pkcs7_info->key_pairs; i++ ) {
        x509 = mbedtls_calloc( 1, sizeof( *x509 ) );
        if( x509 == NULL ) {
            mbedtls_printf( "ERROR: failed to allocate memory\n" );
            ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
            goto out;
        }
        mbedtls_x509_crt_init( x509 );
        /* puts cert data into x509_Crt struct and returns number of failed parses */
        ret = mbedtls_x509_crt_parse( x509, pkcs7_info->crts[i],
                                      pkcs7_info->crt_sizes[i] );
        if( ret != 0 ) {
            mbedtls_printf(
                "ERROR: While extracting signer info, parsing x509 failed with "
                "MBEDTLS exit code: %d \n",
                ret );
            goto out;
        }
        curr_len = *size - ( *ptr - *start );
        ret = pkcs7_set_signer_cert_data( start, size, ptr, pkcs7_info, x509,
                                          pkcs7_info->keys[i], pkcs7_info->key_sizes[i] );
        if( ret != 0 )
            goto out;
        bytes_written_in_step = *size - ( *ptr - *start ) - curr_len;
        ret = pkcs7_write_data( start, size, ptr,
                                WRITE_TAG, &tag,
                                bytes_written_in_step, 0 );
        if( ret != 0 ) {
            mbedtls_printf(
                "ERROR: Failed to add header seqeuence header for signer data\n");
            goto out;
        }

        mbedtls_x509_crt_free( x509 );
        mbedtls_free( x509 );
        x509 = NULL;
    }

out:
    mbedtls_x509_crt_free( x509 );
    mbedtls_free( x509 );

    return ( ret );
}

static int pkcs7_set_signers_data( unsigned char **start, size_t *size,
                                   unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info )
{
    int ret;
    size_t bytes_written_in_step, curr_len;
    unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET;

    curr_len = *size - ( *ptr - *start );

    ret = pkcs7_set_each_signer_data( start, size, ptr, pkcs7_info );
    if( ret != 0 )
        return ( ret );

    bytes_written_in_step = *size - ( *ptr - *start ) - curr_len;
    ret = pkcs7_write_data( start, size, ptr,
                            WRITE_TAG, &tag,
                            bytes_written_in_step, 0 );

    if( ret )
        mbedtls_printf( "ERROR: Failed to add signers data header info to PKCS7\n" );

    return ( ret );
}

static int pkcs7_set_signer_certs( unsigned char **start, size_t *size,
                                   unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info )
{
    int ret;
    size_t bytes_written_in_step, curr_len;
    unsigned char tag =  MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED;

    ret = pkcs7_set_signers_data( start, size, ptr, pkcs7_info );

    if( ret != 0 )
        return ( ret );

    curr_len = *size - ( *ptr - *start );
    for( int i = 0; i < pkcs7_info->key_pairs; i++ ) {
        ret = pkcs7_write_data( start, size, ptr, WRITE_RAW_BUFFER,
                                pkcs7_info->crts[i], pkcs7_info->crt_sizes[i], 0 );
        if( ret )
            break;
    }
    if( ret == 0 ) {
        bytes_written_in_step = *size - ( *ptr - *start ) - curr_len;
        ret = pkcs7_write_data( start, size, ptr, WRITE_TAG,
                                &tag, bytes_written_in_step, 0 );
    }
    if( ret )
        mbedtls_printf( "ERROR: Failed to add raw signing certificate to PKCS7\n");


    return ( ret );
}

static int pkcs7_set_signed_data_oid( unsigned char **start, size_t *size,
                                      unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info )
{
    int ret;

    ret = pkcs7_set_signer_certs( start, size, ptr, pkcs7_info );
    if( ret != 0 )
        return ( ret );

    ret = pkcs7_write_data( start, size, ptr, WRITE_OID_NO_NULL_TAG,
                            (void *) MBEDTLS_OID_PKCS7_DATA,
                            strlen(MBEDTLS_OID_PKCS7_DATA), 0 );
    if( ret )
        mbedtls_printf(
            "ERROR: Failed to add OID, PKCS7_DATA, for Signed Data of PKCS7\n");

    return ( ret );
}

static int pkcs7_set_algo_id( unsigned char **start, size_t *size,
                              unsigned char **ptr,
                              mbedtls_pkcs7_info *pkcs7_info )
{
    int ret;
    unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET;
    size_t bytes_written_in_step, curr_len;

    ret = pkcs7_set_signed_data_oid( start, size, ptr, pkcs7_info );

    if( ret != 0 )
        return ( ret );

    curr_len = *size - ( *ptr - *start );

    ret = pkcs7_write_data( start, size, ptr, WRITE_OID,
                            (void *) pkcs7_info->hash_funct_oid,
                            strlen( pkcs7_info->hash_funct_oid ), 0 );
    if( ret == 0 ) {
        /* bytes in step = new currently written bytes - old currently written */
        bytes_written_in_step = *size - ( *ptr - *start ) - curr_len;
        ret = pkcs7_write_data( start, size, ptr, WRITE_TAG, &tag,
                                bytes_written_in_step, 0 );
    }
    if( ret )
        mbedtls_printf( "ERROR: Failed to add algorithm ID to PKCS7\n" );

    return ( ret );
}

static int pkcs7_set_version( unsigned char **start, size_t *size,
                              unsigned char **ptr,
                              mbedtls_pkcs7_info *pkcs7_info )
{
    int ret;
    /* for now only version 1 */
    int version = 1;

    ret = pkcs7_set_algo_id( start, size, ptr, pkcs7_info );
    if( ret != 0 )
        return ( ret );

    ret = pkcs7_write_data( start, size, ptr, WRITE_VERSION, &version,
                            sizeof( version ), 0 );
    if( ret )
        mbedtls_printf( "ERROR: Failed to add version to PKCS7\n" );

    return ( ret );
}

static int pkcs7_set_signed_data( unsigned char **start, size_t *size,
                                  unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info )
{
    int ret;
    size_t curr_len;
    unsigned char tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE;

    ret = pkcs7_set_version( start, size, ptr, pkcs7_info );
    if( ret != 0 )
        return ( ret );

    curr_len = *size - ( *ptr - *start );
    ret = pkcs7_write_data( start, size, ptr,
                            WRITE_TAG, &tag,
                            curr_len, 0 );
    if( ret )
        mbedtls_printf(
            "ERROR: Failed to add signed data's SEQUENCE header to PKCS7\n");

    return ( ret );
}

static int pkcs7_set_pkcs7_oid( unsigned char **start, size_t *size,
                                unsigned char **ptr,
                                mbedtls_pkcs7_info *pkcs7_info )
{
    int ret;
    size_t curr_len;
    unsigned char tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED;

    ret = pkcs7_set_signed_data( start, size, ptr, pkcs7_info );

    if( ret != 0 )
        return ( ret );

    curr_len = *size - ( *ptr - *start );
    ret = pkcs7_write_data( start, size, ptr,
                            WRITE_TAG,
                            &tag, curr_len, 0 );
    if( ret == 0 ) {
        curr_len = *size - ( *ptr - *start );
        ret = pkcs7_write_data(
                  start, size, ptr, WRITE_OID,
                  (void *) MBEDTLS_OID_PKCS7_SIGNED_DATA,
                  strlen( MBEDTLS_OID_PKCS7_SIGNED_DATA ), curr_len );
    }
    if( ret )
        mbedtls_printf(
            "ERROR: Failed to add PKCS7 OID/SEQUENCE header to PKCS7\n" );

    return ( ret );
}

static int pkcs7_start_generation( unsigned char **start, size_t *size,
                                   unsigned char **ptr, mbedtls_pkcs7_info *pkcs7_info )
{
    /* This will call every other function before anything is actually written */
    return ( pkcs7_set_pkcs7_oid( start, size, ptr, pkcs7_info ) );
}

int mbedtls_pkcs7_create( unsigned char **pkcs7, size_t *pkcs7_size,
                          const unsigned char *data, size_t data_size, const unsigned char **crts,
                          const unsigned char **keys, size_t *crt_sizes, size_t *key_sizes, int key_pairs,
                          mbedtls_md_type_t hash_funct )
{
    unsigned char *pkcs7_buff = NULL, *hash_funct_oid;
    unsigned char *ptr;
    size_t pkcs7_buff_size, white_space, oid_len;
    int ret;
    mbedtls_pkcs7_info info;
    /* ensure there are keys to sign with */
    if( key_pairs <= 0 ) {
        mbedtls_printf(
            "ERROR: missing private key / certificate\n" );
        ret = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
        goto out;
    }
    /* get hash_funct OID, no md is currently unsuported */
    if( hash_funct <= MBEDTLS_MD_NONE || hash_funct > MBEDTLS_MD_RIPEMD160 ) {
        mbedtls_printf( "ERROR: Invalid hash function %u, see mbedtls_md_type_t\n",
                        hash_funct );
        ret = MBEDTLS_ERR_PKCS7_INVALID_ALG;
        goto out;
    }
    ret = mbedtls_oid_get_oid_by_md( hash_funct, (const char **) &hash_funct_oid,
                                     &oid_len );
    if( ret ) {
        mbedtls_printf(
            "Message Digest value %u could not be converted to an OID\n", hash_funct );
        ret = MBEDTLS_ERR_PKCS7_INVALID_ALG;
        goto out;
    }

    info.crts = (unsigned char **) crts;
    info.crt_sizes = crt_sizes;
    info.keys = (unsigned char **) keys;
    info.key_sizes = key_sizes;
    info.key_pairs = key_pairs;
    info.data = data;
    info.data_size = data_size;
    info.hash_funct = hash_funct;
    info.hash_funct_oid = (char *) hash_funct_oid;


    printf( "Generating Pkcs7 with %d pair(s) of signers...\n", key_pairs );

    /* buffer size for pkcs7 will grow exponentially 2^n depending on space needed */
    pkcs7_buff_size = 2;
    pkcs7_buff = mbedtls_calloc( 1, pkcs7_buff_size );
    if( pkcs7_buff == NULL ) {
        mbedtls_printf( "ERROR: failed to allocate memory\n" );
        ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
        goto out;
    }
    /* set ptr to the end of the buffer, mbedtls functions write backwards */
    ptr = pkcs7_buff + pkcs7_buff_size;

    /* this will call all other PKCS7 generation functions */
    ret = pkcs7_start_generation( (unsigned char **) &pkcs7_buff, &pkcs7_buff_size,
                                  &ptr, &info );
    if( ret ) {
        mbedtls_printf( "Failed to generate PKCS7\n" );
        goto out;
    }
    /* trim pkcs7 */
    white_space = get_leading_whitespace( pkcs7_buff, pkcs7_buff_size );
    pkcs7_buff_size -= white_space;

    /* copy into new buffer with only necessary allocated memory */
    *pkcs7_size = pkcs7_buff_size;
    *pkcs7 = mbedtls_calloc( 1, *pkcs7_size );
    if( *pkcs7 == NULL ) {
        ret = MBEDTLS_ERR_PKCS7_ALLOC_FAILED;
        goto out;
    }
    memcpy( *pkcs7, pkcs7_buff + white_space, *pkcs7_size );
    mbedtls_printf( "PKCS7 generation successful...\n" );

out:
    mbedtls_free( pkcs7_buff );
    return ( ret );
}
#endif
