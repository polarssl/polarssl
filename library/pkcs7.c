/* Copyright 2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif
#if defined(MBEDTLS_PKCS7_C)

#include "mbedtls/x509.h"
#include "mbedtls/asn1.h"
#include "mbedtls/pkcs7.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_crl.h"
#include "mbedtls/oid.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#if defined(MBEDTLS_FS_IO)
#include <sys/types.h>
#include <sys/stat.h>
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#include "mbedtls/platform_util.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_free      free
#define mbedtls_calloc    calloc
#define mbedtls_printf    printf
#define mbedtls_snprintf  snprintf
#endif

#if defined(MBEDTLS_HAVE_TIME)
#include "mbedtls/platform_time.h"
#endif
#if defined(MBEDTLS_HAVE_TIME_DATE)
#include <time.h>
#endif

#if defined(MBEDTLS_FS_IO)
/*
 * Load all data from a file into a given buffer.
 *
 * The file is expected to contain DER encoded data.
 * A terminating null byte is always appended.
 */
int mbedtls_pkcs7_load_file( const char *path, unsigned char **buf, size_t *n )
{
    FILE *file;

    if ( !path || !buf || !n )
        return( MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA );

    if( ( file = fopen( path, "rb" ) ) == NULL )
        return( MBEDTLS_ERR_PKCS7_FILE_IO_ERROR );

    fseek( file, 0, SEEK_END );
    *n = (size_t) ftell( file );
    fseek( file, 0, SEEK_SET );

    *buf = mbedtls_calloc( 1, *n + 1 );
    if( *buf == NULL )
        return( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );

    if( fread( *buf, 1, *n, file ) != *n )
    {
        fclose( file );

        mbedtls_platform_zeroize( *buf, *n + 1 );
        mbedtls_free( *buf );

        return( MBEDTLS_ERR_PKCS7_FILE_IO_ERROR );
    }

    fclose( file );

    (*buf)[*n] = '\0';

    return( 0 );
}
#endif

/**
 * Initializes the pkcs7 structure.
 */
void mbedtls_pkcs7_init( mbedtls_pkcs7 *pkcs7 )
{
    memset( pkcs7, 0, sizeof( mbedtls_pkcs7 ) );
}

static int pkcs7_get_next_content_len( unsigned char **p, unsigned char *end,
                                       size_t *len )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_tag( p, end, len, MBEDTLS_ASN1_CONSTRUCTED
                    | MBEDTLS_ASN1_CONTEXT_SPECIFIC ) ) != 0 )
    {
        return( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );
    }

    return( 0 );
}

/**
 * version Version
 * Version ::= INTEGER
 **/
static int pkcs7_get_version( unsigned char **p, unsigned char *end, int *ver )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_int( p, end, ver ) ) != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_VERSION + ret );

    /* If version != 1, return invalid version */
    if( *ver != MBEDTLS_PKCS7_SUPPORTED_VERSION )
        return( MBEDTLS_ERR_PKCS7_INVALID_VERSION );

    return( 0 );
}

/**
 * ContentInfo ::= SEQUENCE {
 *      contentType ContentType,
 *      content
 *              [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 **/
static int pkcs7_get_content_info_type( unsigned char **p, unsigned char *end,
                                        mbedtls_pkcs7_buf *pkcs7 )
{
    size_t len = 0;
    int ret;
    unsigned char *start = *p;

    ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                            | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO + ret );

    ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_OID );
    if( ret != 0 ) {
        *p = start;
        return( MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO + ret );
    }

    pkcs7->tag = MBEDTLS_ASN1_OID;
    pkcs7->len = len;
    pkcs7->p = *p;

    return( ret );
}

/**
 * DigestAlgorithmIdentifier ::= AlgorithmIdentifier
 *
 * This is from x509.h
 **/
static int pkcs7_get_digest_algorithm( unsigned char **p, unsigned char *end,
                                       mbedtls_x509_buf *alg )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_alg_null( p, end, alg ) ) != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_ALG );

    return( 0 );
}

/**
 * DigestAlgorithmIdentifiers :: SET of DigestAlgorithmIdentifier
 **/
static int pkcs7_get_digest_algorithm_set( unsigned char **p,
                                           unsigned char *end,
                                           mbedtls_x509_buf *alg )
{
    size_t len = 0;
    int ret;

    ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                            | MBEDTLS_ASN1_SET );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_ALG + ret );

    end = *p + len;

    /** For now, it assumes there is only one digest algorithm specified **/
    ret = mbedtls_asn1_get_alg_null( p, end, alg );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_ALG + ret );

    if ( *p != end )
        return ( MBEDTLS_ERR_PKCS7_INVALID_FORMAT );

    return( 0 );
}

/**
 * certificates :: SET OF ExtendedCertificateOrCertificate,
 * ExtendedCertificateOrCertificate ::= CHOICE {
 *      certificate Certificate -- x509,
 *      extendedCertificate[0] IMPLICIT ExtendedCertificate }
 * Return number of certificates added to the signed data,
 * 0 or higher is valid.
 * Return negative error code for failure.
 **/
static int pkcs7_get_certificates( unsigned char **p, unsigned char *end,
                                   mbedtls_x509_crt *certs )
{
    int ret;
    size_t len1 = 0;
    size_t len2 = 0;
    unsigned char *end_set, *end_cert;
    unsigned char *start = *p;

    if( ( ret = mbedtls_asn1_get_tag( p, end, &len1, MBEDTLS_ASN1_CONSTRUCTED
                    | MBEDTLS_ASN1_CONTEXT_SPECIFIC ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );
    }
    start = *p;
    end_set = *p + len1;

    ret = mbedtls_asn1_get_tag( p, end_set, &len2, MBEDTLS_ASN1_CONSTRUCTED
            | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_CERT + ret );

    end_cert = *p + len2;

    /*
     * This is to verify that there is only one signer certificate. It seems it is
     * not easy to differentiate between the chain vs different signer's certificate.
     * So, we support only the root certificate and the single signer.
     * The behaviour would be improved with addition of multiple signer support.
     */
    if (end_cert != end_set)
        return ( MBEDTLS_ERR_PKCS7_INVALID_CERT );

    *p = start;
    if( ( ret = mbedtls_x509_crt_parse( certs, *p, len1 ) ) < 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_CERT );

    *p = *p + len1;

    /* Since in this version we strictly support single certificate, and reaching
     * here implies we have parsed successfully, we return 1. */

    return( 1 );
}

/**
 * EncryptedDigest ::= OCTET STRING
 **/
static int pkcs7_get_signature( unsigned char **p, unsigned char *end,
                                mbedtls_pkcs7_buf *signature )
{
    int ret;
    size_t len = 0;

    ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_OCTET_STRING );
    if( ret != 0 )
        return( ret );

    signature->tag = MBEDTLS_ASN1_OCTET_STRING;
    signature->len = len;
    signature->p = *p;

    *p = *p + len;

    return( 0 );
}

/**
 * SignerInfos ::= SET of SignerInfo
 * SignerInfo ::= SEQUENCE {
 *      version Version;
 *      issuerAndSerialNumber   IssuerAndSerialNumber,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      authenticatedAttributes
 *              [0] IMPLICIT Attributes OPTIONAL,
 *      digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier,
 *      encryptedDigest EncryptedDigest,
 *      unauthenticatedAttributes
 *              [1] IMPLICIT Attributes OPTIONAL,
 * Return number of signers added to the signed data,
 * 0 or higher is valid.
 * Return negative error code for failure.
 **/
static int pkcs7_get_signers_info_set( unsigned char **p, unsigned char *end,
                                       mbedtls_pkcs7_signer_info *signers_set )
{
    unsigned char *end_set, *end_set_signer;
    int ret;
    size_t len = 0;

    ret = mbedtls_asn1_get_tag( p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                | MBEDTLS_ASN1_SET );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO + ret );

    end_set = *p + len;

    ret = mbedtls_asn1_get_tag( p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
                                | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO + ret );

    end_set_signer = *p + len;
    if (end_set_signer != end_set)
        return ( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO );

    end_set = end_set_signer;

    ret = mbedtls_asn1_get_int( p, end_set, &signers_set->version );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO );

    ret = mbedtls_asn1_get_tag( p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
                                | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO + ret );

    /* Parsing IssuerAndSerialNumber */
    signers_set->issuer_raw.p = *p;

    ret = mbedtls_asn1_get_tag( p, end_set, &len, MBEDTLS_ASN1_CONSTRUCTED
                                | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO + ret );

    ret  = mbedtls_x509_get_name( p, *p + len, &signers_set->issuer );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO );

    signers_set->issuer_raw.len =  *p - signers_set->issuer_raw.p;

    ret = mbedtls_x509_get_serial( p, end_set, &signers_set->serial );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO );

    ret = pkcs7_get_digest_algorithm( p, end_set, &signers_set->alg_identifier );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO );

    ret = pkcs7_get_digest_algorithm( p, end_set, &signers_set->sig_alg_identifier );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO );

    ret = pkcs7_get_signature( p, end_set, &signers_set->sig );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO );

    signers_set->next = NULL;

    if (*p != end_set)
        return ( MBEDTLS_ERR_PKCS7_INVALID_SIGNER_INFO );

    /* Since in this version we strictly support single signer, and reaching
     * here implies we have parsed successfully, we return 1. */

    return( 1 );
}

/**
 * SignedData ::= SEQUENCE {
 *      version Version,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      contentInfo ContentInfo,
 *      certificates
 *              [0] IMPLICIT ExtendedCertificatesAndCertificates
 *                  OPTIONAL,
 *      crls
 *              [0] IMPLICIT CertificateRevocationLists OPTIONAL,
 *      signerInfos SignerInfos }
 */
static int pkcs7_get_signed_data( unsigned char *buf, size_t buflen,
                                  mbedtls_pkcs7_signed_data *signed_data )
{
    unsigned char *p = buf;
    unsigned char *end = buf + buflen;
    unsigned char *end_set;
    size_t len = 0;
    int ret;
    mbedtls_md_type_t md_alg;

    ret = mbedtls_asn1_get_tag( &p, end, &len, MBEDTLS_ASN1_CONSTRUCTED
                                | MBEDTLS_ASN1_SEQUENCE );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_FORMAT + ret );

    end_set = p + len;

    /* Get version of signed data */
    ret = pkcs7_get_version( &p, end_set, &signed_data->version );
    if( ret != 0 )
        return( ret );

    /* Get digest algorithm */
    ret = pkcs7_get_digest_algorithm_set( &p, end_set,
            &signed_data->digest_alg_identifiers );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_oid_get_md_alg( &signed_data->digest_alg_identifiers, &md_alg );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_INVALID_ALG );

    /* Do not expect any content */
    ret = pkcs7_get_content_info_type( &p, end_set, &signed_data->content.oid );
    if( ret != 0 )
        return( ret );

    if( MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_DATA, &signed_data->content.oid ) )
    {
        return( MBEDTLS_ERR_PKCS7_INVALID_CONTENT_INFO ) ;
    }

    p = p + signed_data->content.oid.len;

    /* Look for certificates, there may or may not be any */
    mbedtls_x509_crt_init( &signed_data->certs );
    ret = pkcs7_get_certificates( &p, end_set, &signed_data->certs );
    if( ret < 0 )
        return( ret ) ;

    signed_data->no_of_certs = ret;

    /*
     * Currently CRLs are not supported. If CRL exist, the parsing will fail
     * at next step of getting signers info and return error as invalid
     * signer info.
     */

    signed_data->no_of_crls = 0;

    /* Get signers info */
    ret = pkcs7_get_signers_info_set( &p, end_set, &signed_data->signers );
    if( ret < 0 )
        return( ret );

    signed_data->no_of_signers = ret;

    /* Support single signer */
    if ( p != end )
        ret = MBEDTLS_ERR_PKCS7_INVALID_FORMAT;

    ret = 0;
    return( ret );
}

int mbedtls_pkcs7_parse_der( const unsigned char *buf, const int buflen,
                             mbedtls_pkcs7 *pkcs7 )
{
    unsigned char *start;
    unsigned char *end;
    size_t len = 0;
    int ret;
    int isoidset = 0;

    if( !pkcs7 )
        return( MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA );

    /* make an internal copy of the buffer for parsing */
    pkcs7->raw.p = start = mbedtls_calloc( 1, buflen );
    if( pkcs7->raw.p == NULL )
    {
        return( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );
    }
    memcpy( start, buf, buflen );
    pkcs7->raw.len = buflen;
    end = start + buflen;

    ret = pkcs7_get_content_info_type( &start, end, &pkcs7->content_type_oid );
    if( ret != 0 )
    {
        len = buflen;
        goto try_data;
    }

    if( ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_DATA, &pkcs7->content_type_oid )
     || ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_ENCRYPTED_DATA, &pkcs7->content_type_oid )
     || ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_ENVELOPED_DATA, &pkcs7->content_type_oid )
     || ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_SIGNED_AND_ENVELOPED_DATA, &pkcs7->content_type_oid )
     || ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_DIGESTED_DATA, &pkcs7->content_type_oid )
     || ! MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_ENCRYPTED_DATA, &pkcs7->content_type_oid ) )
    {
        ret =  MBEDTLS_ERR_PKCS7_FEATURE_UNAVAILABLE;
        goto out;
    }

    if( MBEDTLS_OID_CMP( MBEDTLS_OID_PKCS7_SIGNED_DATA, &pkcs7->content_type_oid ) )
    {
        ret = MBEDTLS_ERR_PKCS7_BAD_INPUT_DATA;
        goto out;
    }

    isoidset = 1;
    start = start + pkcs7->content_type_oid.len;

    ret = pkcs7_get_next_content_len( &start, end, &len );
    if( ret != 0 )
        goto out;

try_data:
    ret = pkcs7_get_signed_data( start, len, &pkcs7->signed_data );
    if ( ret != 0 )
        goto out;

    if ( !isoidset )
    {
        pkcs7->content_type_oid.tag = MBEDTLS_ASN1_OID;
        pkcs7->content_type_oid.len = MBEDTLS_OID_SIZE(MBEDTLS_OID_PKCS7_SIGNED_DATA);
        pkcs7->content_type_oid.p = (unsigned char *)MBEDTLS_OID_PKCS7_SIGNED_DATA;
    }

    ret = MBEDTLS_PKCS7_SIGNED_DATA;

out:
    if ( ret < 0 )
        mbedtls_pkcs7_free( pkcs7 );

    return( ret );
}

int mbedtls_pkcs7_signed_data_verify( mbedtls_pkcs7 *pkcs7,
                                      mbedtls_x509_crt *cert,
                                      const unsigned char *data,
                                      size_t datalen )
{

    int ret;
    unsigned char *hash;
    mbedtls_pk_context pk_cxt = cert->pk;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_type_t md_alg;

    ret = mbedtls_oid_get_md_alg( &pkcs7->signed_data.digest_alg_identifiers, &md_alg );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_VERIFY_FAIL );

    md_info = mbedtls_md_info_from_type( md_alg );
    hash = mbedtls_calloc( mbedtls_md_get_size( md_info ), 1 );

    if( hash == NULL ) {
        return( MBEDTLS_ERR_PKCS7_ALLOC_FAILED );
    }

    mbedtls_md( md_info, data, datalen, hash );

   fprintf(stderr, "Testing verification with data (%lu bytes):\n", datalen);
    for( size_t i = 0; i < datalen ; i++)
        fprintf(stderr, "%02x ", data[i] );
    fprintf(stderr, "\n generated hash (%lu bytes ):\n",(size_t) mbedtls_md_get_size(md_info) );
      for( size_t i = 0; i < (size_t) mbedtls_md_get_size(md_info); i++)
        fprintf(stderr, "%02x ", hash[i] );
    fprintf(  stderr, "\n");
    
    ret = mbedtls_pk_verify( &pk_cxt, md_alg, hash, 0,
                                      pkcs7->signed_data.signers.sig.p,
                                      pkcs7->signed_data.signers.sig.len );

    mbedtls_free( hash );

    return( ret );
}

int mbedtls_pkcs7_signed_hash_verify( mbedtls_pkcs7 *pkcs7,
                                      mbedtls_x509_crt *cert,
                                      const unsigned char *hash, int hashlen)
{
    int ret;
    mbedtls_md_type_t md_alg;
    mbedtls_pk_context pk_cxt;

    ret = mbedtls_oid_get_md_alg( &pkcs7->signed_data.digest_alg_identifiers, &md_alg );
    if( ret != 0 )
        return( MBEDTLS_ERR_PKCS7_VERIFY_FAIL );

    pk_cxt = cert->pk;
    ret = mbedtls_pk_verify( &pk_cxt, md_alg, hash, hashlen,
                             pkcs7->signed_data.signers.sig.p,
                             pkcs7->signed_data.signers.sig.len );

    return ( ret );
}

/*
 * Unallocate all pkcs7 data
 */
void mbedtls_pkcs7_free( mbedtls_pkcs7 *pkcs7 )
{
    mbedtls_x509_name *name_cur;
    mbedtls_x509_name *name_prv;

    if( pkcs7 == NULL )
        return;

    mbedtls_x509_crt_free( &pkcs7->signed_data.certs );
    mbedtls_x509_crl_free( &pkcs7->signed_data.crl );

    name_cur = pkcs7->signed_data.signers.issuer.next;
    while( name_cur != NULL )
    {
        name_prv = name_cur;
        name_cur = name_cur->next;
        mbedtls_platform_zeroize( name_prv, sizeof( mbedtls_x509_name ) );
        mbedtls_free( name_prv );
    }

    mbedtls_platform_zeroize( pkcs7->raw.p, pkcs7->raw.len );
    mbedtls_free( pkcs7->raw.p );

    mbedtls_platform_zeroize( pkcs7, sizeof( mbedtls_pkcs7 ) );
}

#endif
