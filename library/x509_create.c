/*
 *  X.509 base functions for creating certificates / CSRs
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
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

#if defined(MBEDTLS_X509_CREATE_C)

#include "mbedtls/x509.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/oid.h"

#include <string.h>

/* Structure linking OIDs for X.509 DN AttributeTypes to their
 * string representations and default string encodings used by Mbed TLS. */
typedef struct {
   const char *name; /* String representation of AttributeType, e.g.
                      * "CN" or "emailAddress". */
   size_t name_len;  /* Length of 'name', without trailing 0 byte. */
   const char *oid;  /* String representation of OID of AttributeType,
                      * as per RFC 5280, Appendix A.1. */
   int default_tag;  /* The default character encoding used for the
                      * given attribute type, e.g.
                      * MBEDTLS_ASN1_UTF8_STRING for UTF-8. */
} x509_attr_descriptor_t;

#define ADD_STRLEN( s )     s, sizeof( s ) - 1

/* X.509 DN attributes from RFC 5280, Appendix A.1. */
static const x509_attr_descriptor_t x509_attrs[] =
{
    { ADD_STRLEN( "CN" ),
      MBEDTLS_OID_AT_CN, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "commonName" ),
      MBEDTLS_OID_AT_CN, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "C" ),
      MBEDTLS_OID_AT_COUNTRY, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "countryName" ),
      MBEDTLS_OID_AT_COUNTRY, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "O" ),
      MBEDTLS_OID_AT_ORGANIZATION, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "organizationName" ),
      MBEDTLS_OID_AT_ORGANIZATION, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "L" ),
      MBEDTLS_OID_AT_LOCALITY, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "locality" ),
      MBEDTLS_OID_AT_LOCALITY, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "R" ),
      MBEDTLS_OID_PKCS9_EMAIL, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN( "OU" ),
      MBEDTLS_OID_AT_ORG_UNIT, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "organizationalUnitName" ),
      MBEDTLS_OID_AT_ORG_UNIT, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "ST" ),
      MBEDTLS_OID_AT_STATE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "stateOrProvinceName" ),
      MBEDTLS_OID_AT_STATE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "emailAddress" ),
      MBEDTLS_OID_PKCS9_EMAIL, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN( "serialNumber" ),
      MBEDTLS_OID_AT_SERIAL_NUMBER, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "postalAddress" ),
      MBEDTLS_OID_AT_POSTAL_ADDRESS, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "postalCode" ),
      MBEDTLS_OID_AT_POSTAL_CODE, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "dnQualifier" ),
      MBEDTLS_OID_AT_DN_QUALIFIER, MBEDTLS_ASN1_PRINTABLE_STRING },
    { ADD_STRLEN( "title" ),
      MBEDTLS_OID_AT_TITLE, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "surName" ),
      MBEDTLS_OID_AT_SUR_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "SN" ),
      MBEDTLS_OID_AT_SUR_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "givenName" ),
      MBEDTLS_OID_AT_GIVEN_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "GN" ),
      MBEDTLS_OID_AT_GIVEN_NAME, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "initials" ),
      MBEDTLS_OID_AT_INITIALS, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "pseudonym" ),
      MBEDTLS_OID_AT_PSEUDONYM, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "generationQualifier" ),
      MBEDTLS_OID_AT_GENERATION_QUALIFIER, MBEDTLS_ASN1_UTF8_STRING },
    { ADD_STRLEN( "domainComponent" ),
      MBEDTLS_OID_DOMAIN_COMPONENT, MBEDTLS_ASN1_IA5_STRING },
    { ADD_STRLEN( "DC" ),
      MBEDTLS_OID_DOMAIN_COMPONENT,   MBEDTLS_ASN1_IA5_STRING },
    { NULL, 0, NULL, MBEDTLS_ASN1_NULL }
};

static const x509_attr_descriptor_t *x509_attr_descr_from_name( const char *name, size_t name_len )
{
    const x509_attr_descriptor_t *cur;

    for( cur = x509_attrs; cur->name != NULL; cur++ )
        if( cur->name_len == name_len &&
            strncmp( cur->name, name, name_len ) == 0 )
            break;

    if ( cur->name == NULL )
        return( NULL );

    return( cur );
}

static int x509_dn_check_special_chars( const char **cur, const char *end )
{
    int ret = 0;

    /* Check for valid escaped characters */
    if( *cur == end || *( *cur ) != ',' )
    {
        ret = MBEDTLS_ERR_X509_INVALID_NAME;
    }

    return( ret );
}

static int x509_dn_parse_tag( const char **cur, const char *end,
                              const x509_attr_descriptor_t **attr_descr )
{
    int ret = 0;
    const char *start = *cur;

    /*
     * As defined by RFC 1779, the DN is constructed from
     * <string> | <key> <optional-space> "=" <optional-space> <string>
     * where optional space is
     * ( <CR> ) *( " " )
     *
     * When parsing the tag:
     * 1. Skip whitespaces.
     * 2. Read the characters, to evaluate as a valid tag.
     * 3. Skip whitespaces until reaching "=" character.
     */

    /*
     * Skip whitespaces
     */
    while( *cur < end && *( *cur ) == ' ' )
    {
        ( *cur )++;
        start++;
    }

    /*
     * Read the next characters to evaluate as a valid tag.
     */
    while( *cur < end && *( *cur ) != '=' && *( *cur ) != ' ' )
    {
        /*
         * A valid tag can only be followed by a '=' or whitespace.
         */
        if( *( *cur ) == ',' )
        {
            ret = MBEDTLS_ERR_X509_INVALID_NAME;
            goto exit;
        }
        ( *cur )++;
    }

    /*
     * cur character is either '=' or ' '
     * or we reached the end.
     */

    if( *cur == end )
    {
        ret = MBEDTLS_ERR_X509_INVALID_NAME;
        goto exit;
    }
    *attr_descr = x509_attr_descr_from_name( start, *cur - start );
    if( *attr_descr == NULL )
    {
        ret = MBEDTLS_ERR_X509_UNKNOWN_OID;
        goto exit;
    }

    /*
     * Skip all optional whitespaces
     */
    while( *cur < end && *( *cur ) == ' ' )
    {
        ( *cur )++;
    }

    /*
     * The only valid character now is '='
     */
    if( *cur == end || *( *cur ) != '=' )
    {
        ret = MBEDTLS_ERR_X509_INVALID_NAME;
    }

    /*
     * Increment the current position to after the '=' character.
     */
    ( *cur )++;

exit:
    return( ret );
}

static int x509_dn_parse_value( const char **cur, const char *end,
                                const x509_attr_descriptor_t *attr_descr,
                                mbedtls_asn1_named_data **head )
{
    int ret = 0;
    /*
     * `cur` points to the current character in the string being parsed.
     * `d` acts as a write pointer into the temporary 'data' buffer which holds
     * the unescaped and unquoted DN values found in 'name'.
     */
    int in_quot = 0;
    size_t value_len = 0;
    char data[MBEDTLS_X509_MAX_DN_NAME_SIZE];
    char *d = data;

    /*
     * As defined by RFC 1779, the DN is constructed from
     * <string> | <key> <optional-space> "=" <optional-space> <string>
     * where optional space is
     * ( <CR> ) *( " " )
     *
     * When parsing the value:
     * 1. Skip whitespaces.
     * 2. Check if it is a quoted string.
     * 3. Read the characters, to evaluate as a valid value.
     * 4. Skip whitespaces until reaching separator character (',').
     */

    /*
     * Skip whitespaces
     */
    while( *cur < end && *( *cur ) == ' ' )
    {
        ( *cur )++;
    }

    if( *cur == end || *( *cur ) == ',' )
    {
        ret = MBEDTLS_ERR_X509_INVALID_NAME;
        goto exit;
    }
    /*
     * Check if it is a quoted string
     */
    else if( *( *cur ) == '\"' )
    {
        in_quot = 1;
        ( *cur )++;
    }

    while( *cur < end )
    {
        /*
         * Check whether reached end of value to evaluate,
         * whether it is a closing quotation, or a separator character
         */
        if( in_quot == 1 && *( *cur ) == '\"' )
        {
            /*
             * Increase the current position to after the closing quotation
             */
            ( *cur )++;
            /*
             * Mark that quotation has ended.
             */
            in_quot = 0;
            break;
        }
        else if( in_quot == 0 && *( *cur ) == ',')
        {
            break;
        }

        if( *cur != end && *( *cur ) == '\\' )
        {
            ( *cur )++;
            ret = x509_dn_check_special_chars( cur, end );
            if( ret != 0 )
            {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                goto exit;
            }
        }

        /*
         * Fill the current data pointer with the unescaped character.
         */
        if( d - data == MBEDTLS_X509_MAX_DN_NAME_SIZE - 1 && *( *cur ) != ' ' )
        {
            /* The data buffer is not large enough to hold the value */
            ret = MBEDTLS_ERR_X509_INVALID_NAME;
            goto exit;
        }
        else if( d - data < MBEDTLS_X509_MAX_DN_NAME_SIZE - 1 )
        {
            /*
             * Assume that the current character is part of the value tag, but
             * this might actually not be the case if it is just trailing whitespace
             */
            *( d++ ) = *( *cur );
        }
        /*
         * A whitespace can be part of the string,
         * but it can also be a trailing whitespace, so don't set the
         * value length until the character is  not a whitespace
         */
         if ( *( *cur ) != ' ' )
             value_len = d - data;

        ( *cur )++;
    }

    if( value_len == 0 )
    {
        ret = MBEDTLS_ERR_X509_INVALID_NAME;
        goto exit;
    }

    /*
     * Check if quotation has ended.
     */
    if( in_quot == 1 )
    {
        ret = MBEDTLS_ERR_X509_INVALID_NAME;
        goto exit;
    }

    /*
     * We have reached here in the following conditions:
     * 1. The end of the input buffer was reached (*cur == end).
     * 2. A quoted string  reached a closing string quotation.
     *    (in_quot == 1 && *( *cur ) == '"').
     * 3. An unquoted string reached a separator character.
     *    (in_quot == 0 && *( *cur ) == ',').
     */
    /*
     * Skip whitespaces until reaching end or
     * separator character.
     */
    while( *cur < end && *( *cur ) == ' ' )
    {
        ( *cur )++;
    }

    /*
     * Current position must be either end or separator character.
     * Otherwise, return error.
     */
    if( *cur != end && *( *cur ) != ',' )
    {
        ret = MBEDTLS_ERR_X509_INVALID_NAME;
        goto exit;
    }

    /*
     * Change the current position to after the separator character
     */
    if( *cur != end )
        ( *cur )++;

    if( mbedtls_asn1_store_named_data( head, attr_descr->oid,
                                       strlen( attr_descr->oid ),
                                       (unsigned char *) data,
                                       value_len ) == NULL )
    {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto exit;
    }

    ( *head )->val.tag = attr_descr->default_tag;

exit:
    return( ret );
}

int mbedtls_x509_string_to_names( mbedtls_asn1_named_data **head,
                                  const char *name )
{
    int ret = 0;
    const char *cur = name;
    const char *end = name + strlen( name );
    const x509_attr_descriptor_t* attr_descr = NULL;

    /* Clear existing chain if present */
    mbedtls_asn1_free_named_data_list( head );

    /*
     * Parse the name as pairs of tag and value.
     */
    while( cur < end )
    {
        ret = x509_dn_parse_tag( &cur, end, &attr_descr );
        if( ret != 0 )
            goto exit;

        ret = x509_dn_parse_value( &cur, end, attr_descr, head );
        if( ret != 0 )
            goto exit;
    }

exit:

    return( ret );
}

/* The first byte of the value in the mbedtls_asn1_named_data structure is reserved
 * to store the critical boolean for us
 */
int mbedtls_x509_set_extension( mbedtls_asn1_named_data **head, const char *oid, size_t oid_len,
                        int critical, const unsigned char *val, size_t val_len )
{
    mbedtls_asn1_named_data *cur;

    if( ( cur = mbedtls_asn1_store_named_data( head, oid, oid_len,
                                       NULL, val_len + 1 ) ) == NULL )
    {
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );
    }

    cur->val.p[0] = critical;
    memcpy( cur->val.p + 1, val, val_len );

    return( 0 );
}

/*
 *  RelativeDistinguishedName ::=
 *    SET OF AttributeTypeAndValue
 *
 *  AttributeTypeAndValue ::= SEQUENCE {
 *    type     AttributeType,
 *    value    AttributeValue }
 *
 *  AttributeType ::= OBJECT IDENTIFIER
 *
 *  AttributeValue ::= ANY DEFINED BY AttributeType
 */
static int x509_write_name( unsigned char **p, unsigned char *start, mbedtls_asn1_named_data* cur_name)
{
    int ret;
    size_t len = 0;
    const char *oid             = (const char*)cur_name->oid.p;
    size_t oid_len              = cur_name->oid.len;
    const unsigned char *name   = cur_name->val.p;
    size_t name_len             = cur_name->val.len;

    // Write correct string tag and value
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tagged_string( p, start,
                                                       cur_name->val.tag,
                                                       (const char *) name,
                                                       name_len ) );
    // Write OID
    //
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_oid( p, start, oid,
                                                       oid_len ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start,
                                                    MBEDTLS_ASN1_CONSTRUCTED |
                                                    MBEDTLS_ASN1_SEQUENCE ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start,
                                                 MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SET ) );

    return( (int) len );
}

int mbedtls_x509_write_names( unsigned char **p, unsigned char *start,
                              mbedtls_asn1_named_data *first )
{
    int ret;
    size_t len = 0;
    mbedtls_asn1_named_data *cur = first;

    while( cur != NULL )
    {
        MBEDTLS_ASN1_CHK_ADD( len, x509_write_name( p, start, cur ) );
        cur = cur->next;
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

int mbedtls_x509_write_sig( unsigned char **p, unsigned char *start,
                    const char *oid, size_t oid_len,
                    unsigned char *sig, size_t size )
{
    int ret;
    size_t len = 0;

    if( *p < start || (size_t)( *p - start ) < size )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    len = size;
    (*p) -= len;
    memcpy( *p, sig, len );

    if( *p - start < 1 )
        return( MBEDTLS_ERR_ASN1_BUF_TOO_SMALL );

    *--(*p) = 0;
    len += 1;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_BIT_STRING ) );

    // Write OID
    //
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_algorithm_identifier( p, start, oid,
                                                        oid_len, 0 ) );

    return( (int) len );
}

static int x509_write_extension( unsigned char **p, unsigned char *start,
                                 mbedtls_asn1_named_data *ext )
{
    int ret;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start, ext->val.p + 1,
                                              ext->val.len - 1 ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, ext->val.len - 1 ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OCTET_STRING ) );

    if( ext->val.p[0] != 0 )
    {
        MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_bool( p, start, 1 ) );
    }

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_raw_buffer( p, start, ext->oid.p,
                                              ext->oid.len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, ext->oid.len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_OID ) );

    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_len( p, start, len ) );
    MBEDTLS_ASN1_CHK_ADD( len, mbedtls_asn1_write_tag( p, start, MBEDTLS_ASN1_CONSTRUCTED |
                                                 MBEDTLS_ASN1_SEQUENCE ) );

    return( (int) len );
}

/*
 * Extension  ::=  SEQUENCE  {
 *     extnID      OBJECT IDENTIFIER,
 *     critical    BOOLEAN DEFAULT FALSE,
 *     extnValue   OCTET STRING
 *                 -- contains the DER encoding of an ASN.1 value
 *                 -- corresponding to the extension type identified
 *                 -- by extnID
 *     }
 */
int mbedtls_x509_write_extensions( unsigned char **p, unsigned char *start,
                           mbedtls_asn1_named_data *first )
{
    int ret;
    size_t len = 0;
    mbedtls_asn1_named_data *cur_ext = first;

    while( cur_ext != NULL )
    {
        MBEDTLS_ASN1_CHK_ADD( len, x509_write_extension( p, start, cur_ext ) );
        cur_ext = cur_ext->next;
    }

    return( (int) len );
}

#endif /* MBEDTLS_X509_CREATE_C */
