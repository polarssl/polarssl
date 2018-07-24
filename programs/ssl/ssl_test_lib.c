/*
 *  Common code for SSL test programs
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

#include "ssl_test_lib.h"

#ifdef MBEDTLS_PROGRAMS_SSL__PREREQUISITES

void mbedtls_ssl_test_debug( void *ctx, int level,
                             const char *file, int line,
                             const char *str )
{
    const char *p, *basename;

    /* Extract basename from file */
    for( p = basename = file; *p != '\0'; p++ )
        if( *p == '/' || *p == '\\' )
            basename = p + 1;

    mbedtls_fprintf( (FILE *) ctx, "%s:%04d: |%d| %s", basename, line, level, str );
    fflush( (FILE *) ctx );
}

/* Fake entropy source which is a constant string. Use this for
 * reproducible tests. Note that to achieve reproducible tests, you
 * must also either undefine MBEDTLS_HAVE_TIME or arrange to set a
 * constant fake time (e.g. with faketime). */
static int mbedtls_ssl_test_fake_entropy_func( void *data,
                                               unsigned char *output,
                                               size_t output_len )
{
    const char *input = data;
    size_t input_len = strlen( input );
    size_t n;
    for( n = 0; n + input_len < output_len; n += input_len )
        memcpy( output + n, input, input_len );
    memcpy( output + n, input, output_len - n );
    return( 0 );
}

int mbedtls_ssl_test_rng_use_fake_entropy( const char *fake_entropy )
{
    return( fake_entropy != NULL && *fake_entropy != 0 );
}

int mbedtls_ssl_test_rng_init( const char *fake_entropy,
                               const char *pers,
                               mbedtls_entropy_context *entropy,
                               mbedtls_ctr_drbg_context *ctr_drbg )
{
    int ret;

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );

    if( mbedtls_ssl_test_rng_use_fake_entropy( fake_entropy ) )
    {
        ret = mbedtls_ctr_drbg_seed( ctr_drbg,
                                     mbedtls_ssl_test_fake_entropy_func,
                                     (void *) fake_entropy,
                                     (const unsigned char *) pers,
                                     strlen( pers ) );
        mbedtls_printf( " (fake, each connection will use a constant seed)" );
    }
    else
    {
        mbedtls_entropy_init( entropy );
        ret = mbedtls_ctr_drbg_seed( ctr_drbg,
                                     mbedtls_entropy_func, entropy,
                                     (const unsigned char *) pers,
                                     strlen( pers ) );
    }

    if( ret != 0 )
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret );
    else
        mbedtls_printf( " ok\n" );
    return( ret );
}

void mbedtls_ssl_test_rng_reset_if_fake( const char *fake_entropy,
                                         const char *pers,
                                         mbedtls_ctr_drbg_context *ctr_drbg )
{
    if( ! mbedtls_ssl_test_rng_use_fake_entropy( fake_entropy ) )
        return;

    mbedtls_ctr_drbg_free( ctr_drbg );
    mbedtls_ctr_drbg_init( ctr_drbg );
    mbedtls_ctr_drbg_seed( ctr_drbg,
                           mbedtls_ssl_test_fake_entropy_func,
                           (void *) fake_entropy,
                           (const unsigned char *) pers,
                           strlen( pers ) );
    mbedtls_printf( "  . Resetting the random number generator to the constant seed... ok\n" );
}

/*
 * Test recv/send functions that make sure each try returns
 * WANT_READ/WANT_WRITE at least once before sucesseding
 */
int mbedtls_ssl_test_recv( void *ctx, unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_READ );
    }

    ret = mbedtls_net_recv( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_READ )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

int mbedtls_ssl_test_send( void *ctx, const unsigned char *buf, size_t len )
{
    static int first_try = 1;
    int ret;

    if( first_try )
    {
        first_try = 0;
        return( MBEDTLS_ERR_SSL_WANT_WRITE );
    }

    ret = mbedtls_net_send( ctx, buf, len );
    if( ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        first_try = 1; /* Next call will be a new operation */
    return( ret );
}

#define HEX2NUM( c )                    \
        if( c >= '0' && c <= '9' )      \
            c -= '0';                   \
        else if( c >= 'a' && c <= 'f' ) \
            c -= 'a' - 10;              \
        else if( c >= 'A' && c <= 'F' ) \
            c -= 'A' - 10;              \
        else                            \
            return( -1 );

/*
 * Convert a hex string to bytes.
 * Return 0 on success, -1 on error.
 */
int mbedtls_ssl_test_unhexify( const char *input,
                               unsigned char *output, size_t osize,
                               size_t *olen )
{
    unsigned char c;
    size_t j;

    *olen = strlen( input );
    if( *olen % 2 != 0 || *olen / 2 > osize )
        return( -1 );
    *olen /= 2;

    for( j = 0; j < *olen * 2; j += 2 )
    {
        c = input[j];
        HEX2NUM( c );
        output[ j / 2 ] = c << 4;

        c = input[j + 1];
        HEX2NUM( c );
        output[ j / 2 ] |= c;
    }

    return( 0 );
}

int mbedtls_ssl_test_forced_ciphersuite( int force_ciphersuite,
                                         int transport,
                                         int min_version,
                                         int max_version,
                                         int *arc4 )
{
    const mbedtls_ssl_ciphersuite_t *ciphersuite_info;
    ciphersuite_info = mbedtls_ssl_ciphersuite_from_id( force_ciphersuite );

    if( max_version != -1 &&
        ciphersuite_info->min_minor_ver > max_version )
    {
        mbedtls_printf( "forced ciphersuite not allowed with this protocol version\n" );
        return( 2 );
    }
    if( min_version != -1 &&
        ciphersuite_info->max_minor_ver < min_version )
    {
        mbedtls_printf( "forced ciphersuite not allowed with this protocol version\n" );
        return( 2 );
    }

    /* If the server selects a version that's not supported by
     * this suite, then there will be no common ciphersuite... */
    if( max_version == -1 ||
        max_version > ciphersuite_info->max_minor_ver )
    {
        max_version = ciphersuite_info->max_minor_ver;
    }
    if( min_version < ciphersuite_info->min_minor_ver )
    {
        min_version = ciphersuite_info->min_minor_ver;
        /* DTLS starts with TLS 1.1 */
        if( transport == MBEDTLS_SSL_TRANSPORT_DATAGRAM &&
            min_version < MBEDTLS_SSL_MINOR_VERSION_2 )
            min_version = MBEDTLS_SSL_MINOR_VERSION_2;
    }

    /* Enable RC4 if needed and not explicitly disabled */
    if( ciphersuite_info->cipher == MBEDTLS_CIPHER_ARC4_128 )
    {
        if( *arc4 == MBEDTLS_SSL_ARC4_DISABLED )
        {
            mbedtls_printf( "forced RC4 ciphersuite with RC4 disabled\n" );
            return( 2 );
        }

        *arc4 = MBEDTLS_SSL_ARC4_ENABLED;
    }
    return( 0 );
}

int mbedtls_ssl_test_parse_version( const char *p, const char *q )
{
    if( strcmp( q, "ssl3" ) == 0 )
        return( MBEDTLS_SSL_MINOR_VERSION_0 );
    else if( strcmp( q, "tls1" ) == 0 )
        return( MBEDTLS_SSL_MINOR_VERSION_1 );
    else if( strcmp( q, "tls1_1" ) == 0 || strcmp( q, "dtls1" ) == 0 )
        return( MBEDTLS_SSL_MINOR_VERSION_2 );
    else if( strcmp( q, "tls1_2" ) == 0 || strcmp( q, "dtls1_2" ) == 0 )
        return( MBEDTLS_SSL_MINOR_VERSION_3 );
    else
    {
        mbedtls_printf( "Invalid value for option %s (must be ssl3|d?tls1|tls1_1|d?tls1_2)\n",
                        p );
        return( MBEDTLS_SSL_TEST_BAD_VERSION );
    }
}

/*
 * Return authmode from string, or -1 on error
 */
int mbedtls_ssl_test_get_auth_mode( const char *s )
{
    if( strcmp( s, "none" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_NONE );
    if( strcmp( s, "optional" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_OPTIONAL );
    if( strcmp( s, "required" ) == 0 )
        return( MBEDTLS_SSL_VERIFY_REQUIRED );

    return( -1 );
}

#if defined(MBEDTLS_X509_CRT_PARSE_C)
static const int mbedtls_ssl_test_sig_hashes_with_sha1[] = {
#if defined(MBEDTLS_SHA512_C)
    MBEDTLS_MD_SHA512,
    MBEDTLS_MD_SHA384,
#endif
#if defined(MBEDTLS_SHA256_C)
    MBEDTLS_MD_SHA256,
    MBEDTLS_MD_SHA224,
#endif
#if defined(MBEDTLS_SHA1_C)
    /* Allow SHA-1 as we use it extensively in tests. */
    MBEDTLS_MD_SHA1,
#endif
    MBEDTLS_MD_NONE
};

void mbedtls_ssl_test_conf_allow_sha1( mbedtls_ssl_config *conf,
                                       mbedtls_x509_crt_profile *crt_profile )
{
    *crt_profile = mbedtls_x509_crt_profile_default;
    crt_profile->allowed_mds |= MBEDTLS_X509_ID_FLAG( MBEDTLS_MD_SHA1 );
    mbedtls_ssl_conf_cert_profile( conf, crt_profile );
    mbedtls_ssl_conf_sig_hashes( conf, mbedtls_ssl_test_sig_hashes_with_sha1 );
}
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_ECP_C)
int mbedtls_ssl_test_parse_curves( char *p,
                                 mbedtls_ecp_group_id *curve_list )
{
    int i = 0;
    const mbedtls_ecp_curve_info *curve_cur;
    const char *q;

    if( p == NULL )
        return( 0 );

    if( strcmp( p, "none" ) == 0 )
    {
        curve_list[0] = MBEDTLS_ECP_DP_NONE;
    }
    else if( strcmp( p, "default" ) != 0 )
    {
        /* Leave room for a final NULL in curve list */
        while( i < CURVE_LIST_SIZE - 1 && *p != '\0' )
        {
            q = p;

            /* Terminate the current string */
            while( *p != ',' && *p != '\0' )
                p++;
            if( *p == ',' )
                *p++ = '\0';

            if( ( curve_cur = mbedtls_ecp_curve_info_from_name( q ) ) != NULL )
            {
                curve_list[i++] = curve_cur->grp_id;
            }
            else
            {
                mbedtls_printf( "unknown curve %s\n", q );
                mbedtls_printf( "supported curves: " );
                for( curve_cur = mbedtls_ecp_curve_list();
                     curve_cur->grp_id != MBEDTLS_ECP_DP_NONE;
                     curve_cur++ )
                {
                    mbedtls_printf( "%s ", curve_cur->name );
                }
                mbedtls_printf( "\n" );
                return( 2 );
            }
        }

        mbedtls_printf( "Number of curves: %d\n", i );

        if( i == CURVE_LIST_SIZE - 1 && *p != '\0' )
        {
            mbedtls_printf( "curves list too long, maximum %d",
                            CURVE_LIST_SIZE - 1 );
            return( 2 );
        }

        curve_list[i] = MBEDTLS_ECP_DP_NONE;
    }

    return( 0 );
}
#endif /* MBEDTLS_ECP_C */

#if defined(MBEDTLS_SSL_ALPN)
int mbedtls_ssl_test_parse_alpn( char *p,
                                 const char *alpn_list[] )
{
    int i = 0;
    if( p == NULL )
        return( 0 );

    /* Leave room for a final NULL in alpn_list */
    while( i < ALPN_LIST_SIZE - 1 && *p != '\0' )
    {
        alpn_list[i++] = p;

        /* Terminate the current string and move on to next one */
        while( *p != ',' && *p != '\0' )
            p++;
        if( *p == ',' )
            *p++ = '\0';
    }

    return( 0 );
}
#endif /* MBEDTLS_SSL_ALPN */

#endif /* MBEDTLS_PROGRAMS_SSL__PREREQUISITES */
