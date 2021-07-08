/*
 *  TLS 1.3 key schedule
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 ( the "License" ); you may
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

#if defined(MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL)

#include "mbedtls/hkdf.h"
#include "ssl_misc.h"
#include "ssl_tls13_keys.h"
#include "mbedtls/debug.h"

#include <stdint.h>
#include <string.h>

#define MBEDTLS_SSL_TLS1_3_LABEL( name, string )       \
    .name = string,

struct mbedtls_ssl_tls1_3_labels_struct const mbedtls_ssl_tls1_3_labels =
{
    /* This seems to work in C, despite the string literal being one
     * character too long due to the 0-termination. */
    MBEDTLS_SSL_TLS1_3_LABEL_LIST
};

#undef MBEDTLS_SSL_TLS1_3_LABEL

/*
 * This function creates a HkdfLabel structure used in the TLS 1.3 key schedule.
 *
 * The HkdfLabel is specified in RFC 8446 as follows:
 *
 * struct HkdfLabel {
 *   uint16 length;            // Length of expanded key material
 *   opaque label<7..255>;     // Always prefixed by "tls13 "
 *   opaque context<0..255>;   // Usually a communication transcript hash
 * };
 *
 * Parameters:
 * - desired_length: Length of expanded key material
 *                   Even though the standard allows expansion to up to
 *                   2**16 Bytes, TLS 1.3 never uses expansion to more than
 *                   255 Bytes, so we require `desired_length` to be at most
 *                   255. This allows us to save a few Bytes of code by
 *                   hardcoding the writing of the high bytes.
 * - (label, llen): label + label length, without "tls13 " prefix
 *                  The label length MUST be less than or equal to
 *                  MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN
 *                  It is the caller's responsibility to ensure this.
 *                  All (label, label length) pairs used in TLS 1.3
 *                  can be obtained via MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN().
 * - (ctx, clen): context + context length
 *                The context length MUST be less than or equal to
 *                MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN
 *                It is the caller's responsibility to ensure this.
 * - dst: Target buffer for HkdfLabel structure,
 *        This MUST be a writable buffer of size
 *        at least SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN Bytes.
 * - dlen: Pointer at which to store the actual length of
 *         the HkdfLabel structure on success.
 */

static const char tls1_3_label_prefix[6] = "tls13 ";

#define SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN( label_len, context_len ) \
    (   2                  /* expansion length           */ \
      + 1                  /* label length               */ \
      + label_len                                           \
      + 1                  /* context length             */ \
      + context_len )

#define SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN                      \
    SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN(                             \
                     sizeof(tls1_3_label_prefix) +                      \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN,     \
                     MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )

static void ssl_tls1_3_hkdf_encode_label(
                            size_t desired_length,
                            const unsigned char *label, size_t llen,
                            const unsigned char *ctx, size_t clen,
                            unsigned char *dst, size_t *dlen )
{
    size_t total_label_len =
        sizeof(tls1_3_label_prefix) + llen;
    size_t total_hkdf_lbl_len =
        SSL_TLS1_3_KEY_SCHEDULE_HKDF_LABEL_LEN( total_label_len, clen );

    unsigned char *p = dst;

    /* Add the size of the expanded key material.
     * We're hardcoding the high byte to 0 here assuming that we never use
     * TLS 1.3 HKDF key expansion to more than 255 Bytes. */
#if MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN > 255
#error "The implementation of ssl_tls1_3_hkdf_encode_label() is not fit for the \
        value of MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN"
#endif

    *p++ = 0;
    *p++ = MBEDTLS_CHAR_0( desired_length );

    /* Add label incl. prefix */
    *p++ = MBEDTLS_CHAR_0( total_label_len );
    memcpy( p, tls1_3_label_prefix, sizeof(tls1_3_label_prefix) );
    p += sizeof(tls1_3_label_prefix);
    memcpy( p, label, llen );
    p += llen;

    /* Add context value */
    *p++ = MBEDTLS_CHAR_0( clen );
    if( clen != 0 )
        memcpy( p, ctx, clen );

    /* Return total length to the caller.  */
    *dlen = total_hkdf_lbl_len;
}

int mbedtls_ssl_tls1_3_hkdf_expand_label(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *secret, size_t slen,
                     const unsigned char *label, size_t llen,
                     const unsigned char *ctx, size_t clen,
                     unsigned char *buf, size_t blen )
{
    const mbedtls_md_info_t *md;
    unsigned char hkdf_label[ SSL_TLS1_3_KEY_SCHEDULE_MAX_HKDF_LABEL_LEN ];
    size_t hkdf_label_len;

    if( llen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_LABEL_LEN )
    {
        /* Should never happen since this is an internal
         * function, and we know statically which labels
         * are allowed. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( clen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_CONTEXT_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    if( blen > MBEDTLS_SSL_TLS1_3_KEY_SCHEDULE_MAX_EXPANSION_LEN )
    {
        /* Should not happen, as above. */
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
    }

    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    ssl_tls1_3_hkdf_encode_label( blen,
                                  label, llen,
                                  ctx, clen,
                                  hkdf_label,
                                  &hkdf_label_len );

    return( mbedtls_hkdf_expand( md,
                                 secret, slen,
                                 hkdf_label, hkdf_label_len,
                                 buf, blen ) );
}

/*
 * The traffic keying material is generated from the following inputs:
 *
 *  - One secret value per sender.
 *  - A purpose value indicating the specific value being generated
 *  - The desired lengths of key and IV.
 *
 * The expansion itself is based on HKDF:
 *
 *   [sender]_write_key = HKDF-Expand-Label( Secret, "key", "", key_length )
 *   [sender]_write_iv  = HKDF-Expand-Label( Secret, "iv" , "", iv_length )
 *
 * [sender] denotes the sending side and the Secret value is provided
 * by the function caller. Note that we generate server and client side
 * keys in a single function call.
 */
int mbedtls_ssl_tls1_3_make_traffic_keys(
                     mbedtls_md_type_t hash_alg,
                     const unsigned char *client_secret,
                     const unsigned char *server_secret,
                     size_t slen, size_t key_len, size_t iv_len,
                     mbedtls_ssl_key_set *keys )
{
    int ret = 0;

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    client_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( key ),
                    NULL, 0,
                    keys->client_write_key, key_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    server_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( key ),
                    NULL, 0,
                    keys->server_write_key, key_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    client_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( iv ),
                    NULL, 0,
                    keys->client_write_iv, iv_len );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                    server_secret, slen,
                    MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( iv ),
                    NULL, 0,
                    keys->server_write_iv, iv_len );
    if( ret != 0 )
        return( ret );

    keys->key_len = key_len;
    keys->iv_len = iv_len;

    return( 0 );
}

int mbedtls_ssl_tls1_3_derive_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret, size_t slen,
                   const unsigned char *label, size_t llen,
                   const unsigned char *ctx, size_t clen,
                   int ctx_hashed,
                   unsigned char *dstbuf, size_t buflen )
{
    int ret;
    unsigned char hashed_context[ MBEDTLS_MD_MAX_SIZE ];

    const mbedtls_md_info_t *md;
    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    if( ctx_hashed == MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED )
    {
        ret = mbedtls_md( md, ctx, clen, hashed_context );
        if( ret != 0 )
            return( ret );
        clen = mbedtls_md_get_size( md );
    }
    else
    {
        if( clen > sizeof(hashed_context) )
        {
            /* This should never happen since this function is internal
             * and the code sets `ctx_hashed` correctly.
             * Let's double-check nonetheless to not run at the risk
             * of getting a stack overflow. */
            return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );
        }

        memcpy( hashed_context, ctx, clen );
    }

    return( mbedtls_ssl_tls1_3_hkdf_expand_label( hash_alg,
                                                  secret, slen,
                                                  label, llen,
                                                  hashed_context, clen,
                                                  dstbuf, buflen ) );
}

int mbedtls_ssl_tls1_3_evolve_secret(
                   mbedtls_md_type_t hash_alg,
                   const unsigned char *secret_old,
                   const unsigned char *input, size_t input_len,
                   unsigned char *secret_new )
{
    int ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    size_t hlen, ilen;
    unsigned char tmp_secret[ MBEDTLS_MD_MAX_SIZE ] = { 0 };
    unsigned char tmp_input [ MBEDTLS_MD_MAX_SIZE ] = { 0 };

    const mbedtls_md_info_t *md;
    md = mbedtls_md_info_from_type( hash_alg );
    if( md == NULL )
        return( MBEDTLS_ERR_SSL_BAD_INPUT_DATA );

    hlen = mbedtls_md_get_size( md );

    /* For non-initial runs, call Derive-Secret( ., "derived", "")
     * on the old secret. */
    if( secret_old != NULL )
    {
        ret = mbedtls_ssl_tls1_3_derive_secret(
                   hash_alg,
                   secret_old, hlen,
                   MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( derived ),
                   NULL, 0, /* context */
                   MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                   tmp_secret, hlen );
        if( ret != 0 )
            goto cleanup;
    }

    if( input != NULL )
    {
        memcpy( tmp_input, input, input_len );
        ilen = input_len;
    }
    else
    {
        ilen = hlen;
    }

    /* HKDF-Extract takes a salt and input key material.
     * The salt is the old secret, and the input key material
     * is the input secret (PSK / ECDHE). */
    ret = mbedtls_hkdf_extract( md,
                    tmp_secret, hlen,
                    tmp_input, ilen,
                    secret_new );
    if( ret != 0 )
        goto cleanup;

    ret = 0;

 cleanup:

    mbedtls_platform_zeroize( tmp_secret, sizeof(tmp_secret) );
    mbedtls_platform_zeroize( tmp_input,  sizeof(tmp_input)  );
    return( ret );
}

int mbedtls_ssl_tls1_3_derive_early_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *early_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_early_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /*
     *            0
     *            |
     *            v
     *  PSK ->  HKDF-Extract = Early Secret
     *            |
     *            +-----> Derive-Secret(., "c e traffic", ClientHello)
     *            |                     = client_early_traffic_secret
     *            |
     *            +-----> Derive-Secret(., "e exp master", ClientHello)
     *            |                     = early_exporter_master_secret
     *            v
     */

    /* Create client_early_traffic_secret */
    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
                         early_secret, md_size,
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_e_traffic ),
                         transcript, transcript_len,
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         derived->client_early_traffic_secret,
                         md_size );
    if( ret != 0 )
        return( ret );

    /* Create early exporter */
    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
                         early_secret, md_size,
                         MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( e_exp_master ),
                         transcript, transcript_len,
                         MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
                         derived->early_exporter_master_secret,
                         md_size );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_ssl_tls1_3_derive_handshake_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *handshake_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_handshake_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /*
     *
     * Handshake Secret
     * |
     * +-----> Derive-Secret( ., "c hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = client_handshake_traffic_secret
     * |
     * +-----> Derive-Secret( ., "s hs traffic",
     * |                     ClientHello...ServerHello )
     * |                     = server_handshake_traffic_secret
     *
     */

    /*
     * Compute client_handshake_traffic_secret with
     * Derive-Secret( ., "c hs traffic", ClientHello...ServerHello )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
             handshake_secret, md_size,
             MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_hs_traffic ),
             transcript, transcript_len,
             MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
             derived->client_handshake_traffic_secret,
             md_size );
    if( ret != 0 )
        return( ret );

    /*
     * Compute server_handshake_traffic_secret with
     * Derive-Secret( ., "s hs traffic", ClientHello...ServerHello )
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
             handshake_secret, md_size,
             MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( s_hs_traffic ),
             transcript, transcript_len,
             MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
             derived->server_handshake_traffic_secret,
             md_size );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

int mbedtls_ssl_tls1_3_derive_application_secrets(
          mbedtls_md_type_t md_type,
          unsigned char const *application_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_application_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /* Generate {client,server}_application_traffic_secret_0
     *
     * Master Secret
     * |
     * +-----> Derive-Secret( ., "c ap traffic",
     * |                      ClientHello...server Finished )
     * |                      = client_application_traffic_secret_0
     * |
     * +-----> Derive-Secret( ., "s ap traffic",
     * |                      ClientHello...Server Finished )
     * |                      = server_application_traffic_secret_0
     * |
     * +-----> Derive-Secret( ., "exp master",
     * |                      ClientHello...server Finished)
     * |                      = exporter_master_secret
     *
     */

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( c_ap_traffic ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->client_application_traffic_secret_N,
              md_size );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( s_ap_traffic ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->server_application_traffic_secret_N,
              md_size );
    if( ret != 0 )
        return( ret );

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( exp_master ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->exporter_master_secret,
              md_size );
    if( ret != 0 )
        return( ret );

    return( 0 );
}

/* Generate resumption_master_secret for use with the ticket exchange.
 *
 * This is not integrated with mbedtls_ssl_tls1_3_derive_application_secrets()
 * because it uses the transcript hash up to and including ClientFinished. */
int mbedtls_ssl_tls1_3_derive_resumption_master_secret(
          mbedtls_md_type_t md_type,
          unsigned char const *application_secret,
          unsigned char const *transcript, size_t transcript_len,
          mbedtls_ssl_tls1_3_application_secrets *derived )
{
    int ret;
    mbedtls_md_info_t const * const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
              application_secret, md_size,
              MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( res_master ),
              transcript, transcript_len,
              MBEDTLS_SSL_TLS1_3_CONTEXT_HASHED,
              derived->resumption_master_secret,
              md_size );

    if( ret != 0 )
        return( ret );

    return( 0 );
}

static int ssl_tls1_3_calc_finished_core( mbedtls_md_type_t md_type,
                                          unsigned char const *base_key,
                                          unsigned char const *transcript,
                                          unsigned char *dst )
{
    const mbedtls_md_info_t* const md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );
    unsigned char finished_key[MBEDTLS_MD_MAX_SIZE];
    int ret;

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /* TLS 1.3 Finished message
     *
     * struct {
     *     opaque verify_data[Hash.length];
     * } Finished;
     *
     * verify_data =
     *     HMAC( finished_key,
     *            Hash( Handshake Context +
     *                  Certificate*      +
     *                  CertificateVerify* )
     *    )
     *
     * finished_key =
     *    HKDF-Expand-Label( BaseKey, "finished", "", Hash.length )
     */

    ret = mbedtls_ssl_tls1_3_hkdf_expand_label(
                                 md_type, base_key, md_size,
                                 MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( finished ),
                                 NULL, 0,
                                 finished_key, md_size );
    if( ret != 0 )
        goto exit;

    ret = mbedtls_md_hmac( md_info, finished_key, md_size, transcript, md_size, dst );
    if( ret != 0 )
        goto exit;

exit:

    mbedtls_platform_zeroize( finished_key, sizeof( finished_key ) );
    return( ret );
}

int mbedtls_ssl_tls1_3_create_psk_binder( mbedtls_ssl_context *ssl,
                               const mbedtls_md_type_t md_type,
                               unsigned char const *psk, size_t psk_len,
                               int psk_type,
                               unsigned char const *transcript,
                               unsigned char *result )
{
    int ret = 0;
    unsigned char binder_key[MBEDTLS_MD_MAX_SIZE];
    unsigned char early_secret[MBEDTLS_MD_MAX_SIZE];
    mbedtls_md_info_t const *md_info = mbedtls_md_info_from_type( md_type );
    size_t const md_size = mbedtls_md_get_size( md_info );

#if !defined(MBEDTLS_DEBUG_C)
    ssl = NULL; /* make sure we don't use it except for debug */
    ((void) ssl);
#endif

    /* We should never call this function with an unknown hash,
     * but add an assertion anyway. */
    if( md_info == 0 )
        return( MBEDTLS_ERR_SSL_INTERNAL_ERROR );

    /*
     *            0
     *            |
     *            v
     *  PSK ->  HKDF-Extract = Early Secret
     *            |
     *            +-----> Derive-Secret(., "ext binder" | "res binder", "")
     *            |                     = binder_key
     *            v
     */

    ret = mbedtls_ssl_tls1_3_evolve_secret( md_type,
                                            NULL,          /* Old secret */
                                            psk, psk_len,  /* Input      */
                                            early_secret );
    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_evolve_secret", ret );
        goto exit;
    }

    if( psk_type == MBEDTLS_SSL_TLS1_3_PSK_RESUMPTION )
    {
        ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
                            early_secret, md_size,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( res_binder ),
                            NULL, 0, MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                            binder_key, md_size );
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Derive Early Secret with 'res binder'" ) );
    }
    else
    {
        ret = mbedtls_ssl_tls1_3_derive_secret( md_type,
                            early_secret, md_size,
                            MBEDTLS_SSL_TLS1_3_LBL_WITH_LEN( ext_binder ),
                            NULL, 0, MBEDTLS_SSL_TLS1_3_CONTEXT_UNHASHED,
                            binder_key, md_size );
        MBEDTLS_SSL_DEBUG_MSG( 4, ( "Derive Early Secret with 'ext binder'" ) );
    }

    if( ret != 0 )
    {
        MBEDTLS_SSL_DEBUG_RET( 1, "mbedtls_ssl_tls1_3_derive_secret", ret );
        goto exit;
    }

    /*
     * The binding_value is computed in the same way as the Finished message
     * but with the BaseKey being the binder_key.
     */

    ret = ssl_tls1_3_calc_finished_core( md_type, binder_key, transcript, result );
    if( ret != 0 )
        goto exit;

    MBEDTLS_SSL_DEBUG_BUF( 3, "psk binder", result, md_size );

exit:

    mbedtls_platform_zeroize( early_secret, sizeof( early_secret ) );
    mbedtls_platform_zeroize( binder_key,   sizeof( binder_key ) );
    return( ret );
}

#endif /* MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL */
