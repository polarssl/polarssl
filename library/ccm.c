/*
 *  NIST SP800-38C compliant CCM implementation
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

/*
 * Definition of CCM:
 * http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C_updated-July20_2007.pdf
 * RFC 3610 "Counter with CBC-MAC (CCM)"
 *
 * Related:
 * RFC 5116 "An Interface and Algorithms for Authenticated Encryption"
 */

#include "common.h"

#if defined(MBEDTLS_CCM_C)

#include "mbedtls/ccm.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <string.h>

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf printf
#endif /* MBEDTLS_PLATFORM_C */
#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

#if !defined(MBEDTLS_CCM_ALT)

#define CCM_VALIDATE_RET( cond ) \
    MBEDTLS_INTERNAL_VALIDATE_RET( cond, MBEDTLS_ERR_CCM_BAD_INPUT )
#define CCM_VALIDATE( cond ) \
    MBEDTLS_INTERNAL_VALIDATE( cond )

#define CCM_ENCRYPT 0
#define CCM_DECRYPT 1

/*
 * Initialize context
 */
void mbedtls_ccm_init( mbedtls_ccm_context *ctx )
{
    CCM_VALIDATE( ctx != NULL );
    memset( ctx, 0, sizeof( mbedtls_ccm_context ) );
}

int mbedtls_ccm_setkey( mbedtls_ccm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    const mbedtls_cipher_info_t *cipher_info;

    CCM_VALIDATE_RET( ctx != NULL );
    CCM_VALIDATE_RET( key != NULL );

    cipher_info = mbedtls_cipher_info_from_values( cipher, keybits,
                                                   MBEDTLS_MODE_ECB );
    if( cipher_info == NULL )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );

    if( cipher_info->block_size != 16 )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );

    mbedtls_cipher_free( &ctx->cipher_ctx );

    if( ( ret = mbedtls_cipher_setup( &ctx->cipher_ctx, cipher_info ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_cipher_setkey( &ctx->cipher_ctx, key, keybits,
                               MBEDTLS_ENCRYPT ) ) != 0 )
    {
        return( ret );
    }

    return( 0 );
}

/*
 * Free context
 */
void mbedtls_ccm_free( mbedtls_ccm_context *ctx )
{
    if( ctx == NULL )
        return;
    mbedtls_cipher_free( &ctx->cipher_ctx );
    mbedtls_platform_zeroize( ctx, sizeof( mbedtls_ccm_context ) );
}

/*
 * Update the CBC-MAC state in y using a block in b
 * (Always using b as the source helps the compiler optimise a bit better.)
 *
 * Macro results in smaller compiled code than static inline functions.
 */
#define UPDATE_CBC_MAC                                                                        \
    for( i = 0; i < 16; i++ )                                                                 \
        ctx->y[i] ^= ctx->b[i];                                                               \
                                                                                              \
    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx, ctx->y, 16, ctx->y, &olen ) ) != 0 ) \
    {                                                                                         \
        ctx->state |= CCM_STATE__ERROR;                                                       \
        return( ret );                                                                        \
    }                                                                                         \

#define CCM_STATE__CLEAR                0
#define CCM_STATE__STARTED              0x0001
#define CCM_STATE__LENGHTS_SET          0x0002
#define CCM_STATE__ERROR                0x0004

/*
 * Encrypt or decrypt a partial block with CTR
 */
static int mbedtls_ccm_crypt( mbedtls_ccm_context *ctx,
                              size_t offset, size_t use_len,
                              const unsigned char *input,
                              unsigned char *output )
{
    size_t i;
    size_t olen = 0;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char tmp_buf[16] = {0};

    if( ( ret = mbedtls_cipher_update( &ctx->cipher_ctx, ctx->ctr, 16, tmp_buf,
                                       &olen ) ) != 0 )
    {
        ctx->state |= CCM_STATE__ERROR;                                    \
        return ret;
    }

    for( i = 0; i < use_len; i++ )
        output[i] = input[i] ^ tmp_buf[offset + i];

    return ret;
}

static void mbedtls_ccm_clear_state(mbedtls_ccm_context *ctx) {
    ctx->state = CCM_STATE__CLEAR;
    memset( ctx->b, 0, 16);
    memset( ctx->y, 0, 16);
    memset( ctx->ctr, 0, 16);
}

static int mbedtls_ccm_calculate_first_block(mbedtls_ccm_context *ctx)
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char i;
    size_t len_left, olen;

    /* length calulcation can be done only after both
     * mbedtls_ccm_starts() and mbedtls_ccm_set_lengths() have been executed
     */
    if( !(ctx->state & CCM_STATE__STARTED) || !(ctx->state & CCM_STATE__LENGHTS_SET) )
        return 0;

    /*
     * First block B_0:
     * 0        .. 0        flags
     * 1        .. iv_len   nonce (aka iv)  - set by: mbedtls_ccm_starts()
     * iv_len+1 .. 15       length
     *
     * With flags as (bits):
     * 7        0
     * 6        add present?
     * 5 .. 3   (t - 2) / 2
     * 2 .. 0   q - 1
     */
    ctx->b[0] |= ( ctx->add_len > 0 ) << 6;
    ctx->b[0] |= ( ( ctx->tag_len - 2 ) / 2 ) << 3;
    ctx->b[0] |= ctx->q - 1;

    for( i = 0, len_left = ctx->plaintext_len; i < ctx->q; i++, len_left >>= 8 )
        ctx->b[15-i] = (unsigned char)( len_left & 0xFF );

    if( len_left > 0 )
    {
        ctx->state |= CCM_STATE__ERROR;
        return( MBEDTLS_ERR_CCM_BAD_INPUT );
    }

    /* Start CBC-MAC with first block*/
    UPDATE_CBC_MAC;

    return (0);
}

int mbedtls_ccm_starts( mbedtls_ccm_context *ctx,
                        int mode,
                        const unsigned char *iv,
                        size_t iv_len )
{
    /* Also implies q is within bounds */
    if( iv_len < 7 || iv_len > 13 )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );

    if( ctx->state & CCM_STATE__ERROR )
    {
        mbedtls_ccm_clear_state(ctx);
    }

    ctx->mode = mode;
    ctx->q = 16 - 1 - (unsigned char) iv_len;

    /*
     * Prepare counter block for encryption:
     * 0        .. 0        flags
     * 1        .. iv_len   nonce (aka iv)
     * iv_len+1 .. 15       counter (initially 1)
     *
     * With flags as (bits):
     * 7 .. 3   0
     * 2 .. 0   q - 1
     */
    memset( ctx->ctr, 0, 16);
    ctx->ctr[0] = ctx->q - 1;
    memcpy( ctx->ctr + 1, iv, iv_len );
    memset( ctx->ctr + 1 + iv_len, 0, ctx->q );
    ctx->ctr[15] = 1;

    /*
     * See mbedtls_ccm_calculate_first_block() for B block layout description
     */
    memcpy( ctx->b + 1, iv, iv_len );

    ctx->state |= CCM_STATE__STARTED;
    return mbedtls_ccm_calculate_first_block(ctx);
}

int mbedtls_ccm_set_lengths( mbedtls_ccm_context *ctx,
                             size_t total_ad_len,
                             size_t plaintext_len,
                             size_t tag_len )
{
    /*
     * Check length requirements: SP800-38C A.1
     * Additional requirement: a < 2^16 - 2^8 to simplify the code.
     * 'length' checked later (when writing it to the first block)
     *
     * Also, loosen the requirements to enable support for CCM* (IEEE 802.15.4).
     */
    if( tag_len == 2 || tag_len > 16 || tag_len % 2 != 0 )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );

    if( total_ad_len >= 0xFF00 )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );

    if( ctx->state & CCM_STATE__ERROR )
    {
        mbedtls_ccm_clear_state(ctx);
    }

    ctx->plaintext_len = plaintext_len;
    ctx->add_len = total_ad_len;
    ctx->tag_len = tag_len;
    ctx->processed = 0;

    ctx->state |= CCM_STATE__LENGHTS_SET;
    return mbedtls_ccm_calculate_first_block(ctx);
}

int mbedtls_ccm_update_ad( mbedtls_ccm_context *ctx,
                           const unsigned char *add,
                           size_t add_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char i;
    size_t olen, use_len, offset;

    if( ctx->add_len > 0 && add_len > 0)
    {
        if( ctx->processed == 0 )
        {
            memset( ctx->b, 0, 16 );
            ctx->b[0] = (unsigned char)( ( ctx->add_len >> 8 ) & 0xFF );
            ctx->b[1] = (unsigned char)( ( ctx->add_len      ) & 0xFF );

            ctx->processed += 2;
        }

        while( add_len > 0 )
        {
            offset = ctx->processed % 16;

            use_len = 16 - offset;

            if( use_len > add_len )
                use_len = add_len;

            memcpy( ctx->b + offset, add, use_len );
            ctx->processed += use_len;
            add_len -= use_len;
            add += use_len;

            if( use_len + offset == 16 || ctx->processed - 2 == ctx->add_len )
            {
                UPDATE_CBC_MAC;
                memset( ctx->b, 0, 16 );
            }
        }
    }

    if( ctx->processed - 2 == ctx->add_len )
        ctx->processed = 0; // prepare for mbedtls_ccm_update()

    return (0);
}

int mbedtls_ccm_update( mbedtls_ccm_context *ctx,
                        const unsigned char *input, size_t input_len,
                        unsigned char *output, size_t output_size,
                        size_t *output_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char i;
    size_t len_left, olen;
    const unsigned char *src;
    unsigned char *dst;

    if( output_size < input_len )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );
    CCM_VALIDATE_RET( output_length != NULL );
    *output_len = input_len;

    /*
     * Authenticate and {en,de}crypt the message.
     *
     * The only difference between encryption and decryption is
     * the respective order of authentication and {en,de}cryption.
     */
    len_left = input_len;
    src = input;
    dst = output;

    while( len_left > 0 )
    {
        size_t use_len = len_left > 16 ? 16 : len_left;

        if( ctx->mode == CCM_ENCRYPT )
        {
            memset( ctx->b, 0, 16 );
            memcpy( ctx->b, src, use_len );
            UPDATE_CBC_MAC;
        }

        mbedtls_ccm_crypt( ctx, 0, use_len, src, dst );

        if( ctx->mode == CCM_DECRYPT )
        {
            memset( ctx->b, 0, 16 );
            memcpy( ctx->b, dst, use_len );
            UPDATE_CBC_MAC;
        }

        dst += use_len;
        src += use_len;
        len_left -= use_len;

        /*
         * Increment counter.
         * No need to check for overflow thanks to the length check above.
         */
        for( i = 0; i < ctx->q; i++ )
            if( ++(ctx->ctr)[15-i] != 0 )
                break;
    }

    return (0);
}

int mbedtls_ccm_finish( mbedtls_ccm_context *ctx,
                        unsigned char *tag, size_t tag_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char i;

    /*
     * Authentication: reset counter and crypt/mask internal tag
     */
    for( i = 0; i < ctx->q; i++ )
        ctx->ctr[15-i] = 0;

    ret = mbedtls_ccm_crypt( ctx, 0, 16, ctx->y, ctx->y );
    if( ret != 0 )
        return ret;
    memcpy( tag, ctx->y, tag_len );
    mbedtls_ccm_clear_state(ctx);

    return( 0 );
}

/*
 * Authenticated encryption or decryption
 */
static int ccm_auth_crypt( mbedtls_ccm_context *ctx, int mode, size_t length,
                           const unsigned char *iv, size_t iv_len,
                           const unsigned char *add, size_t add_len,
                           const unsigned char *input, unsigned char *output,
                           unsigned char *tag, size_t tag_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    size_t olen;

    if( ( ret = mbedtls_ccm_starts( ctx, mode, iv, iv_len ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_ccm_set_lengths( ctx, add_len, length, tag_len ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_ccm_update_ad( ctx, add, add_len ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_ccm_update( ctx, input, length,
                                    output, length, &olen ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_ccm_finish( ctx, tag, tag_len ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Authenticated encryption
 */
int mbedtls_ccm_star_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len )
{
    CCM_VALIDATE_RET( ctx != NULL );
    CCM_VALIDATE_RET( iv != NULL );
    CCM_VALIDATE_RET( add_len == 0 || add != NULL );
    CCM_VALIDATE_RET( length == 0 || input != NULL );
    CCM_VALIDATE_RET( length == 0 || output != NULL );
    CCM_VALIDATE_RET( tag_len == 0 || tag != NULL );
    return( ccm_auth_crypt( ctx, CCM_ENCRYPT, length, iv, iv_len,
                            add, add_len, input, output, tag, tag_len ) );
}

int mbedtls_ccm_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len )
{
    CCM_VALIDATE_RET( ctx != NULL );
    CCM_VALIDATE_RET( iv != NULL );
    CCM_VALIDATE_RET( add_len == 0 || add != NULL );
    CCM_VALIDATE_RET( length == 0 || input != NULL );
    CCM_VALIDATE_RET( length == 0 || output != NULL );
    CCM_VALIDATE_RET( tag_len == 0 || tag != NULL );
    if( tag_len == 0 )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );

    return( mbedtls_ccm_star_encrypt_and_tag( ctx, length, iv, iv_len, add,
                add_len, input, output, tag, tag_len ) );
}

/*
 * Authenticated decryption
 */
int mbedtls_ccm_star_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len )
{
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
    unsigned char check_tag[16];
    unsigned char i;
    int diff;

    CCM_VALIDATE_RET( ctx != NULL );
    CCM_VALIDATE_RET( iv != NULL );
    CCM_VALIDATE_RET( add_len == 0 || add != NULL );
    CCM_VALIDATE_RET( length == 0 || input != NULL );
    CCM_VALIDATE_RET( length == 0 || output != NULL );
    CCM_VALIDATE_RET( tag_len == 0 || tag != NULL );

    if( ( ret = ccm_auth_crypt( ctx, CCM_DECRYPT, length,
                                iv, iv_len, add, add_len,
                                input, output, check_tag, tag_len ) ) != 0 )
    {
        return( ret );
    }

    /* Check tag in "constant-time" */
    for( diff = 0, i = 0; i < tag_len; i++ )
        diff |= tag[i] ^ check_tag[i];

    if( diff != 0 )
    {
        mbedtls_platform_zeroize( output, length );
        return( MBEDTLS_ERR_CCM_AUTH_FAILED );
    }

    return( 0 );
}

int mbedtls_ccm_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len )
{
    CCM_VALIDATE_RET( ctx != NULL );
    CCM_VALIDATE_RET( iv != NULL );
    CCM_VALIDATE_RET( add_len == 0 || add != NULL );
    CCM_VALIDATE_RET( length == 0 || input != NULL );
    CCM_VALIDATE_RET( length == 0 || output != NULL );
    CCM_VALIDATE_RET( tag_len == 0 || tag != NULL );

    if( tag_len == 0 )
        return( MBEDTLS_ERR_CCM_BAD_INPUT );

    return( mbedtls_ccm_star_auth_decrypt( ctx, length, iv, iv_len, add,
                add_len, input, output, tag, tag_len ) );
}
#endif /* !MBEDTLS_CCM_ALT */

#if defined(MBEDTLS_SELF_TEST) && defined(MBEDTLS_AES_C)
/*
 * Examples 1 to 3 from SP800-38C Appendix C
 */

#define NB_TESTS 3
#define CCM_SELFTEST_PT_MAX_LEN 24
#define CCM_SELFTEST_CT_MAX_LEN 32
/*
 * The data is the same for all tests, only the used length changes
 */
static const unsigned char key_test_data[] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
};

static const unsigned char iv_test_data[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b
};

static const unsigned char ad_test_data[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13
};

static const unsigned char msg_test_data[CCM_SELFTEST_PT_MAX_LEN] = {
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
};

static const size_t iv_len_test_data [NB_TESTS] = { 7, 8,  12 };
static const size_t add_len_test_data[NB_TESTS] = { 8, 16, 20 };
static const size_t msg_len_test_data[NB_TESTS] = { 4, 16, 24 };
static const size_t tag_len_test_data[NB_TESTS] = { 4, 6,  8  };

static const unsigned char res_test_data[NB_TESTS][CCM_SELFTEST_CT_MAX_LEN] = {
    {   0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d },
    {   0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62,
        0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59, 0x3d,
        0x1f, 0xc6, 0x4f, 0xbf, 0xac, 0xcd },
    {   0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a,
        0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7, 0x0b,
        0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5,
        0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0, 0x99, 0x51 }
};

int mbedtls_ccm_self_test( int verbose )
{
    mbedtls_ccm_context ctx;
    /*
     * Some hardware accelerators require the input and output buffers
     * would be in RAM, because the flash is not accessible.
     * Use buffers on the stack to hold the test vectors data.
     */
    unsigned char plaintext[CCM_SELFTEST_PT_MAX_LEN];
    unsigned char ciphertext[CCM_SELFTEST_CT_MAX_LEN];
    size_t i;
    int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;

    mbedtls_ccm_init( &ctx );

    if( mbedtls_ccm_setkey( &ctx, MBEDTLS_CIPHER_ID_AES, key_test_data,
                            8 * sizeof key_test_data ) != 0 )
    {
        if( verbose != 0 )
            mbedtls_printf( "  CCM: setup failed" );

        return( 1 );
    }

    for( i = 0; i < NB_TESTS; i++ )
    {
        if( verbose != 0 )
            mbedtls_printf( "  CCM-AES #%u: ", (unsigned int) i + 1 );

        memset( plaintext, 0, CCM_SELFTEST_PT_MAX_LEN );
        memset( ciphertext, 0, CCM_SELFTEST_CT_MAX_LEN );
        memcpy( plaintext, msg_test_data, msg_len_test_data[i] );

        ret = mbedtls_ccm_encrypt_and_tag( &ctx, msg_len_test_data[i],
                                           iv_test_data, iv_len_test_data[i],
                                           ad_test_data, add_len_test_data[i],
                                           plaintext, ciphertext,
                                           ciphertext + msg_len_test_data[i],
                                           tag_len_test_data[i] );

        if( ret != 0 ||
            memcmp( ciphertext, res_test_data[i],
                    msg_len_test_data[i] + tag_len_test_data[i] ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            return( 1 );
        }
        memset( plaintext, 0, CCM_SELFTEST_PT_MAX_LEN );

        ret = mbedtls_ccm_auth_decrypt( &ctx, msg_len_test_data[i],
                                        iv_test_data, iv_len_test_data[i],
                                        ad_test_data, add_len_test_data[i],
                                        ciphertext, plaintext,
                                        ciphertext + msg_len_test_data[i],
                                        tag_len_test_data[i] );

        if( ret != 0 ||
            memcmp( plaintext, msg_test_data, msg_len_test_data[i] ) != 0 )
        {
            if( verbose != 0 )
                mbedtls_printf( "failed\n" );

            return( 1 );
        }

        if( verbose != 0 )
            mbedtls_printf( "passed\n" );
    }

    mbedtls_ccm_free( &ctx );

    if( verbose != 0 )
        mbedtls_printf( "\n" );

    return( 0 );
}

#endif /* MBEDTLS_SELF_TEST && MBEDTLS_AES_C */

#endif /* MBEDTLS_CCM_C */
