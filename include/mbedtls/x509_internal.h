/**
 * \file x509_internal.h
 *
 * \brief Internal X.509 functions
 */
/*
 *  Copyright (C) 2006-2019, ARM Limited, All Rights Reserved
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
 *  This file is part of Mbed TLS (https://tls.mbed.org)
 *
 */
#ifndef MBEDTLS_X509_INTERNAL_H
#define MBEDTLS_X509_INTERNAL_H

#include "mbedtls/x509.h"
#include "mbedtls/threading.h"

/* Internal structure used for caching parsed data from an X.509 CRT. */

struct mbedtls_x509_crt;
struct mbedtls_pk_context;
struct mbedtls_x509_crt_frame;
#define MBEDTLS_X509_CACHE_PK_READERS_MAX    ((uint32_t) -1)
#define MBEDTLS_X509_CACHE_FRAME_READERS_MAX ((uint32_t) -1)
typedef struct mbedtls_x509_crt_cache
{
#if !defined(MBEDTLS_X509_ALWAYS_FLUSH) || \
    defined(MBEDTLS_THREADING_C)
    uint32_t frame_readers;
    uint32_t pk_readers;
#endif /* !MBEDTLS_X509_ALWAYS_FLUSH || MBEDTLS_THREADING_C */
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t frame_mutex;
    mbedtls_threading_mutex_t pk_mutex;
#endif
    mbedtls_x509_buf_raw pk_raw;
    struct mbedtls_x509_crt_frame *frame;
    struct mbedtls_pk_context *pk;
} mbedtls_x509_crt_cache;

/* Internal X.509 CRT cache handling functions. */

int mbedtls_x509_crt_flush_cache_frame( struct mbedtls_x509_crt const *crt );
int mbedtls_x509_crt_flush_cache_pk( struct mbedtls_x509_crt const *crt );

int mbedtls_x509_crt_cache_provide_frame( struct mbedtls_x509_crt const *crt );
int mbedtls_x509_crt_cache_provide_pk( struct mbedtls_x509_crt const *crt );

/* Uncategorized internal X.509 functions */

int mbedtls_x509_get_name( unsigned char *p, size_t len,
                           mbedtls_x509_name *cur );
int mbedtls_x509_get_alg_null( unsigned char **p, const unsigned char *end,
                       mbedtls_x509_buf *alg );
int mbedtls_x509_get_alg( unsigned char **p, const unsigned char *end,
                  mbedtls_x509_buf *alg, mbedtls_x509_buf *params );
#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
int mbedtls_x509_get_rsassa_pss_params( const mbedtls_x509_buf *params,
                                mbedtls_md_type_t *md_alg, mbedtls_md_type_t *mgf_md,
                                int *salt_len );
#endif
int mbedtls_x509_get_sig( unsigned char **p, const unsigned char *end, mbedtls_x509_buf *sig );
int mbedtls_x509_get_sig_alg_raw( unsigned char **p, unsigned char const *end,
                                  mbedtls_md_type_t *md_alg,
                                  mbedtls_pk_type_t *pk_alg,
                                  void **sig_opts );
int mbedtls_x509_get_sig_alg( const mbedtls_x509_buf *sig_oid, const mbedtls_x509_buf *sig_params,
                      mbedtls_md_type_t *md_alg, mbedtls_pk_type_t *pk_alg,
                      void **sig_opts );
int mbedtls_x509_get_time( unsigned char **p, const unsigned char *end,
                   mbedtls_x509_time *t );
int mbedtls_x509_get_serial( unsigned char **p, const unsigned char *end,
                     mbedtls_x509_buf *serial );
int mbedtls_x509_name_cmp_raw( mbedtls_x509_buf_raw const *a,
                               mbedtls_x509_buf_raw const *b,
                               int (*check)( void *ctx,
                                             mbedtls_x509_buf *oid,
                                             mbedtls_x509_buf *val,
                                             int next_merged ),
                               void *check_ctx );
int mbedtls_x509_memcasecmp( const void *s1, const void *s2,
                             size_t len1, size_t len2 );
int mbedtls_x509_get_ext( unsigned char **p, const unsigned char *end,
                  mbedtls_x509_buf *ext, int tag );
int mbedtls_x509_sig_alg_gets( char *buf, size_t size,
                       mbedtls_pk_type_t pk_alg, mbedtls_md_type_t md_alg,
                       const void *sig_opts );
int mbedtls_x509_key_size_helper( char *buf, size_t buf_size, const char *name );
int mbedtls_x509_string_to_names( mbedtls_asn1_named_data **head, const char *name );
int mbedtls_x509_set_extension( mbedtls_asn1_named_data **head, const char *oid, size_t oid_len,
                        int critical, const unsigned char *val,
                        size_t val_len );
int mbedtls_x509_write_extensions( unsigned char **p, unsigned char *start,
                           mbedtls_asn1_named_data *first );
int mbedtls_x509_write_names( unsigned char **p, unsigned char *start,
                      mbedtls_asn1_named_data *first );
int mbedtls_x509_write_sig( unsigned char **p, unsigned char *start,
                    const char *oid, size_t oid_len,
                    unsigned char *sig, size_t size );

#endif /* MBEDTLS_X509_INTERNAL_H */
