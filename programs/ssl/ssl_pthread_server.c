/*
 *  SSL server demonstration program using pthread for handling multiple
 *  clients.
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

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_fprintf      fprintf
#define mbedtls_printf       printf
#define mbedtls_snprintf     snprintf
#define mbedtls_calloc       calloc
#define mbedtls_free         free
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_CERTS_C) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_SSL_TLS_C) || \
    !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_NET_C) || \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_CTR_DRBG_C) || \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_THREADING_C) || !defined(MBEDTLS_THREADING_PTHREAD) || \
    !defined(MBEDTLS_PEM_PARSE_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_CERTS_C and/or "
                   "MBEDTLS_ENTROPY_C and/or MBEDTLS_SSL_TLS_C and/or "
                   "MBEDTLS_SSL_SRV_C and/or MBEDTLS_NET_C and/or "
                   "MBEDTLS_RSA_C and/or MBEDTLS_CTR_DRBG_C and/or "
                   "MBEDTLS_X509_CRT_PARSE_C and/or MBEDTLS_THREADING_C and/or "
                   "MBEDTLS_THREADING_PTHREAD and/or MBEDTLS_PEM_PARSE_C not "
                   "defined.\n");
    return( MBEDTLS_EXIT_FAILURE );
}
#else

#include <stdlib.h>
#include <string.h>
#include <signal.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include "mbedtls/memory_buffer_alloc.h"
#endif

#define HTTP_RESPONSE                                    \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

#define DEFAULT_MAX_NUM_THREADS          5
#define DEFAULT_CTR_DRBG_SEED_DATA       "ssl_pthread_server"

#define USAGE_MESSAGE                            \
    "\n usage: ssl_pthread_server param=<>...\n" \
    "\n acceptable parameters:\n"                \
    "   max_threads=%%d         default:5\n"

#define LOG_STDOUT( level, str )                      \
    log_msg( stdout, level, __FILE__, __LINE__, str )
#define LOG_STDERR( level, str )                      \
    log_msg( stderr, level, __FILE__, __LINE__, str )

typedef enum {
    CLIENT_THREAD_STATUS_EXIT_SUCCESS = 0,
    CLIENT_THREAD_STATUS_EXIT_FAILURE,
    CLIENT_THREAD_STATUS_ACTIVE,
    CLIENT_THREAD_STATUS_NONE
} client_status;

typedef enum {
    THREAD_REQUEST_NONE = 0,
    THREAD_REQUEST_TERMINATE
} thread_request;

typedef struct {
    /* Client private data */
    mbedtls_net_context client_ctx;
    pthread_t pthread_ctx;
    const mbedtls_ssl_config *ssl_config;
    int thread_id;

    /* Client shared data with server */
    client_status status;
} client_thread_context;

typedef struct {
    int max_threads;
} cmdline_options;

typedef struct {
    int failed_clients;
    int success_clients;
    thread_request req;
    int thread_id;
} server_thread_context;

mbedtls_threading_mutex_t log_mutex;
server_thread_context server_thread;
pthread_key_t id_key;

static void log_msg( void *ctx, int level, const char *file, int line,
                     const char *str )
{
    int *thread_id = (int *)pthread_getspecific( id_key );

    mbedtls_mutex_lock( &log_mutex );

    ((void) level);

    if( thread_id != NULL )
        mbedtls_fprintf( (FILE *)ctx, "%s:%04d: [ #%d ] %s", file, line,
                         *thread_id, str );
    else
        mbedtls_fprintf( (FILE *)ctx, "%s:%04d: [ #?? ] %s", file, line,
                         str );
    fflush( (FILE *)ctx );

    mbedtls_mutex_unlock( &log_mutex );
}

static void termination_handler( int signum )
{
    char buf[1024];

    switch( signum )
    {
        case SIGTERM:
            mbedtls_snprintf( buf, sizeof( buf ),
                              "Received signal SIGTERM. Terminating, "
                              "please wait...\n" );
            server_thread.req = THREAD_REQUEST_TERMINATE;
            break;
        default:
            mbedtls_snprintf( buf, sizeof( buf ),
                              "Ignoring received signal %d\n", signum );
            break;
    }
    LOG_STDOUT( 0, buf );
}

static void *run_client( void *args )
{
    client_thread_context *client_thread = (client_thread_context *)args;
    mbedtls_net_context *client_ctx = &client_thread->client_ctx;
    mbedtls_ssl_context ssl;
    char log_buf[2048];
    unsigned char buf[1024];
    int len, ret;

    /* Make sure memory references are valid. */
    mbedtls_ssl_init( &ssl );

    ret = pthread_setspecific( id_key, &client_thread->thread_id );
    if( ret != 0 )
    {
        mbedtls_snprintf( log_buf, sizeof( log_buf ),
                          "failed\n  !  pthread_setspecific returned 0x%d\n",
                          ret );
        LOG_STDERR( 0, log_buf );
        goto exit;
    }

    LOG_STDOUT( 0, "Setting up SSL/TLS data\n" );

    /* Get the SSL context ready. */
    if( ( ret = mbedtls_ssl_setup( &ssl, client_thread->ssl_config ) ) != 0 )
    {
        mbedtls_snprintf( log_buf, sizeof( log_buf ),
                          "failed\n  !  mbedtls_ssl_setup returned -0x%04x\n",
                          -ret );
        LOG_STDERR( 0, log_buf );
        goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, client_ctx, mbedtls_net_send, mbedtls_net_recv,
                         NULL );

    /* Handshake */
    LOG_STDOUT( 0, "Performing the SSL/TLS handshake\n" );

    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_snprintf( log_buf, sizeof( log_buf ),
                              "failed\n  !  mbedtls_ssl_handshake returned "
                              "-0x%04x\n", -ret );
            LOG_STDERR( 0, log_buf );
            goto exit;
        }
    }

    LOG_STDOUT( 0, "SSL/TLS handshake ok\n" );

    /* Read the HTTP Request */
    LOG_STDOUT( 0, "< Read from client\n" );

    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0x00, sizeof( buf ) );
        ret = mbedtls_ssl_read( &ssl, buf, len );

        if ( ret == MBEDTLS_ERR_SSL_WANT_READ ||
             ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;
        else if ( ret <= 0 )
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    LOG_STDERR( 0, "Connection was closed gracefully\n" );
                    goto exit;
                case MBEDTLS_ERR_NET_CONN_RESET:
                    LOG_STDERR( 0, "Connection was reset by peer\n" );
                    goto exit;
                default:
                    mbedtls_snprintf( log_buf, sizeof( log_buf ),
                                      "failed\n  !  mbedtls_ssl_read returned "
                                      "-0x%04x\n", -ret );
                    LOG_STDERR( 0, log_buf );
                    goto exit;
            }

        len = ret;
        mbedtls_snprintf( log_buf, sizeof( log_buf ),
                          "%d bytes read\n=====\n%s\n=====\n", len,
                          (char *)buf );
        LOG_STDOUT( 0, log_buf );

        if( ret > 0 )
            break;
    }
    while( 1 );

    /* Write the 200 Response */
    LOG_STDOUT( 0, "> Write to client\n" );

    len = mbedtls_snprintf( (char *)buf, sizeof( buf ), HTTP_RESPONSE,
                            mbedtls_ssl_get_ciphersuite( &ssl ) );

    while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret == MBEDTLS_ERR_NET_CONN_RESET )
        {
            LOG_STDERR( 0, "failed\n  !  peer closed connection\n" );
            goto exit;
        }
        else if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
                 ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_snprintf( log_buf, sizeof( log_buf ),
                              "failed\n  !  mbedtls_ssl_write returned "
                              "-0x%04x\n", ret );
            LOG_STDERR( 0, log_buf );
            goto exit;
        }
    }

    len = ret;
    mbedtls_snprintf( log_buf, sizeof( log_buf ),
                      "%d bytes written\n=====\n%s\n=====\n", len,
                      (char *)buf );
    LOG_STDOUT( 0, log_buf );

    /* Close the connection. */
    LOG_STDOUT( 0, "Closing the connection\n" );

    while( ( ret = mbedtls_ssl_close_notify( &ssl ) ) < 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            mbedtls_snprintf( log_buf, sizeof( log_buf ),
                              "failed\n  !  mbedtls_ssl_close_notify returned "
                              "-0x%04x\n", ret );
            goto exit;
        }
    }

    LOG_STDOUT( 0, "Close connection ok\n" );

    ret = 0;

exit:
    mbedtls_net_free( client_ctx );
    mbedtls_ssl_free( &ssl );

    if( ret != 0 )
        client_thread->status = CLIENT_THREAD_STATUS_EXIT_FAILURE;
    else
        client_thread->status = CLIENT_THREAD_STATUS_EXIT_SUCCESS;

    return( NULL );
}

static int thread_create( client_thread_context *client_threads,
                          size_t num_clients, mbedtls_net_context *client_ctx )
{
    int i = 0;

    /* Find inactive or finished slot. */
    while( 1 )
    {
        if( client_threads[i].status == CLIENT_THREAD_STATUS_EXIT_SUCCESS )
        {
            server_thread.success_clients++;
            break;
        }
        else if( client_threads[i].status == CLIENT_THREAD_STATUS_EXIT_FAILURE )
        {
            server_thread.failed_clients++;
            break;
        }
        else if( client_threads[i].status == CLIENT_THREAD_STATUS_NONE )
            break;

        i = ( i + 1 ) % num_clients;
    }

    LOG_STDOUT( 0, "Preparing new thread context\n" );

    if( client_threads[i].status != CLIENT_THREAD_STATUS_NONE )
        pthread_join( client_threads[i].pthread_ctx, NULL );

    client_threads[i].status = CLIENT_THREAD_STATUS_ACTIVE;
    memcpy( &client_threads[i].client_ctx, client_ctx,
            sizeof( mbedtls_net_context ) );

    return pthread_create( &client_threads[i].pthread_ctx, NULL, run_client,
                           &client_threads[i] );

}

static void terminate_client_threads( client_thread_context *client_threads,
                                      size_t num_clients )
{
    size_t i;

    for( i = 0; i < num_clients; i++ )
    {
        if( client_threads[i].status != CLIENT_THREAD_STATUS_NONE )
            pthread_join( client_threads[i].pthread_ctx, NULL );

        switch( client_threads[i].status )
        {
            case CLIENT_THREAD_STATUS_EXIT_SUCCESS:
                server_thread.success_clients++;
                break;
            case CLIENT_THREAD_STATUS_EXIT_FAILURE:
                server_thread.failed_clients++;
                break;
            default:
                break;
        }
    }
}

static int run_server( const cmdline_options *opts )
{
    int ret = -1, i;
    char log_buf[1024];
    client_thread_context *client_threads;
    mbedtls_net_context listen_ctx;
    mbedtls_net_context client_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cachain;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[100000];
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_init( alloc_buf, sizeof(alloc_buf) );
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif

    mbedtls_x509_crt_init( &srvcert );
    mbedtls_x509_crt_init( &cachain );

    mbedtls_ssl_config_init( &conf );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_net_init( &listen_ctx );
    mbedtls_net_init( &client_ctx );

    mbedtls_mutex_init( &log_mutex );

    /* Only a single entropy source is used in all threads. */
    mbedtls_entropy_init( &entropy );

    memset( &server_thread, 0x00, sizeof( server_thread_context ) );

    /* Set the thread id for easier debugging */
    if( (ret = pthread_key_create( &id_key, NULL ) ) != 0 )
    {
        mbedtls_printf( " failed\n  !  pthread_key_create returned %d\n\n",
                        ret );
        goto exit;
    }
    ret = pthread_setspecific( id_key, &server_thread.thread_id );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  pthread_setspecific returned %d\n\n",
                        ret );
        goto exit;
    }

    client_threads = mbedtls_calloc( opts->max_threads,
                                     sizeof( client_thread_context ) );
    if( ( ret = !client_threads ) )
    {
        mbedtls_printf( "  . Failed to allocate client threads...\n" );
        goto exit ;
    }
    for( i = 0; i < opts->max_threads; i++ )
    {
        client_threads[i].ssl_config = &conf;
        client_threads[i].status = CLIENT_THREAD_STATUS_NONE;
        client_threads[i].thread_id = i + 1;
    }

    /* Setup signal handler to be able to gracefully terminate. */
    if( ( ret = ( signal( SIGTERM, termination_handler ) == SIG_ERR ) ) )
    {
        mbedtls_printf( " failed\n  !  signal returned SIG_ERROR\n");
        goto dealloc;
    }

    mbedtls_printf("  . Loading the server cert. and key..." );
    fflush( stdout );

    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse( &srvcert,
                                  (const unsigned char *)mbedtls_test_srv_crt,
                                  mbedtls_test_srv_crt_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n",
                        ret );
        goto dealloc;
    }

    ret = mbedtls_x509_crt_parse( &cachain,
                                  (const unsigned char *)mbedtls_test_cas_pem,
                                  mbedtls_test_cas_pem_len );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n",
                        ret );
        goto dealloc;
    }

    mbedtls_pk_init( &pkey );
    ret =  mbedtls_pk_parse_key( &pkey,
                                 (const unsigned char *)mbedtls_test_srv_key,
                                 mbedtls_test_srv_key_len, NULL, 0 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n",
                        ret );
        goto dealloc;
    }

    mbedtls_printf( " ok\n" );

    /* Seed the random number generator. */
    mbedtls_printf( "  . Seeding the random number generator..." );

    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                                 (const unsigned char *)DEFAULT_CTR_DRBG_SEED_DATA,
                                 strlen( DEFAULT_CTR_DRBG_SEED_DATA ) );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_ctr_drbg_seed returned "
                        "-0x%04x\n", -ret );
        goto dealloc;
    }

    mbedtls_printf( " ok\n" );

    /* Prepare SSL configuration. */
    mbedtls_printf( "  . Setting up the SSL data...." );

    ret = mbedtls_ssl_config_defaults( &conf, MBEDTLS_SSL_IS_SERVER,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_ssl_config_defaults returned "
                        "-0x%04x\n", -ret );
        goto dealloc;
    }

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, log_msg, stdout );

    /*
     * mbedtls_ssl_cache_get() and mbedtls_ssl_cache_set() are thread-safe if
     * MBEDTLS_THREADING_C is set.
     */
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache( &conf, &cache, mbedtls_ssl_cache_get,
                                    mbedtls_ssl_cache_set );
#endif

    mbedtls_ssl_conf_ca_chain( &conf, &cachain, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &srvcert, &pkey ) ) != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_ssl_conf_own_cert returned "
                        "%d\n\n", ret );
        goto dealloc;
    }

    mbedtls_printf( " ok\n" );

    /* Setup the listening TCP socket. */
    mbedtls_printf( "  . Bind on https://localhost:4433/ ..." );
    fflush( stdout );

    ret = mbedtls_net_bind( &listen_ctx, NULL, "4433", MBEDTLS_NET_PROTO_TCP );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_net_bind returned %d\n\n", ret );
        goto dealloc;
    }

    /*
     * Configure listening TCP socket as non-blocking so that we can react
     * when a signal is received
     */
    if( ( ret = mbedtls_net_set_nonblock( &listen_ctx ) ) != 0 )
    {
        mbedtls_printf( " failed\n  !  mbedtls_net_set_nonblock returned "
                        "-0x%04x\n", ret );
        goto dealloc;
    }

    mbedtls_printf( " ok\n" );

    /* Wait for a remote connection */
    mbedtls_printf( "  . Waiting for remote connections...\n" );

    while( server_thread.req != THREAD_REQUEST_TERMINATE )
    {
        ret = mbedtls_net_accept( &listen_ctx, &client_ctx, NULL, 0, NULL );
        if( ret == MBEDTLS_ERR_SSL_WANT_READ )
        {
            /*
             * Currently there is no client waiting, mbedtls_net_accept()
             * would block.
             */
            ret = 0;
            continue;
        }
        else if( ret  != 0 )
        {
            mbedtls_snprintf( log_buf, sizeof( log_buf ), " failed: "
                              "mbedtls_net_accept returned -0x%04x\n", ret );
            LOG_STDERR( 0, log_buf );
            goto dealloc;
        }

        LOG_STDOUT( 0, "Accepted remote connection, creating new thread" );

        ret = thread_create( client_threads, (size_t)opts->max_threads,
                             &client_ctx );
        if( ret != 0 )
        {
            mbedtls_snprintf( log_buf, sizeof( log_buf ),
                              "  failed: thread_create returned %d\n", ret );
            LOG_STDERR( 0, log_buf );
            mbedtls_net_free( &client_ctx );
        }
    }

dealloc:
    terminate_client_threads( client_threads, (size_t)opts->max_threads );
    mbedtls_free( client_threads );

exit:
    mbedtls_x509_crt_free( &srvcert );
    mbedtls_x509_crt_free( &cachain );

    mbedtls_pk_free( &pkey );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free( &cache );
#endif
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_ssl_config_free( &conf );

    mbedtls_net_free( &listen_ctx );
    mbedtls_net_free( &client_ctx );

    mbedtls_mutex_free( &log_mutex );

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_free();
#endif

    mbedtls_printf( "  . Terminating server...\n" );
    mbedtls_printf( "  . Run summary...\n"
                    "        Total connections: %d\n"
                    "        Failed connections: %d\n"
                    "        Successful connections: %d\n",
                    server_thread.failed_clients +
                    server_thread.success_clients,
                    server_thread.failed_clients,
                    server_thread.success_clients );

    /* Fail if any connection resulted in a failure. */
    if( server_thread.failed_clients )
        ret = -1;

    return( ret );
}

static int parse_cmdline_arguments( cmdline_options *opts, int argc,
                                     char * argv[] )
{
    int i;
    int ret = -1;

    memset( opts, 0x00, sizeof( cmdline_options ) );

    /* Set defaults. */
    opts->max_threads = DEFAULT_MAX_NUM_THREADS;

    for( i = 1; i < argc; i++ )
    {
        char *arg_key = argv[i];
        char *arg_val = strchr( arg_key, '=' );
        if( !arg_val )
        {
            mbedtls_printf( " failed\n  !  Could not parse arguments\n" );
            goto exit;
        }
        *arg_val++ = '\0';

        if( strcmp( arg_key, "max_threads" ) == 0 )
        {
            opts->max_threads = atoi( arg_val );
            if( opts->max_threads <= 0 )
            {
                mbedtls_printf( " failed\n  !  max_threads must be a positive "
                                "integer greater than 0\n");
                goto exit;
            }
        }
        else
        {
            mbedtls_printf( " failed\n  !  Unrecognised argument '%s'\n",
                            arg_key );
            goto exit;
        }
    }

    ret = 0;

exit:
    if( ret != 0 )
        mbedtls_printf( USAGE_MESSAGE );

    return( ret );
}

int main( int argc, char* argv[] )
{
    int exit_code = MBEDTLS_EXIT_FAILURE;
    cmdline_options opts;

    if ( parse_cmdline_arguments( &opts, argc, argv ) != 0 )
        goto exit;

    if ( run_server(&opts) != 0 )
        goto exit;

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#if defined(_WIN32)
    mbedtls_printf( "  Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( exit_code );
}

#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_CERTS_C && MBEDTLS_ENTROPY_C &&
        * MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&
        * MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_THREADING_C &&
        * MBEDTLS_THREADING_PTHREAD && MBEDTLS_PEM_PARSE_C
        */
