/*
 *  TCP/IP or UDP/IP networking function stubs for offloading
 *
 *  This module implements the networking interface through stubs that
 *  serialize requests and replies. This way the network operation is
 *  offloaded, potentially to a differnt machine.
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

#if defined(MBEDTLS_NET_OFFLOAD_C)

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include "mbedtls/net_sockets.h"
#include "mbedtls/serialize.h"

static int mbedtls_serialize_pop_fd( int16_t *fd )
{
    uint16_t value;
    int ret;
    if( ( ret = mbedtls_serialize_pop_int16( &value ) ) != 0 )
        return( ret );
    *fd = (int16_t) value;
    return( 0 );
}

/*
 * Prepare for using the sockets interface
 */
static int net_prepare( void )
{
#if 0
    int getpid( void ) ;
    printf( "#### pid = %d ####\n", getpid( ) );
    (void) getchar( );
#endif
    return( 0 );
}

/*
 * Initialize a context
 */
void mbedtls_net_init( mbedtls_net_context *ctx )
{
    ctx->fd = -1;
}

static int mbedtls_net_socket( mbedtls_net_context *ctx, const char *addr,
                               const char *port, uint16_t proto_and_mode )
{
    int ret;
    size_t addr_len = strlen( addr );
    size_t port_len = strlen( port );

    if( ( ret = net_prepare() ) != 0 )
        return( ret );

    if( addr_len > MBEDTLS_SERIALIZE_MAX_STRING_LENGTH )
        return( MBEDTLS_ERR_SERIALIZE_UNSUPPORTED_INPUT );
    if( port_len > MBEDTLS_SERIALIZE_MAX_STRING_LENGTH )
        return( MBEDTLS_ERR_SERIALIZE_UNSUPPORTED_INPUT );

    if( ( ret = mbedtls_serialize_push_int16( proto_and_mode ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_push_buffer( port, port_len + 1 ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_push_buffer( addr, addr_len + 1 ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_SOCKET ) ) != 0 )
        return( ret );

    if( ( ret = mbedtls_serialize_pop_fd( &ctx->fd ) ) != 0 )
        return( ret );

    return( 0 );
}

/*
 * Initiate a TCP connection with host:port and the given protocol
 */
int mbedtls_net_connect( mbedtls_net_context *ctx,
                         const char *host, const char *port, int proto )
{
    return( mbedtls_net_socket( ctx, host, port, proto | MBEDTLS_SERIALIZE_SOCKET_CONNECT ) );
}

/*
 * Create a listening socket on bind_ip:port
 */
int mbedtls_net_bind( mbedtls_net_context *ctx,
                      const char *bind_ip, const char *port, int proto )
{
    return( mbedtls_net_socket( ctx, bind_ip, port, proto | MBEDTLS_SERIALIZE_SOCKET_BIND ) );
}

/*
 * Accept a connection from a remote client
 */
int mbedtls_net_accept( mbedtls_net_context *bind_ctx,
                        mbedtls_net_context *client_ctx,
                        void *client_ip, size_t buf_size, size_t *ip_len )
{
    int ret;
    if( buf_size > MBEDTLS_SERIALIZE_MAX_STRING_LENGTH )
        return( MBEDTLS_ERR_SERIALIZE_UNSUPPORTED_INPUT );
    if( ( ret = mbedtls_serialize_push_int32( buf_size ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_push_int16( bind_ctx->fd ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_ACCEPT ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_pop_fd( &bind_ctx->fd ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_pop_fd( &client_ctx->fd ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_pop_buffer( client_ip, buf_size, ip_len ) ) != 0 )
        return( ret );
    return( 0 );
}

/*
 * Set the socket blocking or non-blocking
 */
static int serialize_set_block( mbedtls_net_context *ctx, uint16_t mode )
{
    int ret;
    if( ( ret = mbedtls_serialize_push_int16( mode ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_push_int16( ctx->fd ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_SET_BLOCK ) ) != 0 )
        return( ret );
    return( 0 );
}

int mbedtls_net_set_block( mbedtls_net_context *ctx )
{
    return( serialize_set_block( ctx, MBEDTLS_SERIALIZE_BLOCK_BLOCK ) );
}

int mbedtls_net_set_nonblock( mbedtls_net_context *ctx )
{
    return( serialize_set_block( ctx, MBEDTLS_SERIALIZE_BLOCK_NONBLOCK ) );
}

/*
 * Portable usleep helper
 */
void mbedtls_net_usleep( unsigned long usec )
{
    int ret;
#if ULONG_MAX > 0xffffffff
    /* Truncate sleeps of more than about 1 hour and 11 minutes so that they
       fit in the parameter size. */
    if( usec > 0xffffffff )
        usec = 0xffffffff;
#endif
    if( ( ret = mbedtls_serialize_push_int32( usec ) ) != 0 )
        return;
    if( ( ret = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_USLEEP ) ) != 0 )
        return;
}

/*
 * Read at most 'len' characters, blocking for at most 'timeout' ms
 */
int mbedtls_net_recv_timeout( void *ctx_arg,
                              unsigned char *buf, size_t len,
                              uint32_t timeout )
{
    mbedtls_net_context *ctx = ctx_arg;
    int ret;
    size_t received_len;

    if( ctx->fd < 0 )
        return( MBEDTLS_ERR_NET_INVALID_CONTEXT );
    if( len > MBEDTLS_SERIALIZE_MAX_STRING_LENGTH || len > INT_MAX )
        return( MBEDTLS_ERR_SERIALIZE_UNSUPPORTED_INPUT );

    if( ( ret = mbedtls_serialize_push_int32( timeout ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_push_int32( len ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_push_int16( ctx->fd ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_RECV ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_pop_buffer( buf, len, &received_len ) ) != 0 )
        return( ret );

    return( received_len );
}

/*
 * Read at most 'len' characters
 */
int mbedtls_net_recv( void *ctx, unsigned char *buf, size_t len )
{
    return( mbedtls_net_recv_timeout( ctx, buf, len,
                                      MBEDTLS_SERIALIZE_TIMEOUT_INFINITE ) );
}

/*
 * Write at most 'len' characters
 */
int mbedtls_net_send( void *ctx_arg, const unsigned char *buf, size_t len )
{
    mbedtls_net_context *ctx = ctx_arg;
    int ret;
    uint32_t sent_len;

    if( ctx->fd < 0 )
        return( MBEDTLS_ERR_NET_INVALID_CONTEXT );
    if( len > MBEDTLS_SERIALIZE_MAX_STRING_LENGTH || len > INT_MAX )
        return( MBEDTLS_ERR_SERIALIZE_UNSUPPORTED_INPUT );

    if( ( ret = mbedtls_serialize_push_buffer( buf, len ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_push_int16( ctx->fd ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_SEND ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_pop_int32( &sent_len ) ) != 0 )
        return( ret );

    return( sent_len );
}

/*
 * Gracefully close the connection
 */
void mbedtls_net_free( mbedtls_net_context *ctx )
{
    int ret;
    if( ctx->fd == -1 )
        return;

    if( ( ret = mbedtls_serialize_push_int16( ctx->fd ) ) != 0 )
        return;
    if( ( ret = mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_SHUTDOWN ) ) != 0 )
        return;

    ctx->fd = -1;
}

#endif /* MBEDTLS_NET_C */
