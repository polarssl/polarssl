/*
 *  Simple serialization framework
 *
 *  Copyright (C) 2017, ARM Limited, All Rights Reserved
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

/*
 * Serialization format description
 *
 * All integers are encoded as a stream of octets in big-endian format.
 *
 * A serialization packet consists of a 4-byte header followed by
 * variable-sized content. The first byte of the header is the packet
 * type:
 *   0x45 ('E') execute   target->host  Execute a function
 *   0x50 ('P') push      target->host  Push an input for the next execution
 *   0x72 ('r') result    host->target  Return an output from the last execution
 *
 * The host maintains a stack of parameters and results. Stack
 * elements are byte arrays. This stack is initially empty. The "push"
 * command transmits one item from the target to the host and pushes
 * this item to the stack. The "execute" command requests that the host
 * perform an action, taking parameters from the stack and sending outputs
 * back to the target.
 *
 * Format of a push packet (by byte offset):
 *   0..0       0x50    Type identifier
 *   1..3       size    Number of bytes to follow
 *   4..3+size  data    Content of the byte array
 *
 * Format of an execute packet (by byte offset):
 *   0..0       0x45    Type identifier
 *   1..3       func    Function identifier
 * Function identifiers are conventionally arranged as follows:
 *   bits 23-16   Library code (1=sockets)
 *   bits 15-8    Function identifier inside the library
 *   bits 7-4     Number of parameters
 *   bits 3-0     Number of results after status code on success
 *
 * Format of a result packet (by byte offset):
 *   0..0       0x72    Type identifier
 *   1..3       size    Number of bytes to follow
 *   4..3+size  data    Content of the byte array
 *
 * All functions currently follow the following result status
 * convention. The first result is a status code (MBEDTLS_ERR_xxx
 * constant). If this is 0 then more results follow. If this is
 * nonzero then it is the only result.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include "mbedtls/serialize.h"

#if defined(MBEDTLS_SERIALIZE_C)

#if defined(MBEDTLS_SERIALIZE_FORK_FRONTEND_C)
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

static int serialize_write_fd = -1;
static int serialize_read_fd = -1;

static int host_pid;

static void kill_host_frontend( void )
{
    kill( host_pid, SIGHUP );
}

static void relay_signal( int signum )
{
    /* Let the atexit function kill the frontend */
    exit( signum + 128 );
}

#define CHECK( expr, var )                      \
    do {                                        \
        var = ( expr );                         \
        if( var < 0 )                           \
        {                                       \
            perror( #expr );                    \
            goto cleanup;                       \
        }                                       \
    } while( 0 )
static int mbedtls_serialize_prepare( void )
{
    int ret;
    int host_to_target[2] = {-1, -1}, target_to_host[2] = {-1, -1};
    const char *const frontend_path[] = {
        "programs/host/frontend",
        "../programs/host/frontend",
        "../../programs/host/frontend",
    };
    const char *frontend_exe = NULL;
    size_t i;

    /* Look for frontend program */
    for( i = 0; i < sizeof( frontend_path ) / sizeof( *frontend_path ); i++ )
    {
        if( access( frontend_path[i], F_OK ) >= 0 )
        {
            frontend_exe = frontend_path[i];
            break;
        }
    }
    if( frontend_exe == NULL )
    {
        fprintf( stderr, "Host frontend executable for offloading not found!\n" );
        return( -1 );
    }

    /* Prepare the plumbing */
    CHECK( pipe( host_to_target ), ret );
    CHECK( pipe( target_to_host ), ret );
    CHECK( signal( SIGTERM, relay_signal ) == SIG_ERR ? -1 : 0 , ret );
    CHECK( fork( ), host_pid );

    if( host_pid == 0 )
    {
        /* Child process (host */
        char arg1[10], arg2[10];
        sprintf( arg1, "%d", target_to_host[0] );
        sprintf( arg2, "%d", host_to_target[1] );

        /* Close peer ends of the pipe */
        close( host_to_target[0] );
        close( target_to_host[1] );

        /* Pass pipe rd/wr descriptors to child */
        execl( frontend_exe, frontend_exe, arg1, arg2, NULL );
        perror( frontend_exe );
        exit( 126 );
    }

    /* Parent process (target) */
    serialize_read_fd = host_to_target[0];
    close( host_to_target[1] );
    close( target_to_host[0] );
    serialize_write_fd = target_to_host[1];
    atexit( kill_host_frontend );

    return( 0 );
cleanup:
    if( host_to_target[0] >= 0 )
        close( host_to_target[0] );
    if( host_to_target[1] >= 0 )
        close( host_to_target[1] );
    if( target_to_host[0] >= 0 )
        close( target_to_host[0] );
    if( target_to_host[1] >= 0 )
        close( target_to_host[1] );
    return( -1 );
}
#undef CHECK

static int mbedtls_serialize_write( const uint8_t *buffer, size_t length )
{
    ssize_t result;
    if( serialize_write_fd == -1 )
        if( mbedtls_serialize_prepare( ) != 0 )
            return( MBEDTLS_ERR_SERIALIZE_SEND );
    do {
        result = write( serialize_write_fd, buffer, length );
        /* This channel should never reach EOF under the current simplistic
           design, so error out on EOF. */
        if( result <= 0 )
        {
            return( MBEDTLS_ERR_SERIALIZE_SEND );
        }
        length -= result;
        buffer += result;
    } while( length > 0 );
    return( 0 );
}

static int mbedtls_serialize_read( uint8_t *buffer, size_t length )
{
    ssize_t result;
    do {
        result = read( serialize_read_fd, buffer, length );

        /* This channel should never reach EOF under the current simplistic
           design, so error out on EOF. */
        if( result <= 0 )
        {
            return( MBEDTLS_ERR_SERIALIZE_RECEIVE );
        }
        length -= result;
        buffer += result;
    } while( length > 0 );
    return( 0 );
}

#endif /* MBEDTLS_SERIALIZE_FORK_FRONTEND_C */

int mbedtls_serialize_push_buffer( const void *buffer, size_t length )
{
    int ret;
    uint8_t header[4];
    if( length > MBEDTLS_SERIALIZE_MAX_STRING_LENGTH )
        return( MBEDTLS_ERR_SERIALIZE_BAD_INPUT );

    header[0] = MBEDTLS_SERIALIZE_TYPE_PUSH;
    header[1] = ( length >> 16 ) & 0xff;
    header[2] = ( length >> 8 ) & 0xff;
    header[3] = length & 0xff;

    if( ( ret = mbedtls_serialize_write( header, sizeof( header ) ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_write( buffer, length ) ) != 0 )
        return( ret );
    return( 0 );
}

int mbedtls_serialize_push_int16( uint16_t value )
{
    uint8_t buffer[2];
    buffer[0] = ( value >> 8 ) & 0xff;
    buffer[1] = value & 0xff;
    return( mbedtls_serialize_push_buffer( buffer, sizeof( buffer ) ) );
}

int mbedtls_serialize_push_int32( uint32_t value )
{
    uint8_t buffer[4];
    buffer[0] = ( value >> 24 ) & 0xff;
    buffer[1] = ( value >> 16 ) & 0xff;
    buffer[2] = ( value >> 8 ) & 0xff;
    buffer[3] = value & 0xff;
    return( mbedtls_serialize_push_buffer( buffer, sizeof( buffer ) ) );
}

int mbedtls_serialize_execute( uint32_t command )
{
    int ret;
    uint8_t buffer[4];
    buffer[0] = MBEDTLS_SERIALIZE_TYPE_EXECUTE;
    buffer[1] = ( command >> 16 ) & 0xff;
    buffer[2] = ( command >> 8 ) & 0xff;
    buffer[3] = command & 0xff;
    if( ( ret = mbedtls_serialize_write( buffer, sizeof( buffer ) ) ) != 0 )
        return( ret );
    if( ( ret = mbedtls_serialize_read( buffer, sizeof( buffer ) ) ) != 0 )
        return( ret );
    if( ! ( buffer[0] == MBEDTLS_SERIALIZE_TYPE_RESULT &&
            buffer[1] == 0 && buffer[2] == 0 && buffer[3] == 4 ) )
        return( MBEDTLS_ERR_SERIALIZE_BAD_OUTPUT );
    if( ( ret = mbedtls_serialize_read( buffer, sizeof( buffer ) ) ) != 0 )
        return( ret );
    return( buffer[0] << 24 | buffer[1] << 16 | buffer[2] << 8 | buffer[3] );
}

int mbedtls_serialize_pop_buffer( void *buffer, size_t max_length, size_t *actual_length )
{
    int ret;
    uint8_t header[4];
    if( ( ret = mbedtls_serialize_read( header, sizeof( header ) ) ) != 0 )
        return( ret );
    *actual_length = header[1] << 16 | header[2] << 8 | header[3];
    if( *actual_length > max_length )
        return( MBEDTLS_ERR_SERIALIZE_BAD_OUTPUT );
    if( ( ret = mbedtls_serialize_read( buffer, *actual_length ) ) != 0 )
        return( ret );
    return( 0 );
}

int mbedtls_serialize_pop_int16( uint16_t *value )
{
    int ret;
    uint8_t buffer[2];
    size_t length;
    if( ( ret = mbedtls_serialize_pop_buffer( buffer, sizeof( buffer ),
                                              &length ) ) != 0 )
        return( ret );
    if( length != sizeof( buffer ) )
        return( MBEDTLS_ERR_SERIALIZE_BAD_OUTPUT );
    *value = buffer[0] << 8 | buffer[1];
    return( 0 );
}

int mbedtls_serialize_pop_int32( uint32_t *value )
{
    int ret;
    uint8_t buffer[4];
    size_t length;
    if( ( ret = mbedtls_serialize_pop_buffer( buffer, sizeof( buffer ),
                                              &length ) ) != 0 )
        return( ret );
    if( length != sizeof( buffer ) )
        return( MBEDTLS_ERR_SERIALIZE_BAD_OUTPUT );
    *value = ( buffer[0] << 24 ) | ( buffer[1] << 16 ) | ( buffer[2] << 8 ) | buffer[3];
    return( 0 );
}

void mbedtls_serialize_exit( int exitcode )
{
    if( mbedtls_serialize_push_int32( exitcode ) != 0 )
        return;
    mbedtls_serialize_execute( MBEDTLS_SERIALIZE_FUNCTION_EXIT );
}


#endif /* MBEDTLS_SERIALIZE_C */
