/**
 * \file serialize.h
 *
 * \brief Serializer for operating system functions
 *
 * \warning THIS IS AN UNSTABLE INTERFACE!
 *  The interfaces in this module are internal to the mbed TLS project. They
 *  are meant for testing purposes only. They may change at any time.
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

#ifndef MBEDTLS_SERIALIZE_H
#define MBEDTLS_SERIALIZE_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


/** Maximum length of a serialized parameter. */
#define MBEDTLS_SERIALIZE_MAX_STRING_LENGTH 0xffffff

/** Offloaded function identifiers */
#define MBEDTLS_SERIALIZE_TYPE_PUSH     0x50 /**< T>H Push input parameter */
#define MBEDTLS_SERIALIZE_TYPE_EXECUTE  0x45 /**< T>H Execute function */
#define MBEDTLS_SERIALIZE_TYPE_RESULT   0x72 /**< H>T Output parameter */

#define MBEDTLS_SERIALIZE_FUNCTION_EXIT         0x000100 /**< exit the frontend */
#define MBEDTLS_SERIALIZE_FUNCTION_ECHO         0x000211 /**< echo input */
    /* in: data
       out: data */
#define MBEDTLS_SERIALIZE_FUNCTION_USLEEP       0x000310 /**< sleep */
    /* in: usec */
#define MBEDTLS_SERIALIZE_FUNCTION_SOCKET       0x010031 /**< bind or connect */
    /* in: string host, string port, int16 proto_and_mode
       out: int16 fd */
#define MBEDTLS_SERIALIZE_FUNCTION_ACCEPT       0x010123 /**< accept */
    /* in: int16 socket_fd, int32 buffer_size
       out: int16 bind_fd, int16 client_fd, string client_ip */
#define MBEDTLS_SERIALIZE_FUNCTION_SET_BLOCK    0x010220 /**< set_block or set_nonblock */
    /* in: int16 fd, int16 nonblock */
#define MBEDTLS_SERIALIZE_FUNCTION_RECV         0x010331 /**< recv or recv_timeout */
    /* in: int16 fd, int32 len, int32 timeout
       out: string data */
#define MBEDTLS_SERIALIZE_FUNCTION_SEND         0x010421 /**< send */
    /* in: int16 fd, string data
       out: int32 len */
#define MBEDTLS_SERIALIZE_FUNCTION_SHUTDOWN     0x010510 /**< shutdown (close socket) */
    /* in: int16 fd */
#define MBEDTLS_SERIALIZE_FUNCTION_FOPEN        0x020121 /**< open file */
    /* in: string file path
       in: string file open mode
       out: int32 file_id
    */
#define MBEDTLS_SERIALIZE_FUNCTION_FREAD        0x020221
    /* in: int32 file id
       in: uint32 read buffer size
       out: string read buffer & size
    */
#define MBEDTLS_SERIALIZE_FUNCTION_FGETS        0x020321
    /* in: int32 file id
       in: uint32 read buffer size
       out: string read buffer & size
    */
#define MBEDTLS_SERIALIZE_FUNCTION_FWRITE       0x020421
    /* in: int32 file id
       in: string write buffer & size
       out: uint32 writen bytes
    */
#define MBEDTLS_SERIALIZE_FUNCTION_FCLOSE       0x020510
    /* in: int32 file id
    */
#define MBEDTLS_SERIALIZE_FUNCTION_FSEEK        0x020630
    /* in: int32 file id
       in: int32 offset
       in: int32 whence
    */
#define MBEDTLS_SERIALIZE_FUNCTION_FTELL        0x020711
    /* in: int32 file id
       out: uint32 file position
    */
#define MBEDTLS_SERIALIZE_FUNCTION_FERROR       0x020810
    /* in: int32 file id
    */
#define MBEDTLS_SERIALIZE_FUNCTION_DOPEN        0x020911
    /* in: string dir path
       out: int32 dir Id
    */
#define MBEDTLS_SERIALIZE_FUNCTION_DREAD        0x020A22
    /* in: int32 file id
       in: uint32 read buffer size
       out: string read buffer
       out: uint32 dir entry type
    */
#define MBEDTLS_SERIALIZE_FUNCTION_DCLOSE       0x020B10
    /* in: int32 dir id
    */

#define MBEDTLS_SERIALIZE_FUNCTION_STAT         0x020C11
    /* in: string file name
       out: int16 file type */

/** whence for fseek function */
#define MBEDTLS_SERIALIZE_FSEEK_SET     0
#define MBEDTLS_SERIALIZE_FSEEK_CUR     1
#define MBEDTLS_SERIALIZE_FSEEK_END     2

/** Flag for MBEDTLS_SERIALIZE_FUNCTION_SOCKET to indicate connect vs bind */
#define MBEDTLS_SERIALIZE_SOCKET_DIRECTION_MASK  0x8000
#define MBEDTLS_SERIALIZE_SOCKET_CONNECT         0x0000
#define MBEDTLS_SERIALIZE_SOCKET_BIND            0x8000

/** Flag for MBEDTLS_SERIALIZE_FUNCTION_SET_BLOCK to indicate block vs nonblock */
#define MBEDTLS_SERIALIZE_BLOCK_BLOCK 0x0000
#define MBEDTLS_SERIALIZE_BLOCK_NONBLOCK 0x0001

/** Infinite timeout value for MBEDTLS_SERIALIZE_FUNCTION_RECV */
#define MBEDTLS_SERIALIZE_TIMEOUT_INFINITE 0xffffffff

/** Serialization errors */
#define MBEDTLS_ERR_SERIALIZE_UNSUPPORTED_INPUT     -0x0070 /**< Unable to serialize this input to send it (raised on target) */
#define MBEDTLS_ERR_SERIALIZE_BAD_INPUT             -0x0071 /**< Unable to deserialize received input (raised on host) */
#define MBEDTLS_ERR_SERIALIZE_UNSUPPORTED_OUTPUT    -0x0072 /**< Unable to serialize output to send result (raised on host) */
#define MBEDTLS_ERR_SERIALIZE_BAD_OUTPUT            -0x0073 /**< Unable to deserialize received result (raised on target) */
#define MBEDTLS_ERR_SERIALIZE_SEND                  -0x0074 /**< Communication error while sending serialized data */
#define MBEDTLS_ERR_SERIALIZE_RECEIVE               -0x0075 /**< Communication error while receiving data to unserialize */
#define MBEDTLS_ERR_SERIALIZE_ALLOC_FAILED          -0x0076 /**< Out of memory to execute the function */

/* Note that the serialization functions must be called in a specific sequence:
 *
 *  1. Push the arguments of a command, in reverse order (i.e. to call
 *     f(x,y), push y first, then x). For each argument, call either
 *     mbedtls_serialize_push_buffer or one of the type-specific variants.
 *  2. Call mbedtls_serialize_execute.
 *  3. Call mbedtls_serialize_pop_buffer or one of the type-specific variants
 *     for each output parameter.
 *
 * It is important to spend minimal time before the calls to
 * mbedtls_serialize_pop_buffer, otherwise data can be lost in transit on
 * the serial port on some platforms.
 */

/** Send an input parameter from target to host. */
int mbedtls_serialize_push_buffer( const void *buffer, size_t length );
int mbedtls_serialize_push_int16( uint16_t value );
int mbedtls_serialize_push_int32( uint32_t value );
/** Send a function execution request from target to host. */
int mbedtls_serialize_execute( uint32_t command );
/** Read an output parameter on the target */
int mbedtls_serialize_pop_buffer( void *buffer, size_t max_length, size_t *actual_length );
int mbedtls_serialize_pop_int16( uint16_t *value );
int mbedtls_serialize_pop_int32( uint32_t *value );

#if !defined(MBEDTLS_SERIALIZE_FORK_FRONTEND_C)
/** Following functions need platform specific implementation. */
int mbedtls_serialize_read( uint8_t *buffer, size_t length );
int mbedtls_serialize_write( const uint8_t *buffer, size_t length );
#endif


#ifdef __cplusplus
};
#endif

#endif /* serialize.h */
