/*
 *  Implementation of platform functions declared in target_platform.h
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

#include "mbed.h"
#include "drivers/TimerEvent.h"
#include "greentea-client/test_env.h"
#include "greentea-client/greentea_serial.h"
#include "target_platform.h"

extern "C" {
#include "mbedtls/serialize.h"
}

using namespace mbed;

/**
 * Extension to TimerEvent class. It adds mbedtls timer functionality that
 * requires running an intermediate delay and then a final delay.
 */
class MyTimer: public TimerEvent
{
public:
    /** Initialise timer in idle state */
    MyTimer(): TimerEvent(), int_us( 0 ), fin_us( 0 ), state( 0 ){}

    /** Reset timer data */
    /*
    void reset()
    {
        int_us = 0;
        fin_us = 0;
        state = 0;
    }
    */

    /** \brief  Timer event handler called on set timer expiry.
     *          It does state transitions as follows:
     *
     *      current state |     condition   | next state
     *          0         | int_us < fin_us |   1
     *          0         | int_us >= fin_us|   2
     *          1         |                 |   2
     *
     * \return  void
     */
    void handler()
    {
        state++;

        if( state == 1 )
        {
            if( int_us < fin_us )
            {
                // intermediate delay passed.
                insert_absolute( event.timestamp + ( fin_us - int_us ) );
            }
            else
                state++;
        }
    }
    /**
     * \brief   Sets the delay and starts the intermediate timer.
     *
     * \param int_ms   First (intermediate) delay in milliseconds.
     *                 The effect if int_ms > fin_ms is unspecified.
     * \param fin_ms   Second (final) delay in milliseconds.
     *                 Pass 0 to cancel the current delay.
     *
     * \return  void
     */
    void set_delay( uint32_t int_ms, uint32_t fin_ms )
    {
        if( fin_ms == 0 )
        {
            remove();
            state = -1;
        }
        else
        {
            // int_us == 0 implies that intermediate delay has passed.
            int_us = int_ms * 1000;
            fin_us = fin_ms * 1000;
            state = ( int_us == 0 )?1:0;
            uint64_t min = ( int_us && int_us < fin_us )?int_us:fin_us;
            insert( min );
        }
    }
    /** Returns timer state */
    int get_delay()
    {
        return state;
    }
    uint64_t int_us;
    uint64_t fin_us;
    int state;
};

/** Dynamically allocate timer context and return */
target_timing_delay_context_t target_timing_delay_context_alloc()
{
    return ( target_timing_delay_context_t )( new MyTimer() );
}

/** Free dynamically allocated timer context */
void target_timing_delay_context_free( target_timing_delay_context_t timer )
{
    delete ( ( MyTimer * ) timer );
}

/** Set timing delays in timer object */
void target_timing_delay_set( target_timing_delay_context_t timer, uint32_t int_ms, uint32_t fin_ms )
{
    ( ( MyTimer * ) timer )->set_delay( int_ms, fin_ms );
}

/** Get timer state */
int target_timing_delay_get( target_timing_delay_context_t timer )
{
    return ( ( MyTimer * ) timer )->get_delay();
}


/** Implementation of mbedtls_serialize_write declared in serialize.h  */
int mbedtls_serialize_write( const uint8_t *buffer, size_t length )
{
    size_t offset = 0;
    for( int i = 0; i < 2;i++ )
    {
        if( greentea_serial->putc( '{' ) == -1 )
            return MBEDTLS_ERR_SERIALIZE_SEND;
    }
    while( offset < length && greentea_serial->putc( buffer[offset++] ) != -1 );
    return ( offset == length )?0:MBEDTLS_ERR_SERIALIZE_SEND;
}

/** Implementation of mbedtls_serialize_read declared in serialize.h  */
int mbedtls_serialize_read( uint8_t *buffer, size_t length )
{
    size_t offset = 0;
    int c;
    while( offset < length && ( c = greentea_serial->getc() ) != EOF )
        buffer[offset++] = (char)c;
    return ( offset == length )?0:MBEDTLS_ERR_SERIALIZE_RECEIVE;
}

/** Receive uint32_t in bytes and return packed uint32_t */
static uint32_t receive_uint32()
{
    uint32_t value;
    value =  ( (uint32_t)greentea_getc() ) << 24;
    value |= ( (uint32_t)greentea_getc() ) << 16;
    value |= ( (uint32_t)greentea_getc() ) << 8;
    value |= ( (uint32_t)greentea_getc() );
    return( (uint32_t)value );
}

/**
 * Receives the command line sent from the host using the greentea API.
 * The expected data format is:
 * - 4 byte buffer size
 * - buffer of the given size (if size > 0, otherwise no buffer is sent)
 *
 * The postconditions are that:
 * - argv is a newly allocated array of pointers to char containing the incoming
 *   arguments, with (*argv)[0] left to contain NULL (it doesn't make sense to
 *   send it in from the frontend)
 * - argc contains a value of the numner of the argv elements.
 *
 * Note that apart from the array itself, _one_ buffer for the arguments is
 * allocated which contains all the arguments terminated with NUL character.
 * This means that in order to clean up after this procedure both the (*argv)[1]
 * and *argv buffers must be freed.
 */
void target_receive_args( int *argc, char ***argv )
{
    uint32_t i, length;
    char *buffer;
    int j;

    /* Wait until start sequence "{{" is received from the host */
    j = 0;
    while( j < 2 )
    {
        if( greentea_getc() == '{' )
            j++;
        else
            j = 0;
    }
    length = receive_uint32();
    if( length == 0 )
    {
        // length == 0 means no further data was sent.
        *argc = 0;
        *argv = NULL;
    }
    else
    {
        // if length was non zero, the args have been sent in a
        // subsequent buffer

        // Initialize with 1 because of the additional (*argv)[0]
        // which is not sent
        *argc = 1;
        buffer = new char[length];
        for( i = 0; i < length; ++i )
        {
            buffer[i] = greentea_getc();
            if( buffer[i] == '\0' ) // count NULs along the way to count args
            {
                ++*argc;
            }
        }

        *argv = new char* [ *argc ];
        ( *argv )[0] = NULL; // Fill this in later if necessary
        for( j = 1; j < *argc; ++j ) // Initialize i to 1 as the first argument
                                     // has been set above.
        {
            // Record current arg
            ( *argv )[j] = buffer;
            printf( "rx [%s]\r\n", buffer );
            fflush( stdout );
            // Find next NUL character
            while( *buffer ) ++buffer;
            // Skip beyond the NUL character to the next arg
            ++buffer;
        }
        printf( "done receive_args\r\n" );
        fflush( stdout );
    }

}

/** Free command line arguments memory allocated in target_receive_args */
void target_free_received_args( char **argv )
{
    delete [] argv[1];
    delete [] argv;
}

