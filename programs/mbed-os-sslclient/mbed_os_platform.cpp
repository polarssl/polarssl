#include "mbed.h"
#include "drivers/TimerEvent.h"
#include "greentea-client/test_env.h"
#include "greentea-client/greentea_serial.h"
#include "mbed_os_platform.h"

extern "C" {
#include "mbedtls/serialize.h"
}

using namespace mbed;

class MyTimer: public TimerEvent
{
public:
    MyTimer(): TimerEvent(), int_us(0), fin_us(0), state(0){}

    void reset()
    {
        int_us = 0;
        fin_us = 0;
        state = 0;
    }

    void handler()
    {
        state++;

        if( state == 1 )
        {
            if( int_us < fin_us )
            {
                // intermediate delay passed.
                insert_absolute(event.timestamp + (fin_us - int_us));
            }
            else
                state++;
        }
    }
    void set_delay(uint32_t int_ms, uint32_t fin_ms)
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
            state = (int_us == 0)?1:0;
            uint64_t min = (int_us && int_us < fin_us)?int_us:fin_us;
            insert(min);
        }
    }
    int get_delay()
    {
        return state;
    }
    uint64_t int_us;
    uint64_t fin_us;
    int state;
};

mbed_os_timing_delay_context_t mbed_os_timing_delay_context_alloc()
{
    return (mbed_os_timing_delay_context_t)(new MyTimer());
}

void mbed_os_timing_delay_context_free( mbed_os_timing_delay_context_t timer )
{
    delete ( ( MyTimer *) timer );
}

void mbed_os_timing_delay_set( mbed_os_timing_delay_context_t timer, uint32_t int_ms, uint32_t fin_ms )
{
    ( ( MyTimer *) timer )->set_delay( int_ms, fin_ms );
}

int mbed_os_timing_delay_get( mbed_os_timing_delay_context_t timer )
{
    return ( ( MyTimer *) timer )->get_delay();
}


int mbedtls_serialize_write( const uint8_t *buffer, size_t length )
{
    size_t offset = 0;
    for(int i = 0; i < 2;i++)
    {
        if(greentea_serial->putc('{') == -1)
            return MBEDTLS_ERR_SERIALIZE_SEND;
    }
    while(offset < length && greentea_serial->putc(buffer[offset++]) != -1);
    return (offset == length)?0:MBEDTLS_ERR_SERIALIZE_SEND;
}

int mbedtls_serialize_read( uint8_t *buffer, size_t length )
{
    size_t offset = 0;
    int c;
    while(offset < length && (c = greentea_serial->getc()) != EOF)
        buffer[offset++] = (char)c;
    return (offset == length)?0:MBEDTLS_ERR_SERIALIZE_RECEIVE;
}

uint32_t receive_uint32()
{
    uint32_t value;
    value =  ((uint32_t)greentea_getc()) << 24;
    value |= ((uint32_t)greentea_getc()) << 16;
    value |= ((uint32_t)greentea_getc()) << 8;
    value |= ((uint32_t)greentea_getc());
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
 *   arguments, with (*argv)[0] left to contain NULL (it doesn't make sense to send
 *   it in from the frontend)
 * - argc contains a value of the numner of the argv elements.
 *
 * Note that apart from the array itself, _one_ buffer for the arguments is
 * allocated which contains all the arguments terminated with NUL character.
 * This means that in order to clean up after this procedure both the (*argv)[1]
 * and *argv buffers must be freed.
 */
void receive_args( int *argc, char ***argv )
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
        // if length was non zero, the args have been sent in a subsequent buffer
        *argc = 1; // Initialize with 1 because of the additional (*argv)[0] which is not sent
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
        (*argv)[0] = NULL; // Fill this in later if necessary
        for( j = 1; j < *argc; ++j ) // Initialize i to 1 as the first argument
                                     // has been set above.
        {
            // Record current arg
            (*argv)[j] = buffer;
            printf("rx [%s]\r\n", buffer);
            fflush(stdout);
            // Find next NUL character
            while( *buffer ) ++buffer;
            // Skip beyond the NUL character to the next arg
            ++buffer;
        }
        printf("done receive_args\r\n");
        fflush(stdout);
    }

}

void free_received_args( char **argv )
{
    //free(argv[1]); // Free the buffer containing the args
    //free(argv); // Free the arg pointer array
    delete [] argv[1];
    delete [] argv;
}

