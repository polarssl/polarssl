#ifndef MBED_OS_PLATFORM_H
#define MBED_OS_PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void * mbed_os_timing_delay_context_t;

mbed_os_timing_delay_context_t mbed_os_timing_delay_context_alloc();
void mbed_os_timing_delay_context_free( mbed_os_timing_delay_context_t );
void mbed_os_timing_delay_set( mbed_os_timing_delay_context_t timer, uint32_t int_ms, uint32_t fin_ms );
int mbed_os_timing_delay_get( mbed_os_timing_delay_context_t );

void free_received_args( char **argv );
void receive_args( int *argc, char ***argv );

#ifdef __cplusplus
}
#endif
#endif /* MBED_OS_PLATFORM_H */
