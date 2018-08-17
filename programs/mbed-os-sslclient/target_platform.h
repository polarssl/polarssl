/*
 *  API for platform functions required by on-target ssl_client app.
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

#ifndef TARGET_PLATFORM_H
#define TARGET_PLATFORM_H

#ifdef __cplusplus
extern "C" {
#endif

/** \brief Timer delay context type */
typedef void * target_timing_delay_context_t;

/**
 * \brief   Allocate timer delay context.
 *
 * \return  Allocated timer delay context.
 */
target_timing_delay_context_t target_timing_delay_context_alloc();

/**
 * \brief       Free allocated timer delay context.
 *
 * \param ctxt  Timer delay context.
 *
 * \return      void
 */
void target_timing_delay_context_free( target_timing_delay_context_t ctxt );

/**
 * \brief       Timer delay set function.
 *
 * \param timer    Timer delay context.
 * \param int_ms   First (intermediate) delay in milliseconds.
 *                 The effect if int_ms > fin_ms is unspecified.
 * \param fin_ms   Second (final) delay in milliseconds.
 *                 Pass 0 to cancel the current delay.
 *
 * \return      void
 */
void target_timing_delay_set( target_timing_delay_context_t timer,
                              uint32_t int_ms, uint32_t fin_ms );

/**
 * \brief       Timer delay get function.
 *
 * \param ctxt  Timer delay context.
 *
 * \return      -1 if cancelled (fin_ms = 0),
 *               0 if none of the delays are passed,
 *               1 if only the intermediate delay is passed,
 *               2 if the final delay is passed.
 */
int target_timing_delay_get( target_timing_delay_context_t ctxt );


/**
 * \brief       Free received command line arguments.
 *
 * \param argv  Arguments string array.
 *
 * \return      void
 */
void target_free_received_args( char **argv );

/**
 * \brief       Receive command line arguments from serial interface
 *              on start up.
 *
 * \param argc  Argument count filled by the function.
 * \param argv  Arguments string array allocated and filled by the function.
 *
 * \return      void
 */
void target_receive_args( int *argc, char ***argv );

#ifdef __cplusplus
}
#endif
#endif /* TARGET_PLATFORM_H */
