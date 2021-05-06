/**
 * \file x509_invasive.h
 *
 * \brief x509 module: interfaces for invasive testing only.
 *
 * The interfaces in this file are intended for testing purposes only.
 * They SHOULD NOT be made available in library integrations except when
 * building the library for testing.
 */
/*
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
#ifndef MBEDTLS_X509_INVASIVE_H
#define MBEDTLS_X509_INVASIVE_H

#if defined(MBEDTLS_TEST_HOOKS)

/*
 * parse ipv4 address from canonical string form into bytes.
 * return 0 if success, -1 otherwise
 */
int mbedtls_x509_parse_ipv4( const char *h, size_t hlen, unsigned char *addr );

/*
 * parse ipv6 address from canonical string form into bytes.
 * return 0 if success, -1 otherwise
 */
int mbedtls_x509_parse_ipv6( const char *h, size_t hlen, unsigned char *addr );

#endif /* MBEDTLS_TEST_HOOKS */

#endif /* MBED_TLS_X509_INVASIVE_H */
