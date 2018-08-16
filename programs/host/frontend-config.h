/**
 * Config for host frontend application.
 *
 * \brief Configuration options when compiling the host frontend
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

#ifndef MBEDTLS_HOST_CONFIG_H
#define MBEDTLS_HOST_CONFIG_H

#define MBEDTLS_NET_C
#define MBEDTLS_NET_FRONTEND_C
#define MBEDTLS_SERIALIZE_FORK_FRONTEND_C
#define MBEDTLS_FS_IO

#endif /* host/config.h */
