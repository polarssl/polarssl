#! /usr/bin/env sh

# build-mbed-os-sslclient.sh
#
# This file is part of mbed TLS (https://tls.mbed.org)
#
# Copyright (c) 2018, ARM Limited, All Rights Reserved
#
# Purpose
#
# To create mbed-os application with ssl_client program. It does:
#
#   1. Create mbed-os application workspace using mbed-cli
#   2. Import current mbedtls into mbed-os application
#   3. Enable serialization in feature:mbedtls config
#   4. Invokes application with supplied platform and toolchain arguments
#
# Usage
#
#   build-mbed-os-sslclient.sh <mbed platform> <toolchain>
#

USAGE="Usage: $0 <mbed platform> <toolchain>"


# Validate that script is invoked from correct path
if [ ! -x tests/scripts/$(basename "$0") ]; then
    echo "This script should be run from mbedtls root!"
    exit 1
fi

if [ $# != 2 ]; then
    echo "$0: Error: mbed platform and/or toolchain not specified"
    echo $USAGE
    echo ""
    exit 1
fi

# Clean objects and binaries before setting up mbed-os program
make clean

# Setup paths
MBEDTLS_ROOT=$(pwd)
MBED_OS_SSLCLIENT=$MBEDTLS_ROOT/programs/mbed-os-sslclient
MBEDTLS_IMPORTER_DIR=$MBED_OS_SSLCLIENT/mbed-os/features/mbedtls/importer/
MBED_OS_SSLCLIENT_CONFIG=$MBED_OS_SSLCLIENT/mbed-os/features/mbedtls/inc/mbedtls/config.h

# Fetch mbed-os
cd $MBED_OS_SSLCLIENT
mbed config root .
mbed new .
mbed deploy

# Import mbedtls into mbed-os
ln -s $MBEDTLS_ROOT $MBEDTLS_IMPORTER_DIR/TARGET_IGNORE/mbedtls
ln -s $MBEDTLS_ROOT/programs/ssl/ssl_client2.c $MBED_OS_SSLCLIENT/main.c
cd $MBEDTLS_IMPORTER_DIR
make deploy

# Enable serialized network and file system
$MBEDTLS_ROOT/scripts/config.pl -f $MBED_OS_SSLCLIENT_CONFIG set MBEDTLS_SERIALIZE_C
$MBEDTLS_ROOT/scripts/config.pl -f $MBED_OS_SSLCLIENT_CONFIG set MBEDTLS_FS_IO
$MBEDTLS_ROOT/scripts/config.pl -f $MBED_OS_SSLCLIENT_CONFIG set MBEDTLS_NET_C
$MBEDTLS_ROOT/scripts/config.pl -f $MBED_OS_SSLCLIENT_CONFIG set MBEDTLS_NET_OFFLOAD_C

# Build ssl client
cd $MBED_OS_SSLCLIENT
mbed-cli compile -m $1 -t $2
