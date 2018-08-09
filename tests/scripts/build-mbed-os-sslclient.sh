#!/bin/sh


# Validate that script is invoked from correct path
if [ ! -x tests/scripts/$(basename "$0") ]; then
    echo "This script should be run from mbedtls root!"
    exit 1
fi

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
cd $MBEDTLS_IMPORTER_DIR
make deploy

# Enable serialized network and file system
$MBEDTLS_ROOT/scripts/config.pl -f $MBED_OS_SSLCLIENT_CONFIG set MBEDTLS_SERIALIZE_C
$MBEDTLS_ROOT/scripts/config.pl -f $MBED_OS_SSLCLIENT_CONFIG set MBEDTLS_FS_IO
$MBEDTLS_ROOT/scripts/config.pl -f $MBED_OS_SSLCLIENT_CONFIG set MBEDTLS_NET_C
$MBEDTLS_ROOT/scripts/config.pl -f $MBED_OS_SSLCLIENT_CONFIG set MBEDTLS_NET_OFFLOAD_C

# Build ssl client
cd $MBED_OS_SSLCLIENT
mbed-cli compile -m K64F -t GCC_ARM
