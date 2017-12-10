#!/bin/sh

# check if generated files are up-to-date

set -eu

if [ -d library -a -d include -a -d tests ]; then :; else
    echo "Must be run from mbed TLS root" >&2
    exit 1
fi

check()
{
    SCRIPT=$1
    shift

    for FILE; do
        cp "$FILE" "$FILE.bak"
    done
    "$SCRIPT"
    for FILE; do
        diff "$FILE" "$FILE.bak"
        mv "$FILE.bak" "$FILE"
    done
}

check scripts/generate_errors.pl library/error.c include/mbedtls/error.h
check scripts/generate_features.pl library/version_features.c
