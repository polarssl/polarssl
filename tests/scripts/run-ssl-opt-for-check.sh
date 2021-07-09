#!/bin/sh

# Auxiliary script for check_ssl_opt.py. This script runs an adapted version
# of ssl-opt.sh with some variables and functions defined for the sake of
# the checks. See check_ssl_opt.py for details.

set -e -u

G_CLI="gnutls-cli"
G_NEXT_CLI="next/gnutls-cli"
G_NEXT_SRV="next/gnutls-serv"
G_SRV="gnutls-serv"
MAX_CONTENT_LEN=-111111
MAX_IM_CA=8
O_CLI="openssl s_client"
O_SRV="openssl s_server"
P_PXY="udp_proxy"
P_CLI="ssl_client2"
P_SRV="ssl_server2"
SESSION="session.tmp"
SKIP_NEXT=

client_needs_more_time () {
  :
}

fragments_for_write () {
  echo ...
}

requires () {
  requirements="$requirements;$*"
}

# run_test DESCRIPTION [-p PROXY] SERVER CLIENT RET ...
run_test () {
  description=$1; shift
  if [ "$1" = "-p" ]; then
    proxy=$2
    shift 2
  else
    proxy=
  fi
  server=$1
  client=$2
  ret=$3
  shift 3

  printf '%s\036%s\036%s\036%s\036%s\036%s\036%s\035' \
         "$description" \
         "${requirements%;}" \
         "$server " "$proxy " "$client " "$ret" "$*"

  requirements=
}

requirements=

. "$1"
