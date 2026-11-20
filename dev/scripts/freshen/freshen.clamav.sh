#!/bin/bash

# Name: freshen.clamav.sh
# Author: Ladar Levison
#
# Description: Used to update the Clam Antivirus Signatures using the system freshclam
# binary and the sandbox config file. Note the update signatures will be placed in the
# sandbox environment.
#
# ClamAV is no longer vendored, so this script uses the platform's freshclam/sigtool
# (RHEL/Rocky 9: the clamav-freshclam and clamav packages) rather than the former
# bundled binaries under lib/sources/clamav.

# Handle self referencing, sourcing etc.
if [[ $0 != $BASH_SOURCE ]]; then
  export CMD=`readlink -f $BASH_SOURCE`
else
  export CMD=`readlink -f $0`
fi

# Cross Platform Base Directory Discovery
pushd `dirname $CMD` > /dev/null
BASE=`pwd -P`
popd > /dev/null

cd $BASE/../../../

# If the TERM environment variable is missing, then tput may trigger a fatal error.
if [[ -n "$TERM" ]] && [[ "$TERM" != "dumb" ]]; then
  export TPUT="tput"
else
  export TPUT="tput -Tvt100"
fi

export MAGMA_DIST=`pwd`

# ClamAV is provided by the platform now; use the system freshclam/sigtool from PATH.
FRESHCLAM=`command -v freshclam`
SIGTOOL=`command -v sigtool`
if [ -z "$FRESHCLAM" ]; then
  [[ -t 0 ]] && ${TPUT} setaf 1 || true
  printf "The system freshclam binary was not found.\n"
  printf "Install it before freshening signatures, e.g. on RHEL/Rocky 9:  dnf install clamav clamav-freshclam\n"
  [[ -t 0 ]] && ${TPUT} sgr0 || true
  exit 1
fi

# If the sandbox contains a CA bundle file, override the path to the CA file used by Freshclam.
if [ -f $MAGMA_DIST/sandbox/etc/ca-bundle.crt ]; then
  "$FRESHCLAM" --user $USER --ca=$MAGMA_DIST/sandbox/etc/ca-bundle.crt --datadir=$MAGMA_DIST/sandbox/virus --config-file=$MAGMA_DIST/sandbox/etc/freshclam.conf
else
  "$FRESHCLAM" --user $USER --datadir=$MAGMA_DIST/sandbox/virus --config-file=$MAGMA_DIST/sandbox/etc/freshclam.conf
fi

# Print statistics for all of the ClamAV database files.
printf "\n\n"
if [ -n "$SIGTOOL" ]; then
  find sandbox/virus/ \( -type f -name "*.cvd" -print0 \) -or \( -type f -name "*.cld" -print0 \) | xargs -0 --replace={} bash -c '"'"$SIGTOOL"'" --info={} | grep -v Builder | grep -v MD5 | grep -v "Digital signature" ; printf "\n"'
fi

# Done.
[[ -t 0 ]] && ${TPUT} setaf 2 || true ; printf "Done.\n" ; [[ -t 0 ]] && ${TPUT} sgr0 || true

