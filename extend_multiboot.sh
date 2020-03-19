#!/bin/bash
. util.sh

if [[ $# -lt 1 ]] || [[ ! -e "$1" ]] ; then
	echo "Usage: $0 multiboot_kernel [module [module ...]]"
	exit
fi

KERNEL=$1
shift

read SKIP SIZE <<< $(readelf "$KERNEL" -l | awk '/LOAD/ {printf "%s  %s\n", $2, $5}')
SKIP=$(($SKIP))
SIZE=$(($SIZE))

extend_sha1 "$(extend_sha1)" "`dd if="$KERNEL" bs=1 skip=$SKIP count=$SIZE 2>/dev/null | sha1sum`" "$@"
extend_sha256 "$(extend_sha256)" "`dd if="$KERNEL" bs=1 skip=$SKIP count=$SIZE 2>/dev/null | sha256sum`" "$@"

