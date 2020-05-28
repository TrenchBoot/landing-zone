#!/bin/bash
. util.sh

if [[ $# -lt 1 ]] || [[ ! -e "$1" ]] ; then
	echo "Usage: $0 multiboot_kernel [module [module ...]]"
	exit
fi

KERNEL=$1
shift

read SKIP SIZE <<< $(readelf "$KERNEL" -S | sed "s/\[ /\[0/" | awk '/PROGBITS/ {printf "0x%s  0x%s\n", $5, $6}')
SKIP=$(($SKIP))
SIZE=$(($SIZE))

extend_sha1 "$(extend_sha1)" "`dd if="$KERNEL" bs=1 skip=$SKIP count=$SIZE 2>/dev/null | sha1sum`" "$@"
extend_sha256 "$(extend_sha256)" "`dd if="$KERNEL" bs=1 skip=$SKIP count=$SIZE 2>/dev/null | sha256sum`" "$@"

