#!/bin/bash
. util.sh

if [[ $# -ne 2 ]] || [[ ! -e "$1" ]] || [[ ! -e "$2" ]] ; then
	echo "Usage: $0 path/to/bzImage path/to/initrd"
	exit
fi

# see https://www.kernel.org/doc/html/latest/x86/boot.html#details-of-harder-fileds
KERNEL_PROT_SKIP=$((`hexdump "$1" -s0x1f1 -n1 -e '/1 "%u"'` * 512 + 512))

extend_sha1 "$(extend_sha1)" "`dd if="$1" bs=1 skip=$KERNEL_PROT_SKIP 2>/dev/null | sha1sum`" "$2"
extend_sha256 "$(extend_sha256)" "`dd if="$1" bs=1 skip=$KERNEL_PROT_SKIP 2>/dev/null | sha256sum`" "$2"

