#!/bin/bash
. util.sh

if [[ $# -eq 2 ]] && [[ -e "$1" ]] && [[ -e "$2" ]] ; then
	extend_sha1 "$sha1_zeroes" $(sha1_lz) $(sha1_kernel "$1") "$2"
	extend_sha256 $sha256_zeroes $(sha256_lz) $(sha256_kernel "$1") "$2"
elif [[ $# -eq 1 ]] && [[ -e "$1" ]] ; then
	extend_sha1 $sha1_zeroes $(sha1_lz) $(sha1_kernel "$1")
	extend_sha256 $sha256_zeroes $(sha256_lz) $(sha256_kernel "$1")
else
	echo "Usage: $0 path/to/bzImage [path/to/initrd]"
	exit
fi


