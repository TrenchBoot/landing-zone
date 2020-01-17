#!/bin/bash
. util.sh

od --format=x8 --skip-bytes=$SL_SIZE --read-bytes=16 $SLB_FILE | \
	grep "e91192048e26f178 02ccc4765bc82a83" > /dev/null || \
	{ echo "ERROR: LZ UUID missing or misplaced in $SLB_FILE" >&2; false; }

