#!/bin/bash
. util.sh

LZ_INFO=`hexdump "$SLB_FILE" -s4 -n2 -e '/2 "%u"'`

if ! od --format=x8 --skip-bytes=$LZ_INFO --read-bytes=16 $SLB_FILE | grep -q "e91192048e26f178 02ccc4765bc82a83"; then
    echo "ERROR: LZ UUID missing or misplaced in $SLB_FILE" >&2
    false
fi
