#!/bin/bash
. util.sh

if ! od --format=x8 --skip-bytes=$SL_SIZE --read-bytes=16 $SLB_FILE | grep -q "e91192048e26f178 02ccc4765bc82a83"; then
    echo "ERROR: LZ UUID missing or misplaced in $SLB_FILE" >&2
    false
    exit
fi

# UUID + 4 * u32 + SHA1 + u32 + u16
SHA1_SEEK=$(($SL_SIZE + 16 + (4 * 4) + 20 + 4 + 2))

# ... + SHA1 + u16
SHA256_SEEK=$(($SHA1_SEEK + 20 + 2))

dd if="$SLB_FILE" bs=1 count=$SL_SIZE 2>/dev/null | sha1sum | xxd -r -p | dd bs=1 of="$SLB_FILE" seek=$SHA1_SEEK count=20 conv=notrunc
dd if="$SLB_FILE" bs=1 count=$SL_SIZE 2>/dev/null | sha256sum | xxd -r -p | dd bs=1 of="$SLB_FILE" seek=$SHA256_SEEK count=32 conv=notrunc
