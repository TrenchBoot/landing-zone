#!/bin/bash
. util.sh

echo "Initial extensions of PCR17 after SKINIT for ${SLB_FILE}:"
extend_sha1 "$sha1_zeroes" $(sha1_lz)
extend_sha256 "$sha256_zeroes" $(sha256_lz)
