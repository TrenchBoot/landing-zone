SLB_FILE=${SLB_FILE:=lz_header.bin}

SL_SIZE=`hexdump "$SLB_FILE" -s2 -n2 -e '/2 "%u"'`

validate_and_escape_hash () {
	local TRIM=`echo -n "$1" | sed -r -e "s/ .*//"`
	if (( ${#TRIM} != 64 && ${#TRIM} != 40 )); then
		>&2 echo "\"$TRIM\" is not a valid SHA1/SHA256 hash"
		return
	fi
	echo -n $TRIM | sed -r -e "s/([a-f0-9]{2})/\\\x\1/g"
}

# extend_sha* - extend initial PCR value (all 0s) with ${FILE}'s hash (SL only)
# extend_sha* file.bin - extend initial PCR value with full file.bin's hash
# extend_sha* HASH file.bin - extend PCR with value=HASH with file.bin's hash
# extend_sha* HASH1 HASH2 - extend PCR with value=HASH1 with HASH2
# extend_sha* HASH file file...
# extend_sha* HASH HASH HASH... - as long as file is not first
extend_sha1 () {
	local HASH1
	local HASH2
	case $# in
	0)	HASH1=`printf "0%.0s" {1..40}`
		HASH2=`dd if="$SLB_FILE" bs=1 count=$SL_SIZE 2>/dev/null | sha1sum`
		;;
	1 )	if [ -f "$1" ]; then
			HASH1=`printf "0%.0s" {1..40}`
			HASH2=`dd if="$1" 2>/dev/null | sha1sum`
		else
			HASH1=`printf "0%.0s" {1..40}`
			HASH2="$1"
		fi
		;;
	2 )	if [ -f "$2" ]; then
			HASH1="$1"
			HASH2=`dd if="$2" 2>/dev/null | sha1sum`
		else
			HASH1="$1"
			HASH2="$2"
		fi
		;;
	* )	HASH1=$(extend_sha1 "$1" "$2")
		shift 2
		extend_sha1 "$HASH1" $@
		return
		;;
	esac
	local HASH1_ESC=$(validate_and_escape_hash "$HASH1")
	local HASH2_ESC=$(validate_and_escape_hash "$HASH2")
	printf "%b" $HASH1_ESC $HASH2_ESC | sha1sum | sed "s/-/SHA1/"
}

extend_sha256 () {
	local HASH1
	local HASH2
	if [ $# -eq 0 ]; then
		HASH1=`printf "0%.0s" {1..64}`
		HASH2=`dd if="$SLB_FILE" bs=1 count=$SL_SIZE 2>/dev/null | sha256sum`
	elif [ $# -eq 1 ]; then
		if [ -f "$1" ]; then
			HASH1=`printf "0%.0s" {1..64}`
			HASH2=`dd if="$1" 2>/dev/null | sha256sum`
		else
			HASH1=`printf "0%.0s" {1..64}`
			HASH2="$1"
		fi
	elif [ $# -eq 2 ]; then
		if [ -f "$2" ]; then
			HASH1="$1"
			HASH2=`dd if="$2" 2>/dev/null | sha256sum`
		else
			HASH1="$1"
			HASH2="$2"
		fi
	else
		HASH1=$(extend_sha256 "$1" "$2")
		shift 2
		extend_sha256 "$HASH1" $@
		return
	fi
	local HASH1_ESC=$(validate_and_escape_hash "$HASH1")
	local HASH2_ESC=$(validate_and_escape_hash "$HASH2")
	printf "%b" $HASH1_ESC $HASH2_ESC | sha256sum | sed "s/-/SHA256/"
}
