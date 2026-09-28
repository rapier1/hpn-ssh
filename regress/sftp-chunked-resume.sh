#	Placed in the Public Domain.

tid="hpnsftp chunked verified resume (reputv/regetv)"

# Exercises chunked_reconcile_span through reputv and regetv: a span of
# two or more 64 MiB chunks is hashed per chunk on both sides and only
# the chunks that differ move. The 200 MiB source has four chunks, the
# last one 8 MiB short. The 100 MiB source is below the two-chunk floor,
# so the chunked path declines and the whole-file gate takes it.

BIG=${OBJ}/chunked-big.src
SMALL=${OBJ}/chunked-small.src
DST=${OBJ}/chunked.dst
MiB=1048576

dd if=/dev/urandom of=${BIG} bs=${MiB} count=200 2>/dev/null \
    || fatal "cannot create ${BIG}"
dd if=/dev/urandom of=${SMALL} bs=${MiB} count=100 2>/dev/null \
    || fatal "cannot create ${SMALL}"

# Overwrite one MiB of $1 at MiB offset $2 with random bytes.
corrupt() {
	dd if=/dev/urandom of=$1 bs=${MiB} seek=$2 count=1 conv=notrunc \
	    2>/dev/null
}

# Assert that the client log contains the basic regex $2; $1 names the case.
expect() {
	grep -q -- "$2" ${CLIENT_LOG} \
	    || fail "$1: expected \"$2\" in the client log"
}

for direction in reputv regetv; do
    for case in one-chunk two-runs tail-chunk partial identical small; do
	verbose "$tid: ${direction} ${case}"
	CLIENT_LOG=${OBJ}/sftp-chunked-resume.${direction}.${case}.log
	rm -f ${DST}
	src=${BIG}
	case "${case}" in
	one-chunk)	cp ${BIG} ${DST}; corrupt ${DST} 65 ;;
	two-runs)	cp ${BIG} ${DST}; corrupt ${DST} 1; corrupt ${DST} 129 ;;
	tail-chunk)	cp ${BIG} ${DST}; corrupt ${DST} 195 ;;
	partial)	dd if=${BIG} of=${DST} bs=${MiB} count=100 2>/dev/null ;;
	identical)	cp ${BIG} ${DST} ;;
	small)		src=${SMALL}; cp ${SMALL} ${DST}; corrupt ${DST} 50 ;;
	esac

	# reputv names the local source first, regetv the remote source
	# first. Under -D both are local files; the roles are the client's.
	echo "${direction} ${src} ${DST}" | \
	    ${SFTP} -D ${SFTPSERVER} -vvv >${CLIENT_LOG} 2>&1 \
	    || fail "${direction} ${case}: hpnsftp failed"
	cmp ${src} ${DST} \
	    || fail "${direction} ${case}: destination differs from source"

	label="${direction} ${case}"
	case "${case}" in
	one-chunk)
		expect "${label}" "verified resume .*: re-[a-z]* 1/4 chunks (4 hashed, 0 known-missing"
		expect "${label}" "chunks \[1, 2) at offset 67108864 length 67108864"
		;;
	two-runs)
		expect "${label}" "verified resume .*: re-[a-z]* 2/4 chunks (4 hashed, 0 known-missing"
		expect "${label}" "chunks \[0, 1) at offset 0 length 67108864"
		expect "${label}" "chunks \[2, 3) at offset 134217728 length 67108864"
		;;
	tail-chunk)
		expect "${label}" "1/4 chunks (4 hashed, 0 known-missing past dest EOF; 8388608 / 209715200 bytes"
		expect "${label}" "chunks \[3, 4) at offset 201326592 length 8388608"
		;;
	partial)
		expect "${label}" "dest-EOF clamp for .*: checking 1/4 chunks (dest size 104857600); 3 known-missing"
		expect "${label}" "3/4 chunks (1 hashed, 3 known-missing past dest EOF; 142606336 / 209715200 bytes"
		;;
	identical)
		expect "${label}" "all 4 chunks of span match"
		;;
	small)
		expect "${label}" "span 104857600 of .* below chunked threshold 134217728; declining"
		expect "${label}" "sftp_hpn_prefix_match: .* first 104857600 bytes: local"
		;;
	esac
    done
done

# The data always goes; the client logs go on a clean run and stay
# behind a failure for reading.
rm -f ${BIG} ${SMALL} ${DST}
if [ "${RESULT:-0}" = 0 ]; then
	rm -f ${OBJ}/sftp-chunked-resume.*.log
fi
