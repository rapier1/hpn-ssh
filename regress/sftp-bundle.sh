#	HPN-SSH sftp-bundle.sh
#	Placed in the Public Domain.
#
#	Exercises the hpn-bundle@hpnssh.org small-file aggregation path
#	and the HPNUseBundle / HPNBundleSize ssh_config options.

tid="sftp bundle path"

SRCDIR=${OBJ}/bundle-src
DSTDIR=${OBJ}/bundle-dst

bclean() {
	rm -rf ${SRCDIR} ${DSTDIR}
	mkdir -p ${SRCDIR} ${DSTDIR}
}

# Bundle dispatch requires the orchestrator + real sshd path.
start_sshd

# Build a many-small-files dataset that comfortably hits the bundle
# accumulator (default 4 MiB target).  Twenty 16 KiB files = 320 KiB
# total - small enough to pack as a single bundle per worker, large
# enough that the directory walk exercises the batch path.  The empty
# files ride along to pin the tar codec's zero-size entry path (header
# with no data phase on pack; entry creation with no data callbacks on
# extract) - a bundle-only special case that plain transfers never hit.
make_dataset() {
	for i in 01 02 03 04 05 06 07 08 09 10 \
	         11 12 13 14 15 16 17 18 19 20; do
		dd if=/dev/urandom of=${SRCDIR}/f${i} bs=16k count=1 \
		    status=none 2>/dev/null || \
		    fail "could not seed bundle dataset"
	done
	touch ${SRCDIR}/empty1 ${SRCDIR}/f00 ${SRCDIR}/zzz-empty || \
	    fail "could not seed empty files"
}

# Each test pass: recursive put -r then recursive get -r, with a
# checksum-equivalent diff on both ends.  Caller supplies extra -o
# options for the bundle config we want to exercise.
bundle_round_trip() {
	label="$1"
	shift
	bclean
	make_dataset

	verbose "$tid: $label (put -r)"
	${SFTP} -j 4 -q -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes "$@" \
	    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
put -r ${SRCDIR} ${DSTDIR}/up
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "$label put -r failed with $r"
		return
	fi
	diff -r ${SRCDIR} ${DSTDIR}/up || \
	    fail "$label: uploaded tree differs from source"

	verbose "$tid: $label (get -r)"
	rm -rf ${DSTDIR}/down
	${SFTP} -j 4 -q -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes "$@" \
	    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
get -r ${SRCDIR} ${DSTDIR}/down
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "$label get -r failed with $r"
		return
	fi
	diff -r ${SRCDIR} ${DSTDIR}/down || \
	    fail "$label: downloaded tree differs from source"
}

# Pass 1: defaults - bundle path enabled (server advertises the
# extension; HPNUseBundle defaults to yes).
bundle_round_trip "default (bundle enabled)"

# Pass 2: HPNUseBundle=no forces the Phase-4 batch fallback.
bundle_round_trip "HPNUseBundle=no fallback" \
    -o HPNUseBundle=no

# Pass 3: HPNBundleSize=64K keeps the bundle path enabled but shrinks
# the per-bundle accumulator target.  The dataset still fits within a
# single bundle, but this verifies the option is plumbed through.
bundle_round_trip "HPNBundleSize=64K" \
    -o HPNBundleSize=64K

bclean
