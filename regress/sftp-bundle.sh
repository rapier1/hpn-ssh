#	HPN-SSH sftp-bundle.sh
#	Placed in the Public Domain.
#
#	Exercises the hpn-bundle@hpnssh.org small-file aggregation path,
#	parallel and serial, in both directions, with and without -p, with
#	and without -V, and the HPNUseBundle, HPNBundleSize and
#	HPNWriterPool ssh_config options.

tid="sftp bundle path"

SRCDIR=${OBJ}/bundle-src
DSTDIR=${OBJ}/bundle-dst
LOG=${OBJ}/sftp-bundle.log

bclean() {
	rm -rf ${SRCDIR} ${DSTDIR}
	mkdir -p ${SRCDIR} ${DSTDIR}
}

# The regress sshd serves every pass. The last pass restarts it with
# the server side of bundling turned off.
start_sshd

# The dataset. Twenty 16 KiB files pack as one bundle per worker under
# every target the passes use, several records to a block. The empty
# files pin the codec's zero-size entry path, a header with no data on
# pack and an entry with no data callbacks on extract, which plain
# transfers never hit. Their names put one first, one in the middle and
# one last. Permission and subdir tested because these are different
# paths when using bundling.
make_dataset() {
	for i in 01 02 03 04 05 06 07 08 09 10 \
	         11 12 13 14 15 16 17 18 19 20; do
		dd if=/dev/urandom of=${SRCDIR}/f${i} bs=16k count=1 \
		    2>/dev/null || fail "could not seed bundle dataset"
	done
	touch ${SRCDIR}/empty1 ${SRCDIR}/f00 ${SRCDIR}/zzz-empty || \
	    fail "could not seed empty files"
	# A 300 KiB file is eligible under the default target but above a
	# quarter of the 1 MiB one, so that pass mixes a bundle with a
	# single-file transfer.
	dd if=/dev/urandom of=${SRCDIR}/big bs=100k count=3 2>/dev/null || \
	    fail "could not seed the large file"
	# Eight 200 KiB files are each eligible under the 1 MiB target and
	# together exceed it, so the serial pass at that target flushes
	# more than one bundle per direction.
	for i in 1 2 3 4 5 6 7 8; do
		dd if=/dev/urandom of=${SRCDIR}/m${i} bs=100k count=2 \
		    2>/dev/null || fail "could not seed the medium files"
	done
	# A subdirectory, so entries carry a parent the extractor has to
	# create or find.
	mkdir ${SRCDIR}/sub || fail "could not seed the subdirectory"
	for i in 1 2 3; do
		dd if=/dev/urandom of=${SRCDIR}/sub/s${i} bs=16k count=1 \
		    2>/dev/null || fail "could not seed the subdirectory"
	done
	# Modes and an old mtime for the -p pass. The setuid bit must not
	# survive a transfer.
	chmod 600 ${SRCDIR}/f01 && chmod 755 ${SRCDIR}/f02 && \
	    chmod 4755 ${SRCDIR}/f03 && touch -t 200001010000 ${SRCDIR}/f04 || \
	    fail "could not set modes on the dataset"
}

# After a -p pass, compare modes and the old mtime in one transferred
# tree against the source. The mode string comes from ls, and mtime
# equality is "neither file is newer than the other".
check_preserve() {
	tree="$1"
	for f in f01:-rw------- f02:-rwxr-xr-x f03:-rwxr-xr-x; do
		name=${f%%:*}
		want=${f#*:}
		got=$(ls -ld ${tree}/${name} | cut -c1-10)
		[ "$got" = "$want" ] || \
		    fail "$label: ${tree}/${name} mode $got, wanted $want"
	done
	if [ -n "$(find ${tree}/f04 -newer ${SRCDIR}/f04)" ] || \
	    [ -n "$(find ${SRCDIR}/f04 -newer ${tree}/f04)" ]; then
		fail "$label: ${tree}/f04 mtime not preserved"
	fi
}

# Check the client log after one direction. With bundling expected the
# per-bundle line must be there, at least twice for bundle-multi.
# Otherwise it must be absent and the workers must have said why they
# skipped the bundle path. On the download side the client's writer
# pool must match the expectation as well.
check_log() {
	direction="$1"
	bundle_line="$2"
	if [ "$expect" = bundle-multi ]; then
		[ $(grep -c "$bundle_line" ${LOG}) -ge 2 ] || \
		    fail "$label: $direction sent fewer than two bundles"
	elif [ "$expect" = bundle ] || [ "$expect" = bundle-nopool ]; then
		grep -q "$bundle_line" ${LOG} || \
		    fail "$label: $direction did not use the bundle path"
	else
		grep -q "$bundle_line" ${LOG} && \
		    fail "$label: $direction used the bundle path"
		grep -q "$reason" ${LOG} || \
		    fail "$label: $direction did not report '$reason'"
	fi
	# The client's download pool announces itself. The server's does
	# not reach this log, so the upload side is not checked.
	if [ "$direction" = get ]; then
		case "$expect" in
		bundle|bundle-multi)
			grep -q "writer pool active" ${LOG} || \
			    fail "$label: get did not use the writer pool" ;;
		bundle-nopool)
			grep -q "writer pool active" ${LOG} && \
			    fail "$label: get used the writer pool" ;;
		esac
	fi
}

# Under -V the client log must show that the verify phase ran without a
# mismatch and, on the upload side, that every non-empty file's source
# hash came from the transfer's tee rather than a second read. A
# download reads its destination back, so no teed hash appears there.
# Empty files are verified on size alone and hash nothing.
check_verify() {
	direction="$1"
	teed=$(grep -c "verify: teed source hash for" ${LOG})
	if [ "$direction" = put ]; then
		want=$(find ${SRCDIR} -type f -size +0 | wc -l | tr -d ' ')
	else
		want=0
	fi
	if [ "$teed" -ne "$want" ]; then
		cp ${LOG} ${OBJ}/sftp-bundle-failed.log
		fail "$label: $direction used $teed teed source hashes, wanted $want"
	fi
	grep -q "VERIFY FAILED" ${LOG} && \
	    fail "$label: $direction reported a verify mismatch"
}

# One pass: put -r then get -r, each followed by a recursive diff
# against the source and a check of the client's -v log. $2 says what
# the log must show: bundle, bundle-multi (at least two bundles per
# direction), bundle-nopool (bundled without the writer pool),
# client-off (HPNUseBundle=no in ssh_config) or server-off (the server
# does not advertise the extension). The rest are the client options
# under test, -j included, so each pass states its mode.
bundle_round_trip() {
	label="$1"
	expect="$2"
	shift 2
	case "$expect" in
	bundle|bundle-multi|bundle-nopool) reason="" ;;
	client-off) reason="bundle disabled" ;;
	server-off) reason="lacks hpn-bundle" ;;
	*) fail "$label: unknown result '$expect'"; return ;;
	esac
	verify=no
	for arg; do
		[ "$arg" = -V ] && verify=yes
	done
	bclean
	make_dataset

	verbose "$tid: $label (put -r)"
	# -q keeps the ssh transport quiet, -v after it turns hpnsftp's
	# own debug output back on, which check_log reads.
	${SFTP} -q -v -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes "$@" \
	    -b - ${USER}@somehost > /dev/null 2> ${LOG} <<EOF
put -r ${SRCDIR} ${DSTDIR}/up
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "$label: put -r failed with $r"
		return
	fi
	diff -r ${SRCDIR} ${DSTDIR}/up || \
	    fail "$label: uploaded tree differs from source"
	check_log put "hpn-bundle upload: n="
	[ $verify = yes ] && check_verify put

	verbose "$tid: $label (get -r)"
	${SFTP} -q -v -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes "$@" \
	    -b - ${USER}@somehost > /dev/null 2> ${LOG} <<EOF
get -r ${SRCDIR} ${DSTDIR}/down
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "$label: get -r failed with $r"
		return
	fi
	diff -r ${SRCDIR} ${DSTDIR}/down || \
	    fail "$label: downloaded tree differs from source"
	check_log get "hpn-bundle-fetch: n="
	[ $verify = yes ] && check_verify get
}

# Pass 1: parallel defaults. HPNUseBundle is yes and the server
# advertises the extension.
bundle_round_trip "parallel default" bundle -j 4

# Pass 2: the serial walk, no -j, which bundles through its own
# accumulator.
bundle_round_trip "serial default" bundle

# Pass 3: HPNUseBundle=no on the client forces the per-file path.
bundle_round_trip "HPNUseBundle=no fallback" client-off -j 4 \
    -o HPNUseBundle=no

# Pass 4: HPNBundleSize=1M, the minimum bundle size, on the serial
# walk. A file is eligible below a quarter of the target, so the 300 KiB
# file goes single-file while the rest bundle, and the 200 KiB files
# overflow one bundle, so each direction sends at least two.
bundle_round_trip "HPNBundleSize=1M serial" bundle-multi \
    -o HPNBundleSize=1M

# Pass 5: the same target on the parallel planner, whose eligibility
# check is its own code. The files are spread over four workers, so no
# single accumulator overflows.
bundle_round_trip "HPNBundleSize=1M parallel" bundle -j 4 \
    -o HPNBundleSize=1M

# Pass 6: HPNWriterPool=no on the client. It sends NO_POOL, so the
# server extracts inline, and it writes its own downloads inline.
bundle_round_trip "HPNWriterPool=no" bundle-nopool -j 4 \
    -o HPNWriterPool=no

# Pass 7: -p. Modes and mtimes ride in the record headers and are
# applied by the bundle extractors at both ends.
bundle_round_trip "preserve" bundle -j 4 -p
check_preserve ${DSTDIR}/up
check_preserve ${DSTDIR}/down

# Pass 8: -V on the parallel default. The bundle writer tees each
# member's source hash as it packs it, so the verify phase reads no
# source file.
bundle_round_trip "parallel -V" bundle -j 4 -V

# Pass 9: -V with bundling off on the client. The pipelined batch tees
# each small file from its read buffer.
bundle_round_trip "HPNUseBundle=no -V" client-off -j 4 -V \
    -o HPNUseBundle=no

# Pass 10: -V at the 1 MiB target, so the 300 KiB file travels as a
# single unit whose hash the plain upload tees.
bundle_round_trip "HPNBundleSize=1M parallel -V" bundle -j 4 -V \
    -o HPNBundleSize=1M

# Pass 11: the server side off. With sshd_config HPNUseBundle=no the
# server does not advertise the extension, so a default client takes
# the per-file path.
stop_sshd
start_sshd -oHPNUseBundle=no
bundle_round_trip "sshd HPNUseBundle=no fallback" server-off -j 4

rm -rf ${SRCDIR} ${DSTDIR}
