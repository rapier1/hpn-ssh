#	HPN-SSH sftp-hpn-config.sh
#	Placed in the Public Domain.
#
#	Verifies the four ssh_config options promoted in 18.10 are
#	parsed, applied, and clamped on out-of-range values:
#	  HPNUseBundle, HPNBundleSize, HPNMaxRetries, HPNMaxAuthConcurrent

tid="sftp HPN ssh_config options"

SRCDIR=${OBJ}/hpncfg-src
DSTDIR=${OBJ}/hpncfg-dst
STDERR=${OBJ}/hpncfg.err

cclean() {
	rm -rf ${SRCDIR} ${DSTDIR} ${STDERR}
	mkdir -p ${SRCDIR} ${DSTDIR}
}

start_sshd

# Small dataset so each pass is cheap; eight 4 KiB files round-trip in
# well under a second.
seed_dataset() {
	for i in 1 2 3 4 5 6 7 8; do
		dd if=/dev/urandom of=${SRCDIR}/f${i} bs=4k count=1 \
		    status=none 2>/dev/null || \
		    fatal "could not seed config-test dataset"
	done
}

# Verify a transfer succeeds with the supplied -o option(s), and that
# hpnsftp applied them: at -v it logs the HPN options it resolved, which
# must match $2.
expect_ok() {
	label="$1"
	applied="$2"
	shift 2
	cclean
	seed_dataset

	verbose "$tid: $label"
	${SFTP} -j 2 -q -v -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes "$@" \
	    -b - ${USER}@somehost > /dev/null 2>${STDERR} <<EOF
put -r ${SRCDIR} ${DSTDIR}/up
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "$label: hpnsftp exit $r"
		cat ${STDERR} >&2
		return
	fi
	diff -r ${SRCDIR} ${DSTDIR}/up || \
	    fail "$label: transferred tree differs from source"
	grep "$applied" ${STDERR} >/dev/null || \
	    fail "$label: hpnsftp did not apply '$applied'"
}

# Verify the option triggers the readconf clamp-with-warning path, and
# that hpnsftp applied the bound value, $3.
expect_clamp_warning() {
	label="$1"
	pattern="$2"
	applied="$3"
	shift 3
	cclean
	seed_dataset

	verbose "$tid: $label (expect clamp warning)"
	${SFTP} -j 2 -q -v -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes "$@" \
	    -b - ${USER}@somehost > /dev/null 2>${STDERR} <<EOF
put -r ${SRCDIR} ${DSTDIR}/up
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "$label: hpnsftp exit $r (warning was expected, not failure)"
		cat ${STDERR} >&2
		return
	fi
	if ! grep -q "$pattern" ${STDERR}; then
		fail "$label: expected clamp warning matching '$pattern' on stderr"
		cat ${STDERR} >&2
		return
	fi
	diff -r ${SRCDIR} ${DSTDIR}/up || \
	    fail "$label: transferred tree differs from source"
	grep "$applied" ${STDERR} >/dev/null || \
	    fail "$label: hpnsftp did not apply '$applied'"
}

# Happy-path acceptance for each option. A count is followed by a
# non-digit in the log, so 1 does not match 16.
expect_ok "HPNUseBundle=yes" "HPNUseBundle=yes" -o HPNUseBundle=yes
expect_ok "HPNUseBundle=no" "HPNUseBundle=no" -o HPNUseBundle=no
expect_ok "HPNBundleSize=1M" "HPNBundleSize=1048576[^0-9]" \
    -o HPNBundleSize=1M
expect_ok "HPNBundleSize=4M" "HPNBundleSize=4194304[^0-9]" \
    -o HPNBundleSize=4M
expect_ok "HPNMaxRetries=1" "HPNMaxRetries=1[^0-9]" -o HPNMaxRetries=1
expect_ok "HPNMaxRetries=20" "HPNMaxRetries=20[^0-9]" -o HPNMaxRetries=20
expect_ok "HPNMaxAuthConcurrent=1" "HPNMaxAuthConcurrent=1[^0-9]" \
    -o HPNMaxAuthConcurrent=1
expect_ok "HPNMaxAuthConcurrent=16" "HPNMaxAuthConcurrent=16[^0-9]" \
    -o HPNMaxAuthConcurrent=16

# Out-of-range clamp paths.  fill_default_options emits the warning to
# stderr and proceeds with the bound value; the transfer should still
# succeed.
expect_clamp_warning "HPNBundleSize=64K below minimum" \
    "HPNBundleSize 65536 is below the minimum" \
    "HPNBundleSize=1048576[^0-9]" -o HPNBundleSize=64K
expect_clamp_warning "HPNMaxRetries=0 below minimum" \
    "HPNMaxRetries 0 is below the minimum" \
    "HPNMaxRetries=1[^0-9]" -o HPNMaxRetries=0
expect_clamp_warning "HPNMaxRetries=999 above maximum" \
    "HPNMaxRetries 999 is above the maximum" \
    "HPNMaxRetries=20[^0-9]" -o HPNMaxRetries=999
expect_clamp_warning "HPNMaxAuthConcurrent=0 below minimum" \
    "HPNMaxAuthConcurrent 0 is below the minimum" \
    "HPNMaxAuthConcurrent=1[^0-9]" -o HPNMaxAuthConcurrent=0
expect_clamp_warning "HPNMaxAuthConcurrent=999 above maximum" \
    "HPNMaxAuthConcurrent 999 is above the maximum" \
    "HPNMaxAuthConcurrent=64[^0-9]" -o HPNMaxAuthConcurrent=999

cclean
