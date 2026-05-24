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

# Verify a transfer succeeds with the supplied -o option(s).
expect_ok() {
	label="$1"
	shift
	cclean
	seed_dataset

	verbose "$tid: $label"
	${SFTP} -j 2 -q -S "$SSH" -F $OBJ/ssh_config \
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
}

# Verify the option triggers the readconf clamp-with-warning path.
expect_clamp_warning() {
	label="$1"
	pattern="$2"
	shift 2
	cclean
	seed_dataset

	verbose "$tid: $label (expect clamp warning)"
	${SFTP} -j 2 -q -S "$SSH" -F $OBJ/ssh_config \
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
}

# Happy-path acceptance for each option.
expect_ok "HPNUseBundle=yes"          -o HPNUseBundle=yes
expect_ok "HPNUseBundle=no"           -o HPNUseBundle=no
expect_ok "HPNBundleSize=64K"         -o HPNBundleSize=64K
expect_ok "HPNBundleSize=4M"          -o HPNBundleSize=4M
expect_ok "HPNMaxRetries=1"           -o HPNMaxRetries=1
expect_ok "HPNMaxRetries=20"          -o HPNMaxRetries=20
expect_ok "HPNMaxAuthConcurrent=1"    -o HPNMaxAuthConcurrent=1
expect_ok "HPNMaxAuthConcurrent=16"   -o HPNMaxAuthConcurrent=16

# Out-of-range clamp paths.  fill_default_options emits the warning to
# stderr and proceeds with the bound value; the transfer should still
# succeed.
expect_clamp_warning "HPNMaxRetries=0 below minimum" \
    "HPNMaxRetries" -o HPNMaxRetries=0
expect_clamp_warning "HPNMaxRetries=999 above maximum" \
    "HPNMaxRetries" -o HPNMaxRetries=999
expect_clamp_warning "HPNMaxAuthConcurrent=0 below minimum" \
    "HPNMaxAuthConcurrent" -o HPNMaxAuthConcurrent=0
expect_clamp_warning "HPNMaxAuthConcurrent=999 above maximum" \
    "HPNMaxAuthConcurrent" -o HPNMaxAuthConcurrent=999

cclean
