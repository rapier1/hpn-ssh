#	HPN-SSH sftp-parallel-tput.sh
#	Placed in the Public Domain.
#
#	Adaptive throughput-outlier detection on a healthy path.  The
#	detector samples each worker once per watchdog slow-tick (~1s),
#	skips the first tick to seed its baselines, and needs
#	TPUT_EMA_WARMUP_TICKS more before it will judge anyone, so a
#	transfer has to run past ~7s for the classifier to reach its
#	second pass at all.  This test throttles two workers to a rate
#	comfortably above the path-health floor and keeps them there long
#	enough for that to happen, then requires the transfer to finish
#	byte-exact with nobody killed, flagged, or respawned.
#
#	It also pins the floor itself.  The detector stores rates in bytes
#	per second; the floor is 2000 * 1024.  An error in that scaling is
#	a factor of 1024 either way, which shows up in the startup line as
#	2.0KB/s or 2.0GB/s instead of 2.0MB/s.

tid="sftp parallel throughput detection"

SRCDIR=${OBJ}/tput-src
DSTDIR=${OBJ}/tput-dst
SFTP_LOG=${OBJ}/tput-sftp.log

start_sshd

# 80 MB in two files.  -l 32768 is Kbit/s per worker, so each worker runs
# at ~4 MiB/s, twice the 2 MiB/s floor, and 40 MB apiece takes ~10s: one
# tick to seed, five to warm the EMA, and margin.  Zeros are fine here
# since compression is off by default and the throttle counts bytes.
rm -rf ${SRCDIR} ${DSTDIR}
mkdir -p ${SRCDIR} ${DSTDIR}
for i in 1 2; do
	dd if=/dev/zero of=${SRCDIR}/file${i} bs=1m count=40 \
	    >/dev/null 2>&1 ||
		dd if=/dev/zero of=${SRCDIR}/file${i} bs=1M count=40 \
		    >/dev/null 2>&1 ||
		fatal "could not create test data"
done

verbose "$tid: throttled put -r past the EMA warmup"
${SFTP} -j 2 -l 32768 -v -S "$SSH" -F $OBJ/ssh_config \
    -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > ${SFTP_LOG} 2>&1 <<EOF
put -r ${SRCDIR} ${DSTDIR}/up
EOF
r=$?
if [ $r -ne 0 ]; then
	fail "throttled parallel put failed (exit $r)"
fi

for i in 1 2; do
	cmp ${SRCDIR}/file${i} ${DSTDIR}/up/file${i} ||
		fail "file${i} differs after throttled parallel put"
done

# The floor is a byte rate, so it must read as megabytes.
grep -q "tput-outlier detection: healthy=2.0MB/s" ${SFTP_LOG} ||
	fail "path-health floor is not 2 MiB/s (see ${SFTP_LOG})"

# Nothing about this path is unhealthy, so nobody should have been
# touched.  Any of these means the detector fired on a healthy fleet.
for pat in "born-slow kill" "born-dead fast-kill" "tput-outlier:" \
    "declared dead" "will attempt to respawn"; do
	if grep -q "${pat}" ${SFTP_LOG}; then
		fail "detector fired on a healthy path: ${pat}"
	fi
done

# The negative greps above prove nothing unless the detector actually ran,
# and it only samples once per watchdog slow-tick.  It logs a sample line
# on every fifth call, so the 6 calls it needs before it will judge anyone
# (one to seed baselines, TPUT_EMA_WARMUP_TICKS more to warm the EMA) yield
# exactly 2 lines.  Fewer than that means the transfer finished before the
# classifier ever looked at a worker, and this test proved nothing.
samples=`grep -c "tput sample" ${SFTP_LOG}`
if [ "$samples" -lt 2 ]; then
	fail "detector logged $samples samples, need 2 (transfer too short?)"
fi

# Keep the tree and the log on failure; they are the only evidence.
if [ ${RESULT} -eq 0 ]; then
	rm -rf ${SRCDIR} ${DSTDIR} ${SFTP_LOG}
fi
