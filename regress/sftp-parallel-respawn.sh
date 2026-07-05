#	HPN-SSH sftp-parallel-respawn.sh
#	Placed in the Public Domain.
#
#	Worker-death recovery: kill one parallel worker's SSH child mid-
#	transfer and require the orchestrator to requeue the in-flight
#	work, respawn the worker, and finish the transfer byte-exact with
#	exit status 0.  Workers are identified by the HPN_PARALLEL_WORKER
#	marker the orchestrator sets in each worker child's environment;
#	that needs /proc/<pid>/environ, so the test is skipped where /proc
#	is unavailable.

tid="sftp parallel worker respawn"

SRCDIR=${OBJ}/respawn-src
DSTDIR=${OBJ}/respawn-dst
SFTP_LOG=${OBJ}/respawn-sftp.log

if [ ! -r /proc/self/environ ]; then
	verbose "$tid: skipped (no /proc environ support)"
	exit 0
fi

start_sshd

# 8 MiB across four files; -l 4000 (Kbit/s, per worker) stretches the
# transfer to several seconds so the kill lands mid-flight.
increase_datafile_size 2048
rm -rf ${SRCDIR} ${DSTDIR}
mkdir -p ${SRCDIR} ${DSTDIR}
for i in 1 2 3 4; do
	cp ${DATA} ${SRCDIR}/file${i}
done

verbose "$tid: throttled put -r with mid-transfer worker kill"
${SFTP} -j 2 -l 4000 -q -S "$SSH" -F $OBJ/ssh_config \
    -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > ${SFTP_LOG} 2>&1 <<EOF &
put -r ${SRCDIR} ${DSTDIR}/up
EOF
SFTP_PID=$!

# Find a worker: an ssh child of the sftp process carrying the
# HPN_PARALLEL_WORKER environment marker.  Poll up to ~5s.
WORKER=""
n=0
while [ $n -lt 25 ]; do
	for p in $(pgrep -P ${SFTP_PID} 2>/dev/null); do
		if [ -r /proc/$p/environ ] && \
		    tr '\0' '\n' < /proc/$p/environ 2>/dev/null | \
		    grep -q '^HPN_PARALLEL_WORKER='; then
			WORKER=$p
			break 2
		fi
	done
	# stop polling if the transfer already finished
	kill -0 ${SFTP_PID} 2>/dev/null || break
	sleep 0.2
	n=$((n + 1))
done

if [ -z "$WORKER" ]; then
	kill ${SFTP_PID} 2>/dev/null
	wait ${SFTP_PID} 2>/dev/null
	fail "no parallel worker found to kill (transfer too fast?)"
else
	trace "$tid: killing worker pid $WORKER"
	kill -9 ${WORKER} 2>/dev/null

	wait ${SFTP_PID}
	r=$?
	if [ $r -ne 0 ]; then
		fail "transfer failed ($r) after worker kill"
	else
		diff -r ${SRCDIR} ${DSTDIR}/up || \
		    fail "destination differs from source after worker kill"
	fi
fi

rm -rf ${SRCDIR} ${DSTDIR} ${SFTP_LOG}
