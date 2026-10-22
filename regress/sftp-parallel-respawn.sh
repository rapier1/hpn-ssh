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
	skip "no /proc environ support"
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
${SFTP} -j 2 -l 4000 -q -v -S "$SSH" -F $OBJ/ssh_config \
    -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > ${SFTP_LOG} 2>&1 <<EOF &
put -r ${SRCDIR} ${DSTDIR}/up
EOF
SFTP_PID=$!

# A kill during parallel setup makes the whole setup fail and fall back
# to one stream, which tests nothing here. Wait until a file has data,
# so setup is over and the transfer is in flight. Poll up to ~10s.
n=0
while [ $n -lt 50 ]; do
	landed=$(find ${DSTDIR}/up -type f -size +0 2>/dev/null | wc -l)
	[ "$landed" -ge 1 ] && break
	kill -0 ${SFTP_PID} 2>/dev/null || break
	sleep 0.2
	n=$((n + 1))
done
if [ "$landed" -lt 1 ]; then
	kill ${SFTP_PID} 2>/dev/null
	wait ${SFTP_PID} 2>/dev/null
	fatal "no file had data after ~10s, so no kill would land mid-transfer"
fi
grep "falling back to single-stream mode" ${SFTP_LOG} >/dev/null && \
    fail "parallel setup failed before the kill"

# Find the busy worker. Workers are the ssh children of the sftp process
# that carry the HPN_PARALLEL_WORKER environment marker. A few files
# travel as one unit, a bundle or a pipelined batch, on a single worker,
# so the other worker is idle and killing it leaves nothing to requeue.
# The busy one is the worker whose ssh has written the most.
WORKER=""
most=-1
for p in $(pgrep -P ${SFTP_PID} 2>/dev/null); do
	tr '\0' '\n' < /proc/$p/environ 2>/dev/null | \
	    grep -q '^HPN_PARALLEL_WORKER=' || continue
	written=$(awk '/^wchar:/ { print $2 }' /proc/$p/io 2>/dev/null)
	written=${written:-0}
	if [ "$written" -gt "$most" ]; then
		most=$written
		WORKER=$p
	fi
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
	# The surviving worker could finish the transfer alone, so the log
	# must show the killed worker dropping mid-transfer and being
	# respawned. -v after -q brings back the debug lines.
	grep "will attempt to respawn" ${SFTP_LOG} >/dev/null || \
	    fail "the killed worker was not seen to drop mid-transfer"
	grep "initiating respawn for" ${SFTP_LOG} >/dev/null || \
	    fail "the orchestrator did not respawn the killed worker"
	grep "worker respawn failed" ${SFTP_LOG} >/dev/null && \
	    fail "the respawned worker failed to start"
fi

# Keep the tree and the log on failure; they are the only evidence.
if [ ${RESULT} -eq 0 ]; then
	rm -rf ${SRCDIR} ${DSTDIR} ${SFTP_LOG}
fi
