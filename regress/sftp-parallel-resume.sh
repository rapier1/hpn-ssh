#	HPN-SSH sftp-parallel-resume.sh
#	Placed in the Public Domain.
#
#	Pins the parallel-path reget contract: a visibly short local
#	partial (the state an aborted parallel/bundle download leaves
#	behind - the client truncates the in-flight entry to its written
#	length) must complete byte-exact with a plain size-based reget
#	through the -j orchestrator.  Complements sftp-resume.sh, which
#	covers single-stream -a via the direct server path.

tid="sftp parallel reget resume"

PLOG=${OBJ}/sftp-parallel-resume.log

# parallel transfers require a real sshd
start_sshd

# 1200 KiB source, so every partial below is well short of it.
increase_datafile_size 1200

for size in 0 1023 600k; do
	verbose "$tid: reget onto ${size}-byte partial (j=4)"
	rm -f ${COPY}
	case "${size}" in
	0)	touch ${COPY}
		;;
	*)	dd if=${DATA} of=${COPY} bs=${size} count=1 >/dev/null 2>&1
		;;
	esac

	${SFTP} -j 4 -q -v -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes \
	    -b - ${USER}@somehost > /dev/null 2>${PLOG} <<EOF
reget ${DATA} ${COPY}
EOF
	r=$?
	# A failed parallel setup falls back to one stream and still
	# succeeds, so the log must not show that fallback. -v after -q
	# brings back the line that reports it.
	grep "falling back to single-stream mode" ${PLOG} >/dev/null && \
	    fail "reget onto ${size} partial did not use the -j orchestrator"
	if [ $r -ne 0 ]; then
		fail "reget onto ${size} partial failed with $r"
	else
		cmp ${DATA} ${COPY} || \
		    fail "corrupted copy after reget onto ${size} partial"
	fi
done

rm -f ${COPY} ${PLOG}
