#	HPN-SSH sftp-worker-log-dir.sh
#	Placed in the Public Domain.
#
#	Verifies the -W <dir> flag: each parallel worker should write its
#	SSH child's stderr to <dir>/hpnssh-worker-<pid>.stderr.  Also
#	checks that without -W no such files appear under <dir> - the
#	production default is "inherit stderr".

tid="sftp -W worker log directory"

LOGDIR=${OBJ}/worker-logs
SRCDIR=${OBJ}/wlog-src
DSTDIR=${OBJ}/wlog-dst

wclean() {
	rm -rf ${LOGDIR} ${SRCDIR} ${DSTDIR}
	mkdir -p ${LOGDIR} ${SRCDIR} ${DSTDIR}
	for i in 1 2 3 4; do
		dd if=/dev/urandom of=${SRCDIR}/f${i} bs=4k count=1 \
		    status=none 2>/dev/null
	done
}

start_sshd

# --- pass 1: -W set, expect files to appear ----------------------------------
wclean
verbose "$tid: -W ${LOGDIR} should produce per-worker stderr files"
${SFTP} -j 4 -W ${LOGDIR} -q -S "$SSH" -F $OBJ/ssh_config \
    -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
put -r ${SRCDIR} ${DSTDIR}/with-W
EOF
r=$?
if [ $r -ne 0 ]; then
	fail "transfer with -W failed (rc=$r)"
fi
nlogs=$(ls ${LOGDIR}/hpnssh-worker-*.stderr 2>/dev/null | wc -l)
if [ ${nlogs} -lt 1 ]; then
	fail "-W ${LOGDIR}: expected at least one hpnssh-worker-*.stderr file, got ${nlogs}"
fi
# We deliberately do NOT assert non-empty content here.  -W's contract is
# "create the per-worker stderr file at the documented path" - it cannot
# guarantee that ssh emits anything.  Under the regress framework, $SSH is
# wrapped by ssh-log-wrapper.sh which invokes ssh -E <logfile>, peeling
# debug output OFF stderr into a separate file; our redirect then catches
# an empty stream.  In real-world hpnsftp use (no wrapper) the workers'
# ssh debug lines land in these files as documented.

# --- pass 2: no -W, expect NO files in LOGDIR --------------------------------
wclean
verbose "$tid: no -W should leave LOGDIR empty"
${SFTP} -j 4 -q -S "$SSH" -F $OBJ/ssh_config \
    -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
put -r ${SRCDIR} ${DSTDIR}/without-W
EOF
r=$?
if [ $r -ne 0 ]; then
	fail "transfer without -W failed (rc=$r)"
fi
nlogs=$(ls ${LOGDIR}/hpnssh-worker-*.stderr 2>/dev/null | wc -l)
if [ ${nlogs} -ne 0 ]; then
	fail "no -W: expected 0 hpnssh-worker-*.stderr files in LOGDIR, got ${nlogs}"
fi

# --- pass 3: -W with an uncreatable directory should be fatal ---------------
# /etc is writable only by root; under regular user the mkdir-p inside
# /etc/will-fail/... cannot succeed and the parse should fatal.
verbose "$tid: -W /etc/hpnsftp-cant-create-here should be fatal"
${SFTP} -W /etc/hpnsftp-cant-create-here -j 2 -q -S "$SSH" \
    -F $OBJ/ssh_config -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > /dev/null 2>${OBJ}/wlog-err <<EOF
put ${SRCDIR}/f1 ${DSTDIR}/x
EOF
r=$?
if [ $r -eq 0 ]; then
	fail "-W /etc/hpnsftp-cant-create-here should have been fatal but rc=0"
fi

# --- pass 4: -W with no argument should be a usage error --------------------
verbose "$tid: -W with no argument should be usage error"
${SFTP} -W 2>${OBJ}/wlog-err </dev/null
r=$?
if [ $r -eq 0 ]; then
	fail "-W with no argument should be usage error but rc=0"
fi

rm -rf ${LOGDIR} ${SRCDIR} ${DSTDIR} ${OBJ}/wlog-err
