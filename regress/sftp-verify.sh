#	HPN-SSH sftp-verify.sh
#	Placed in the Public Domain.
#
#	Exercises the verified-resume hash gate (Option A) and the
#	HPNVerifyTransfer post-transfer integrity check.
#
#	The gate is the security-critical piece: a destination that is the
#	SAME SIZE as the source but has different content (the range-split
#	crash-resume sparse-hole scenario) must be detected by hashing and
#	re-transferred, NOT trusted on size alone.

tid="sftp verified resume gate and HPNVerifyTransfer"

# Need a source large enough that a full-file hash is meaningful.
increase_datafile_size 512

# ---- Part 1: the hash gate (reputv / regetv), via the direct server ----
# reputv/regetv set verify=1 per command, so no ssh_config is needed; the
# gate runs against the hpnsftp-server's hpn-check-file extension.

verbose "$tid: reputv re-transfers a same-size content mismatch (upload)"
rm -f ${COPY}.1 ${COPY}.2
cp ${DATA} ${COPY}.1
# Destination: identical SIZE to the source but all-zero content.
dd if=/dev/zero of=${COPY}.2 bs=$(wc -c < ${COPY}.1) count=1 \
    status=none 2>/dev/null
echo "reputv ${COPY}.1 ${COPY}.2" | \
    ${SFTP} -D ${SFTPSERVER} -q -b - >/dev/null 2>&1 || \
    fail "reputv failed"
cmp ${COPY}.1 ${COPY}.2 || \
    fail "gate (upload): same-size content mismatch was NOT re-transferred"

verbose "$tid: regetv re-transfers a same-size content mismatch (download)"
rm -f ${COPY}.1 ${COPY}.2
cp ${DATA} ${COPY}.1
dd if=/dev/zero of=${COPY}.2 bs=$(wc -c < ${COPY}.1) count=1 \
    status=none 2>/dev/null
echo "regetv ${COPY}.1 ${COPY}.2" | \
    ${SFTP} -D ${SFTPSERVER} -q -b - >/dev/null 2>&1 || \
    fail "regetv failed"
cmp ${COPY}.1 ${COPY}.2 || \
    fail "gate (download): same-size content mismatch was NOT re-transferred"

# A genuinely identical destination must be detected as complete (skipped),
# and the result must still match - i.e. no false "re-transfer" needed and
# no corruption.
verbose "$tid: reputv treats an identical destination as complete"
rm -f ${COPY}.1 ${COPY}.2
cp ${DATA} ${COPY}.1
cp ${DATA} ${COPY}.2
echo "reputv ${COPY}.1 ${COPY}.2" | \
    ${SFTP} -D ${SFTPSERVER} -q -b - >/dev/null 2>&1 || \
    fail "reputv (identical) failed"
cmp ${COPY}.1 ${COPY}.2 || fail "reputv corrupted an identical file"

# ---- Part 2: -V whole-file verify (post-transfer integrity check) ----
# -V is the program switch that replaced the old HPNVerifyTransfer
# ssh_config option.  A clean transfer must verify successfully: exit 0
# and no "VERIFY FAILED" output.

start_sshd

verbose "$tid: -V clean upload verifies (no false positive)"
rm -f ${COPY}.2
echo "put ${DATA} ${COPY}.2" | \
    ${SFTP} -V -q -S "$SSH" -F $OBJ/ssh_config -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > ${OBJ}/verify.out 2>&1
r=$?
if [ $r -ne 0 ]; then
	cat ${OBJ}/verify.out >&2
	fail "-V clean upload exit $r (expected 0)"
fi
cmp ${DATA} ${COPY}.2 || fail "-V upload corrupted the file"
if grep -q "VERIFY FAILED" ${OBJ}/verify.out; then
	fail "-V reported a false-positive mismatch on a clean transfer"
fi

stop_sshd
rm -f ${COPY}.1 ${COPY}.2 ${OBJ}/verify.out
