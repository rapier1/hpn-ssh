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
# and no "VERIFY FAILED" output, and the phase must use the source hash
# teed during the upload rather than read the source again, which the
# -v log names once per file.

start_sshd

verbose "$tid: -V clean upload verifies (no false positive)"
rm -f ${COPY}.2
echo "put ${DATA} ${COPY}.2" | \
    ${SFTP} -V -q -v -S "$SSH" -F $OBJ/ssh_config -P ${PORT} -o BatchMode=yes \
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
teed=$(grep -c "verify: teed source hash for" ${OBJ}/verify.out)
[ "$teed" -eq 1 ] || \
    fail "-V clean upload used $teed teed source hashes, wanted 1"

# ---- Part 3: -V on a serial recursive upload ----
# Each file's source hash is teed as the upload reads it and taken into
# the verify phase, so the phase hashes only the remote copies. At -v
# the client log names every teed hash; the count must match the
# non-empty files (an empty file is verified on size alone), and no
# mismatch may be reported.

VSRC=${OBJ}/verify-src
VDST=${OBJ}/verify-dst
rm -rf ${VSRC} ${VDST}
mkdir -p ${VSRC}/sub ${VDST}
for i in 1 2 3 4; do
	dd if=/dev/urandom of=${VSRC}/f${i} bs=16k count=1 2>/dev/null || \
	    fail "could not seed the verify tree"
done
dd if=/dev/urandom of=${VSRC}/sub/s1 bs=100k count=3 2>/dev/null || \
    fail "could not seed the verify tree"
touch ${VSRC}/empty || fail "could not seed the verify tree"

verbose "$tid: -V serial put -r tees every source hash"
${SFTP} -V -q -v -S "$SSH" -F $OBJ/ssh_config -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > /dev/null 2> ${OBJ}/verify.out <<EOF
put -r ${VSRC} ${VDST}/up
EOF
r=$?
if [ $r -ne 0 ]; then
	cat ${OBJ}/verify.out >&2
	fail "-V put -r exit $r (expected 0)"
fi
diff -r ${VSRC} ${VDST}/up || fail "-V put -r tree differs from source"
teed=$(grep -c "verify: teed source hash for" ${OBJ}/verify.out)
want=$(find ${VSRC} -type f -size +0 | wc -l | tr -d ' ')
if [ "$teed" -ne "$want" ]; then
	cp ${OBJ}/verify.out ${OBJ}/verify-failed.out
	fail "-V put -r used $teed teed source hashes, wanted $want"
fi
grep -q "VERIFY FAILED" ${OBJ}/verify.out && \
    fail "-V put -r reported a false-positive mismatch"

stop_sshd
rm -rf ${VSRC} ${VDST}
rm -f ${COPY}.1 ${COPY}.2 ${OBJ}/verify.out
