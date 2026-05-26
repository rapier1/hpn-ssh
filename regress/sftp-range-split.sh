#	HPN-SSH sftp-range-split.sh
#	Placed in the Public Domain.
#
#	Exercises the byte-range parallelism path that splits a single
#	large file across multiple workers.  The -M flag sets the
#	minimum file size (MiB) above which range-split kicks in.

tid="sftp byte-range split"

BIG=${OBJ}/bigfile
COPY=${OBJ}/bigcopy
DSTDIR=${OBJ}/range-dst

rclean() {
	rm -rf ${BIG} ${COPY} ${DSTDIR}
	mkdir -p ${DSTDIR}
}

# Range-split requires multiple workers + the orchestrator.
start_sshd

# -M is bounded by sftp.c to [64, 10240] MiB, so range-split only kicks
# in for files larger than 64 MiB.  Use a 128 MiB file from /dev/zero
# (compressibility doesn't matter on the SSH wire) so the test stays
# fast on loopback while still exercising splitting.
rclean
dd if=/dev/zero of=${BIG} bs=1M count=128 status=none 2>/dev/null || \
    fatal "could not create 128 MiB test file"

# Pass 1: -M 64 (the smallest legal threshold) forces range-split.
verbose "$tid: put with -M 64 (range-split forced)"
${SFTP} -j 4 -M 64 -q -S "$SSH" -F $OBJ/ssh_config \
    -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
put ${BIG} ${DSTDIR}/split
EOF
r=$?
if [ $r -ne 0 ]; then
	fail "put -M 64 failed with $r"
else
	cmp ${BIG} ${DSTDIR}/split || \
	    fail "range-split put produced corrupt copy"
fi

# Pass 2: -M 256 leaves the file as a single whole-file unit (128 MiB
# below the 256 MiB threshold).  Same workload, different path.
verbose "$tid: put with -M 256 (whole-file path)"
rm -f ${DSTDIR}/whole
${SFTP} -j 4 -M 256 -q -S "$SSH" -F $OBJ/ssh_config \
    -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
put ${BIG} ${DSTDIR}/whole
EOF
r=$?
if [ $r -ne 0 ]; then
	fail "put -M 256 failed with $r"
else
	cmp ${BIG} ${DSTDIR}/whole || \
	    fail "whole-file put produced corrupt copy"
fi

# Pass 3: range-split download path.
verbose "$tid: get with -M 64 (range-split download)"
rm -f ${COPY}
${SFTP} -j 4 -M 64 -q -S "$SSH" -F $OBJ/ssh_config \
    -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
get ${BIG} ${COPY}
EOF
r=$?
if [ $r -ne 0 ]; then
	fail "get -M 64 failed with $r"
else
	cmp ${BIG} ${COPY} || \
	    fail "range-split get produced corrupt copy"
fi

rclean
rm -f ${BIG}
