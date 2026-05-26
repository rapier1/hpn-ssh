#	HPN-SSH sftp-parallel.sh
#	Placed in the Public Domain.

tid="sftp parallel streams"

COPY2=${OBJ}/copy2
SRCDIR=${OBJ}/par-src
DSTDIR=${OBJ}/par-dst

parclean() {
	rm -rf ${COPY} ${COPY2} ${SRCDIR} ${DSTDIR}
	mkdir -p ${SRCDIR} ${DSTDIR}
}

# parallel transfers require a real sshd (ControlMaster)
start_sshd

# Ensure test data is large enough to exercise parallel paths
increase_datafile_size 512

# Single-file tests: upload and download at various stream counts
for J in 1 2 4; do
	verbose "$tid: put single file j=$J"
	parclean
	${SFTP} -j $J -q -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes \
	    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
put ${DATA} ${COPY}
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "put j=$J failed with $r"
	else
		cmp ${DATA} ${COPY} || fail "corrupted copy after put j=$J"
	fi

	verbose "$tid: get single file j=$J"
	parclean
	${SFTP} -j $J -q -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes \
	    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
get ${DATA} ${COPY}
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "get j=$J failed with $r"
	else
		cmp ${DATA} ${COPY} || fail "corrupted copy after get j=$J"
	fi
done

# Multi-file tests: put and get several files at j=2,4
for J in 2 4; do
	verbose "$tid: put multiple files j=$J"
	parclean
	# create a handful of small files
	for i in 1 2 3 4 5; do
		cp ${DATA} ${SRCDIR}/file${i}
	done
	${SFTP} -j $J -q -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes \
	    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
put ${SRCDIR}/file1 ${DSTDIR}/file1
put ${SRCDIR}/file2 ${DSTDIR}/file2
put ${SRCDIR}/file3 ${DSTDIR}/file3
put ${SRCDIR}/file4 ${DSTDIR}/file4
put ${SRCDIR}/file5 ${DSTDIR}/file5
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "multi-put j=$J failed with $r"
	else
		for i in 1 2 3 4 5; do
			cmp ${SRCDIR}/file${i} ${DSTDIR}/file${i} || \
			    fail "corrupted file${i} after multi-put j=$J"
		done
	fi

	verbose "$tid: get multiple files j=$J"
	parclean
	for i in 1 2 3 4 5; do
		cp ${DATA} ${SRCDIR}/file${i}
	done
	mkdir -p ${DSTDIR}
	${SFTP} -j $J -q -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes \
	    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
get ${SRCDIR}/file1 ${DSTDIR}/file1
get ${SRCDIR}/file2 ${DSTDIR}/file2
get ${SRCDIR}/file3 ${DSTDIR}/file3
get ${SRCDIR}/file4 ${DSTDIR}/file4
get ${SRCDIR}/file5 ${DSTDIR}/file5
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "multi-get j=$J failed with $r"
	else
		for i in 1 2 3 4 5; do
			cmp ${SRCDIR}/file${i} ${DSTDIR}/file${i} || \
			    fail "corrupted file${i} after multi-get j=$J"
		done
	fi
done

# Recursive directory transfer tests at j=2,4
for J in 2 4; do
	verbose "$tid: recursive put j=$J"
	parclean
	mkdir -p ${SRCDIR}/sub1 ${SRCDIR}/sub2
	cp ${DATA} ${SRCDIR}/top
	cp ${DATA} ${SRCDIR}/sub1/a
	cp ${DATA} ${SRCDIR}/sub1/b
	cp ${DATA} ${SRCDIR}/sub2/c
	${SFTP} -j $J -q -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes \
	    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
put -r ${SRCDIR} ${DSTDIR}/uploaded
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "recursive put j=$J failed with $r"
	else
		diff -r ${SRCDIR} ${DSTDIR}/uploaded || \
		    fail "recursive put j=$J: destination differs from source"
	fi

	verbose "$tid: recursive get j=$J"
	parclean
	mkdir -p ${SRCDIR}/sub1 ${SRCDIR}/sub2
	cp ${DATA} ${SRCDIR}/top
	cp ${DATA} ${SRCDIR}/sub1/a
	cp ${DATA} ${SRCDIR}/sub1/b
	cp ${DATA} ${SRCDIR}/sub2/c
	${SFTP} -j $J -q -S "$SSH" -F $OBJ/ssh_config \
	    -P ${PORT} -o BatchMode=yes \
	    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
get -r ${SRCDIR} ${DSTDIR}/downloaded
EOF
	r=$?
	if [ $r -ne 0 ]; then
		fail "recursive get j=$J failed with $r"
	else
		diff -r ${SRCDIR} ${DSTDIR}/downloaded || \
		    fail "recursive get j=$J: destination differs from source"
	fi
done

parclean
