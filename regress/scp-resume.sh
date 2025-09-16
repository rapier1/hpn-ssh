#	$OpenBSD: scp.sh,v 1.19 2023/09/08 05:50:57 djm Exp $
#	Placed in the Public Domain.

tid="scp-resume"

#set -x

COPY2=${OBJ}/copy2
DIR=${COPY}.dd
DIR2=${COPY}.dd2
COPY3=${OBJ}/copy.glob[123]
DIR3=${COPY}.dd.glob[456]
DIFFOPT="-rN"

# Figure out if diff does not understand "-N"
if ! diff -N ${SRC}/scp.sh ${SRC}/scp.sh 2>/dev/null; then
	DIFFOPT="-r"
fi

maybe_add_scp_path_to_sshd

SRC=`dirname ${SCRIPT}`
cp ${SRC}/scp-ssh-wrapper.sh ${OBJ}/scp-ssh-wrapper.scp
chmod 755 ${OBJ}/scp-ssh-wrapper.scp
export SCP # used in scp-ssh-wrapper.scp

scpclean() {
	rm -rf ${COPY} ${COPY2} ${DIR} ${DIR2} ${COPY3} ${DIR3}
	mkdir ${DIR} ${DIR2} ${DIR3}
	chmod 755 ${DIR} ${DIR2} ${DIR3}
}

# Create directory structure for recursive copy tests.
forest() {
	scpclean
	rm -rf ${DIR2}
	cp ${DATA} ${DIR}/copy
	ln -s ${DIR}/copy ${DIR}/copy-sym
	mkdir ${DIR}/subdir
	cp ${DATA} ${DIR}/subdir/copy
	ln -s ${DIR}/subdir ${DIR}/subdir-sym
}

for mode in scp sftp ; do
	tag="$tid: $mode mode"
	if test $mode = scp ; then
		scpopts="-O -S ${OBJ}/scp-ssh-wrapper.scp"
	else
		scpopts="-qs -D ${SFTPSERVER}"
	fi

	# we don't want to run this test if openssl is not installed
	# if isn't then the usage text won't have the "vZ" in the
	# output
	if $SCP -Z 2>&1 | grep "vZ" > /dev/null 2>&1
	then
	    verbose "$tag: resume remote dir to local dir"
	    scpclean
	    rm -rf ${DIR2}
	    cp ${DATA} ${DIR}/copy1
	    cp ${DATA} ${DIR}/copy2
	    cp ${DATA} ${DIR}/copy3
	    $SCP -r $scpopts somehost:${DIR} ${DIR2} || fail "copy failed"
	    truncate --size=-512 ${DIR2}/copy1
	    truncate --size=+512 ${DIR2}/copy2
	    $SCP -Z $scpopts somehost:${DIR}/* ${DIR2} || fail "resume failed"
	    for i in $(cd ${DIR} && echo *); do
		cmp ${DIR}/$i ${DIR2}/$i || fail "corrupted resume copy"
	    done
	fi
done

scpclean
rm -f ${OBJ}/scp-ssh-wrapper.scp
