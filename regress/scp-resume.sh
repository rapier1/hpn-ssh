#	Placed in the Public Domain.

tid="scp-resume"

COPY2=${OBJ}/copy2
DIR=${COPY}.dd
DIR2=${COPY}.dd2

maybe_add_scp_path_to_sshd

SRC=`dirname ${SCRIPT}`
cp ${SRC}/scp-ssh-wrapper.sh ${OBJ}/scp-ssh-wrapper.scp
chmod 755 ${OBJ}/scp-ssh-wrapper.scp
export SCP # used in scp-ssh-wrapper.scp

# We test up to 1MB, ensure source data is large enough.
increase_datafile_size 1200

scpclean() {
	rm -rf ${COPY} ${COPY2} ${DIR} ${DIR2}
	mkdir -p ${DIR} ${DIR2}
	chmod 755 ${DIR} ${DIR2}
}

# The resume function uses xxhash (bundled, header-only) -- no OpenSSL needed.
# Test both legacy SCP protocol (-O -Z) and normal SFTP-path (-Z), and both
# put and get directions.

for mode in legacy sftp; do
	if test $mode = legacy; then
		# -O forces legacy SCP protocol; -S wires in the ssh wrapper
		scpopts="-O -S ${OBJ}/scp-ssh-wrapper.scp"
		tag="$tid: legacy (-O)"
	else
		scpopts="-D ${SFTPSERVER}"
		tag="$tid: sftp"
	fi

	for direction in put get; do
		for size in 0 1k size-1 larger corrupt same; do
			verbose "$tag: $direction size=${size}"
			trace "$tag: test $direction $size"
			scpclean
			rm -f ${COPY}.1 ${COPY}.2

			# COPY.1 is the reference (complete) source file.
			cp ${DATA} ${COPY}.1

			# COPY.2 is the destination (partial/empty/etc).
			case "${size}" in
			0)
				touch ${COPY}.2
				;;
			size-1)
				dd if=${COPY}.1 of=${COPY}.2 bs=1023 count=1 \
				    >/dev/null 2>&1
				;;
			larger)
				# Dest is larger than source; should overwrite fully
				# and ftruncate to source size.
				cp ${COPY}.1 ${COPY}.2
				dd if=/dev/urandom bs=512 count=1 >>${COPY}.2 \
				    2>/dev/null
				;;
			corrupt)
				# Same length as 1k partial but wrong content;
				# hash mismatch should trigger full retransfer.
				dd if=/dev/urandom of=${COPY}.2 bs=1024 count=1 \
				    >/dev/null 2>&1
				;;
			same)
				cp ${COPY}.1 ${COPY}.2
				;;
			*)
				dd if=${COPY}.1 of=${COPY}.2 bs=${size} count=1 \
				    >/dev/null 2>&1
				;;
			esac

			if test $direction = put; then
				if test $mode = sftp; then
					case "${size}" in
					same|larger)
						# SFTP put refuses when dest >= source size.
						$SCP -Z $scpopts ${COPY}.1 somehost:${COPY}.2 \
						    && fail "$tag put -Z should have refused size=${size}"
						continue
						;;
					esac
				fi
				$SCP -Z $scpopts ${COPY}.1 somehost:${COPY}.2 \
				    || fail "$tag put -Z failed size=${size}"
				cmp ${COPY}.1 ${COPY}.2 \
				    || fail "$tag corrupted after put -Z size=${size}"
			else
				$SCP -Z $scpopts somehost:${COPY}.1 ${COPY}.2 \
				    || fail "$tag get -Z failed size=${size}"
				cmp ${COPY}.1 ${COPY}.2 \
				    || fail "$tag corrupted after get -Z size=${size}"
			fi
		done
	done
done

scpclean
rm -f ${OBJ}/scp-ssh-wrapper.scp
