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
# Verified resume (-Z) is SFTP-only: confirm the legacy SCP protocol (-O)
# refuses it, then exercise the supported SFTP path for both put and get.

# Verified resume (-Z) is SFTP-only.  Confirm the legacy SCP protocol (-O)
# refuses the combination loudly instead of silently degrading.
verbose "$tid: legacy (-O) -Z is refused"
scpclean
rm -f ${COPY}.1 ${COPY}.2
cp ${DATA} ${COPY}.1
touch ${COPY}.2
$SCP -Z -O -S ${OBJ}/scp-ssh-wrapper.scp ${COPY}.1 somehost:${COPY}.2 \
    2>${OBJ}/scp-resume.err && \
    fail "$tid: legacy (-O) -Z was accepted, expected refusal"
grep -q "requires SFTP mode" ${OBJ}/scp-resume.err || \
    fail "$tid: legacy (-O) -Z did not fail with the expected message"
rm -f ${OBJ}/scp-resume.err

# Full verified-resume matrix over the supported SFTP path.
for mode in sftp; do
	scpopts="-D ${SFTPSERVER}"
	tag="$tid: sftp"

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
				# Dest is larger than source; verified resume skips
				# it (a larger file can't be a partial of the source).
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
					same)
						# SFTP put skips identical files (exit 0).
						$SCP -Z $scpopts ${COPY}.1 somehost:${COPY}.2 \
						    || fail "$tag put -Z failed size=${size}"
						cmp ${COPY}.1 ${COPY}.2 \
						    || fail "$tag corrupted after put -Z size=${size}"
						continue
						;;
					larger)
						# SFTP put skips when dest is larger (exit 0);
						# dest is intentionally left untouched.
						$SCP -Z $scpopts ${COPY}.1 somehost:${COPY}.2 \
						    || fail "$tag put -Z failed size=${size}"
						continue
						;;
					esac
				fi
				$SCP -Z $scpopts ${COPY}.1 somehost:${COPY}.2 \
				    || fail "$tag put -Z failed size=${size}"
				cmp ${COPY}.1 ${COPY}.2 \
				    || fail "$tag corrupted after put -Z size=${size}"
			else
				if test $mode = sftp; then
					case "${size}" in
					larger)
						# SFTP get skips when dest is larger (exit 0);
						# dest is intentionally left untouched (a larger
						# file can't be a partial of the source).
						$SCP -Z $scpopts somehost:${COPY}.1 ${COPY}.2 \
						    || fail "$tag get -Z failed size=${size}"
						continue
						;;
					esac
				fi
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
