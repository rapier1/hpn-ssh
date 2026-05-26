#	Placed in the Public Domain.

tid="hpnsftp verified resume (reputv/regetv)"

CLIENT_LOG=${OBJ}/sftp-verified-resume.log

# We test up to 1MB, ensure source data is large enough.
increase_datafile_size 1200

# Test cases for verified reput/regetv:
#   0       - dest is empty (fresh transfer)
#   1k      - dest has valid partial (matching hash, should resume)
#   size-1  - dest is one byte short of source (matching prefix, should resume)
#   corrupt - dest has same size as partial but different content (hash mismatch,
#             should restart full transfer)
#   same    - dest is identical to source (should skip)
#   larger  - dest is larger than source (should skip)

for size in 0 1k size-1 larger corrupt same; do
    verbose "$tid: reputv size=${size}"
    trace "$tid: test reputv ${size}"
    rm -f ${COPY}.1 ${COPY}.2

    cp ${DATA} ${COPY}.1

    case "${size}" in
    0)
        touch ${COPY}.2
        ;;
    size-1)
        dd if=${COPY}.1 of=${COPY}.2 bs=1023 count=1 >/dev/null 2>&1
        ;;
    larger)
        # Dest is larger than source; verified resume skips it
        # (a larger file can't be a partial of the source).
        cp ${COPY}.1 ${COPY}.2
        dd if=/dev/urandom bs=512 count=1 >>${COPY}.2 2>/dev/null
        ;;
    corrupt)
        # Partial file with same length as 1k partial but wrong content
        dd if=/dev/urandom of=${COPY}.2 bs=1024 count=1 >/dev/null 2>&1
        ;;
    same)
        cp ${COPY}.1 ${COPY}.2
        ;;
    *)
        dd if=${COPY}.1 of=${COPY}.2 bs=${size} count=1 >/dev/null 2>&1
        ;;
    esac

    echo "reputv ${COPY}.1 ${COPY}.2" | \
        ${SFTP} -D ${SFTPSERVER} -vvv >${CLIENT_LOG} 2>&1 \
        || fail "reputv failed for size=${size}"
    case "${size}" in
    same)
        # reputv skips identical files; sftp interactive always exits 0
        # so check the log for the skip message instead.
        grep "File skipped:.*Identical" ${CLIENT_LOG} >/dev/null \
            || fail "reputv should have skipped identical file but did not"
        ;;
    larger)
        grep "File skipped:.*Target is larger" ${CLIENT_LOG} >/dev/null \
            || fail "reputv should have skipped larger dest but did not"
        ;;
    *)
        cmp ${COPY}.1 ${COPY}.2 || fail "corrupted result after reputv size=${size}"
        ;;
    esac
done

# Verify that a resumed upload actually picks up from the right offset
# by checking that "resuming" appears in the log for the valid partial case.
verbose "$tid: reputv resume offset check"
rm -rf ${COPY}.1 ${COPY}.2
cp ${DATA} ${COPY}.1
dd if=${COPY}.1 of=${COPY}.2 bs=1024 count=1 >/dev/null 2>&1
echo "reputv ${COPY}.1 ${COPY}.2" | \
    ${SFTP} -D ${SFTPSERVER} -vvv >${CLIENT_LOG} 2>&1 \
    || fail "reputv failed for resume offset check"
grep -i "resum" ${CLIENT_LOG} >/dev/null \
    || fail "no resume indication in log for valid partial"
cmp ${COPY}.1 ${COPY}.2 || fail "corrupted result after reputv resume offset check"

rm -f ${COPY}.1 ${COPY}.2

# ---- regetv (verified resume download) ----
# COPY.1 is the remote source; COPY.2 is the local destination.

for size in 0 1k size-1 larger corrupt same; do
    verbose "$tid: regetv size=${size}"
    trace "$tid: test regetv ${size}"
    rm -f ${COPY}.1 ${COPY}.2

    cp ${DATA} ${COPY}.1

    case "${size}" in
    0)
        touch ${COPY}.2
        ;;
    size-1)
        dd if=${COPY}.1 of=${COPY}.2 bs=1023 count=1 >/dev/null 2>&1
        ;;
    larger)
        cp ${COPY}.1 ${COPY}.2
        dd if=/dev/urandom bs=512 count=1 >>${COPY}.2 2>/dev/null
        ;;
    corrupt)
        dd if=/dev/urandom of=${COPY}.2 bs=1024 count=1 >/dev/null 2>&1
        ;;
    same)
        cp ${COPY}.1 ${COPY}.2
        ;;
    *)
        dd if=${COPY}.1 of=${COPY}.2 bs=${size} count=1 >/dev/null 2>&1
        ;;
    esac

    echo "regetv ${COPY}.1 ${COPY}.2" | \
        ${SFTP} -D ${SFTPSERVER} -vvv >${CLIENT_LOG} 2>&1 \
        || fail "regetv failed for size=${size}"
    case "${size}" in
    same)
        grep "File skipped:.*Identical" ${CLIENT_LOG} >/dev/null \
            || fail "regetv should have skipped identical file but did not"
        ;;
    larger)
        grep "File skipped:.*Target is larger" ${CLIENT_LOG} >/dev/null \
            || fail "regetv should have skipped larger dest but did not"
        ;;
    *)
        cmp ${COPY}.1 ${COPY}.2 || fail "corrupted result after regetv size=${size}"
        ;;
    esac
done

# Verify that a resumed download actually picks up from the right offset.
verbose "$tid: regetv resume offset check"
rm -f ${COPY}.1 ${COPY}.2
cp ${DATA} ${COPY}.1
dd if=${COPY}.1 of=${COPY}.2 bs=1024 count=1 >/dev/null 2>&1
echo "regetv ${COPY}.1 ${COPY}.2" | \
    ${SFTP} -D ${SFTPSERVER} -vvv >${CLIENT_LOG} 2>&1 \
    || fail "regetv failed for resume offset check"
grep -i "resum" ${CLIENT_LOG} >/dev/null \
    || fail "no resume indication in log for valid partial (regetv)"
cmp ${COPY}.1 ${COPY}.2 || fail "corrupted result after regetv resume offset check"

rm -f ${COPY}.1 ${COPY}.2

# ---- multi-file continuity test ----
# Verify that when transferring multiple files, a same-size-or-larger refusal
# on one file does not abort the session; the remaining files still transfer.
#
# Layout:
#   ok1  - partial destination (should resume successfully)
#   skip - destination same size as source (should be refused)
#   ok2  - partial destination (should resume successfully)

verbose "$tid: reputv multi-file continuity"
rm -f ${COPY}.ok1.src ${COPY}.ok1.dst \
      ${COPY}.skip.src ${COPY}.skip.dst \
      ${COPY}.ok2.src ${COPY}.ok2.dst
cp ${DATA} ${COPY}.ok1.src
cp ${DATA} ${COPY}.skip.src
cp ${DATA} ${COPY}.ok2.src
dd if=${COPY}.ok1.src  of=${COPY}.ok1.dst  bs=1024 count=1 >/dev/null 2>&1
cp ${COPY}.skip.src ${COPY}.skip.dst
dd if=${COPY}.ok2.src  of=${COPY}.ok2.dst  bs=1024 count=1 >/dev/null 2>&1
printf "reputv %s %s\nreputv %s %s\nreputv %s %s\n" \
    ${COPY}.ok1.src  ${COPY}.ok1.dst \
    ${COPY}.skip.src ${COPY}.skip.dst \
    ${COPY}.ok2.src  ${COPY}.ok2.dst | \
    ${SFTP} -D ${SFTPSERVER} -vvv >${CLIENT_LOG} 2>&1 \
    || fail "reputv multi-file session failed"
cmp ${COPY}.ok1.src ${COPY}.ok1.dst \
    || fail "reputv multi-file: ok1 not transferred correctly"
grep "File skipped:.*Identical" ${CLIENT_LOG} >/dev/null \
    || fail "reputv multi-file: skip file was not skipped"
cmp ${COPY}.ok2.src ${COPY}.ok2.dst \
    || fail "reputv multi-file: ok2 not transferred (session aborted early)"
rm -f ${COPY}.ok1.src ${COPY}.ok1.dst \
      ${COPY}.skip.src ${COPY}.skip.dst \
      ${COPY}.ok2.src ${COPY}.ok2.dst

verbose "$tid: regetv multi-file continuity"
rm -f ${COPY}.ok1.src ${COPY}.ok1.dst \
      ${COPY}.skip.src ${COPY}.skip.dst \
      ${COPY}.ok2.src ${COPY}.ok2.dst
cp ${DATA} ${COPY}.ok1.src
cp ${DATA} ${COPY}.skip.src
cp ${DATA} ${COPY}.ok2.src
dd if=${COPY}.ok1.src  of=${COPY}.ok1.dst  bs=1024 count=1 >/dev/null 2>&1
cp ${COPY}.skip.src ${COPY}.skip.dst
dd if=${COPY}.ok2.src  of=${COPY}.ok2.dst  bs=1024 count=1 >/dev/null 2>&1
printf "regetv %s %s\nregetv %s %s\nregetv %s %s\n" \
    ${COPY}.ok1.src  ${COPY}.ok1.dst \
    ${COPY}.skip.src ${COPY}.skip.dst \
    ${COPY}.ok2.src  ${COPY}.ok2.dst | \
    ${SFTP} -D ${SFTPSERVER} -vvv >${CLIENT_LOG} 2>&1 \
    || fail "regetv multi-file session failed"
cmp ${COPY}.ok1.src ${COPY}.ok1.dst \
    || fail "regetv multi-file: ok1 not transferred correctly"
grep "File skipped:.*Identical" ${CLIENT_LOG} >/dev/null \
    || fail "regetv multi-file: skip file was not skipped"
cmp ${COPY}.ok2.src ${COPY}.ok2.dst \
    || fail "regetv multi-file: ok2 not transferred (session aborted early)"
rm -f ${COPY}.ok1.src ${COPY}.ok1.dst \
      ${COPY}.skip.src ${COPY}.skip.dst \
      ${COPY}.ok2.src ${COPY}.ok2.dst
