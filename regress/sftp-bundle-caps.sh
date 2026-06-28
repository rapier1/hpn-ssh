#	HPN-SSH sftp-bundle-caps.sh
#	Placed in the Public Domain.
#
#	Exercises the hpn-bundle@hpnssh.org accumulator: a recursive,
#	parallel put of many small files must bundle correctly and arrive
#	byte-identical.  (The old server-side -B/-T memory-cap CLI flags
#	were removed as unnecessary, so this no longer configures caps.)

tid="sftp bundle accumulator (recursive put)"

SRCDIR=${OBJ}/caps-src
DSTDIR=${OBJ}/caps-dst

xclean() {
	rm -rf ${SRCDIR} ${DSTDIR}
	mkdir -p ${SRCDIR} ${DSTDIR}
}

start_sshd

# Bundle dispatch needs many small files to actually exercise the
# accumulator.  Twenty 4 KiB files = 80 KiB total - single bundle.
xclean
for i in 01 02 03 04 05 06 07 08 09 10 \
         11 12 13 14 15 16 17 18 19 20; do
	dd if=/dev/urandom of=${SRCDIR}/f${i} bs=4k count=1 \
	    status=none 2>/dev/null || \
	    fatal "could not seed bundle dataset"
done

verbose "$tid: recursive parallel put of many small files"
${SFTP} -j 4 -q -S "$SSH" -F $OBJ/ssh_config \
    -P ${PORT} -o BatchMode=yes \
    -b - ${USER}@somehost > /dev/null 2>&1 <<EOF
put -r ${SRCDIR} ${DSTDIR}/up
EOF
r=$?
if [ $r -ne 0 ]; then
	fail "recursive bundle put failed with $r"
else
	diff -r ${SRCDIR} ${DSTDIR}/up || \
	    fail "transferred tree differs from source"
fi

xclean
