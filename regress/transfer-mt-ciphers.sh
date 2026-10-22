#	Placed in the Public Domain.

tid="hpn multithreaded cipher transfer"

# Use a larger data file to exercise the MT cipher paths meaningfully.
increase_datafile_size 4096

cp $OBJ/sshd_proxy $OBJ/sshd_proxy_bak

for c in chacha20-poly1305-mt@hpnssh.org aes256-ctr aes128-ctr; do
	verbose "$tid: cipher $c"
	cp $OBJ/sshd_proxy_bak $OBJ/sshd_proxy
	echo "Ciphers=$c" >> $OBJ/sshd_proxy

	rm -f ${COPY}
	${SSH} -c $c -F $OBJ/ssh_proxy somehost "cat ${DATA}" > ${COPY}
	if [ $? -ne 0 ]; then
		fail "ssh transfer failed with cipher $c"
	fi
	cmp ${DATA} ${COPY} || fail "corrupted copy after transfer with cipher $c"
	# MT ciphers are off by design in FIPS mode.
	grep "FIPS mode is enabled" $TEST_SSH_LOGFILE >/dev/null && continue
	case $c in
	chacha*)	mtlog="chachapoly_new_mt: <main thread" ;;
	*)		mtlog="AES-CTR MT spawned a thread" ;;
	esac
	grep "$mtlog" $TEST_SSH_LOGFILE >/dev/null ||
	    fail "cipher $c did not switch to its multithreaded form"
done

rm -f ${COPY}
