#	Placed in the Public Domain.

tid="hpn none cipher connect and transfer"

# Test that NoneSwitch transfers data correctly when both sides permit it.
start_sshd -oNoneEnabled=yes -oNoneMacEnabled=yes

trace "none cipher data transfer"
${SSH} -oNoneEnabled=yes -oNoneSwitch=yes -oNoneMacEnabled=yes \
    -F $OBJ/ssh_config somehost "cat ${DATA}" > ${COPY}
if [ $? -ne 0 ]; then
	fail "ssh transfer with None cipher failed"
fi
cmp ${DATA} ${COPY} || fail "corrupted copy after None cipher transfer"
grep "cipher: none MAC: none" $TEST_SSH_LOGFILE >/dev/null ||
    fail "ssh did not switch to the none cipher and MAC"
rm -f ${COPY}

stop_sshd

# Test that the connection fails when the server has NoneEnabled=no. The
# client sees that the server did not offer none and exits before any
# rekey, rather than rekey to a normal cipher and corrupt the stream.
start_sshd -oNoneEnabled=no

trace "none cipher rejected when disabled on server"
${SSH} -oNoneEnabled=yes -oNoneSwitch=yes -oNoneMacEnabled=yes \
    -F $OBJ/ssh_config somehost true
if [ $? -eq 0 ]; then
	fail "ssh should have failed when server has NoneEnabled=no"
fi
grep "Server does not permit the none cipher" $TEST_SSH_LOGFILE \
    >/dev/null || fail "ssh did not refuse the none cipher before the rekey"

stop_sshd
