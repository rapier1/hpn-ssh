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
rm -f ${COPY}

stop_sshd

# Test that the connection fails when the server has NoneEnabled=no.
# The client proposes none as the rekey cipher; the server rejects it
# because none is not in its accepted cipher list, causing the rekey
# and therefore the session to fail.
start_sshd -oNoneEnabled=no

trace "none cipher rejected when disabled on server"
${SSH} -oNoneEnabled=yes -oNoneSwitch=yes -oNoneMacEnabled=yes \
    -F $OBJ/ssh_config somehost true
if [ $? -eq 0 ]; then
	fail "ssh should have failed when server has NoneEnabled=no"
fi

stop_sshd
