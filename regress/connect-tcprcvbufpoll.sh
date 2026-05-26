#	Placed in the Public Domain.

tid="hpn tcp receive buffer poll"

increase_datafile_size 4096

start_sshd

trace "TcpRcvBufPoll=yes transfer"
${SSH} -oTcpRcvBufPoll=yes -F $OBJ/ssh_config somehost \
    "cat ${DATA}" > ${COPY}
if [ $? -ne 0 ]; then
	fail "ssh transfer with TcpRcvBufPoll=yes failed"
fi
cmp ${DATA} ${COPY} || fail "corrupted copy after TcpRcvBufPoll=yes transfer"
rm -f ${COPY}

trace "TcpRcvBufPoll=no transfer"
${SSH} -oTcpRcvBufPoll=no -F $OBJ/ssh_config somehost \
    "cat ${DATA}" > ${COPY}
if [ $? -ne 0 ]; then
	fail "ssh transfer with TcpRcvBufPoll=no failed"
fi
cmp ${DATA} ${COPY} || fail "corrupted copy after TcpRcvBufPoll=no transfer"
rm -f ${COPY}

stop_sshd
