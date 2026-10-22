#	Placed in the Public Domain.

tid="mptcp connect"

start_sshd

trace "direct connect"
${SSH} -oUseMPTCP=yes -F $OBJ/ssh_config somehost true
mptcp_ok=$?
if [ $mptcp_ok -ne 0 ]; then
	warn "ssh direct connect with MPTCP failed"
fi

# A proxy command makes its own connection, so MPTCP is not used. This
# only checks that the option does not break a proxied login.
trace "proxy connect"
${SSH} -oUseMPTCP=yes -F $OBJ/ssh_config -o "proxycommand $NC %h %p" somehost true
if [ $? -ne 0 ]; then
	warn "ssh proxycommand connect with MPTCP failed"
fi
stop_sshd

# A plain TCP server makes the client fall back to TCP, so MPTCP is only
# used with it on both ends. A server that cannot open an MPTCP socket
# does not start, so this runs only when the client could open one above.
if [ $mptcp_ok -eq 0 ]; then
	start_sshd -oUseMPTCP=yes
	trace "direct connect, MPTCP on both ends"
	${SSH} -oUseMPTCP=yes -F $OBJ/ssh_config somehost true
	if [ $? -ne 0 ]; then
		warn "ssh direct connect with MPTCP on both ends failed"
	fi
	stop_sshd
fi
