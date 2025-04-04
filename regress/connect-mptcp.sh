#	$OpenBSD: connect.sh,v 1.8 2020/01/25 02:57:53 dtucker Exp $
#	Placed in the Public Domain.

tid="mptcp connect"

start_sshd

trace "direct connect"
${SSH} -oUseMPTCP=yes -F $OBJ/ssh_config somehost true
if [ $? -ne 0 ]; then
	warn "ssh direct connect with MPTCP failed"
fi

trace "proxy connect"
${SSH} -oUseMPTCP=yes -F $OBJ/ssh_config -o "proxycommand $NC %h %p" somehost true
if [ $? -ne 0 ]; then
	warn "ssh proxycommand connect with MPTCP failed"
fi
