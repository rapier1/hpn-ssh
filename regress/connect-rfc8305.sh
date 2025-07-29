#	$OpenBSD: connect.sh,v 1.8 2020/01/25 02:57:53 dtucker Exp $
#	Placed in the Public Domain.

tid="Happy Eyeballs (RFC 8305) connect"

start_sshd

trace "direct connect"
${SSH} -oHappyEys=yes -F $OBJ/ssh_config somehost true
if [ $? -ne 0 ]; then
	warn "ssh direct connect with RFC 8305 failed"
fi

trace "proxy connect"
${SSH} -oHappyEyes=yes -F $OBJ/ssh_config -o "proxycommand $NC %h %p" somehost true
if [ $? -ne 0 ]; then
	warn "ssh proxycommand connect with RFC 8305 failed"
fi
