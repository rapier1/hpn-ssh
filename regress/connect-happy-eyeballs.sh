#	Placed in the Public Domain.

tid="happy eyeballs (rfc 8305) connect"

start_sshd

trace "direct connect"
${SSH} -oHappyEyes=yes -F $OBJ/ssh_config somehost true
if [ $? -ne 0 ]; then
	warn "ssh direct connect with Happy Eyeballs failed"
fi
grep "RFC 8305 / Happy Eyeballs connection successful" $TEST_SSH_LOGFILE \
    >/dev/null || warn "ssh connected without using Happy Eyeballs"

# A proxy command makes its own connection, so Happy Eyeballs is not used.
# This only checks that the option does not break a proxied login.
trace "proxy connect"
${SSH} -oHappyEyes=yes -F $OBJ/ssh_config -o "proxycommand $NC %h %p" somehost true
if [ $? -ne 0 ]; then
	warn "ssh proxycommand connect with Happy Eyeballs failed"
fi
