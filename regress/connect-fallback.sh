#	Placed in the Public Domain.

tid="hpn port fallback"

start_sshd

# Pick a port that is not listening to serve as the dead primary.
DEAD_PORT=`expr $PORT + 50`

# When the user specifies an explicit (non-default) port that cannot be
# reached, HPN-SSH should exit with an error rather than silently falling
# back.  Fallback only applies when the connection attempt is on the
# HPN default port (2222).
trace "explicit port failure exits with error (no fallback)"
${SSH} -oFallback=yes -oFallbackPort=$PORT \
    -p $DEAD_PORT -F $OBJ/ssh_config somehost true
if [ $? -eq 0 ]; then
	fail "ssh should have exited with error on unreachable explicit port $DEAD_PORT"
fi

stop_sshd
