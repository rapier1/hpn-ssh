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

# Fallback itself is tested on the default port, the only port it applies
# to, so only when nothing listens there. A host that runs its own hpnsshd
# on the default port skips this half. The default comes from ssh, since
# an hpnssh entry in /etc/services can change it.
DEFAULT_PORT=`${SSH} -G -F /dev/null somehost 2>/dev/null | \
    awk '/^port /{print $2}'`
if [ -z "$DEFAULT_PORT" ]; then
	fatal "could not read the default port from ssh -G"
elif ${NC} -z 127.0.0.1 $DEFAULT_PORT >/dev/null 2>&1; then
	stop_sshd
	skip "default port $DEFAULT_PORT is in use, fallback not tested"
fi

trace "dead default port $DEFAULT_PORT falls back to port $PORT"
${SSH} -oPort=$DEFAULT_PORT -oFallback=yes -oFallbackPort=$PORT \
    -F $OBJ/ssh_config somehost true 2>$OBJ/fallback.err
if [ $? -ne 0 ]; then
	fail "ssh did not fall back from default port $DEFAULT_PORT to $PORT"
fi
grep "Falling back to user defined port $PORT" $OBJ/fallback.err \
    >/dev/null || fail "ssh did not report falling back to port $PORT"
rm -f $OBJ/fallback.err

stop_sshd
