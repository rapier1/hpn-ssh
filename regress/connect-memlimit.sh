#  Test if we can set the memory levels and connect. 

tid="hpn memory limit connect"

# Test client-side HPNMemoryLimit settings
start_sshd

# Each level and the number the channel code logs when it applies it.
for pair in default:0 high:1 max:2; do
	level=${pair%:*}
	index=${pair#*:}

	trace "client HPNMemoryLimit=$level direct connect"
	${SSH} -oHPNMemoryLimit=$level -F $OBJ/ssh_config somehost true
	if [ $? -ne 0 ]; then
		fail "ssh direct connect with HPNMemoryLimit=$level failed"
	fi
	grep "HPN Memory Limit: $index (cap" $TEST_SSH_LOGFILE >/dev/null ||
	    fail "client did not apply HPNMemoryLimit=$level"

done
stop_sshd

# Test server-side HPNMemoryLimit settings
for pair in default:0 high:1 max:2; do
	level=${pair%:*}
	index=${pair#*:}
	start_sshd -oHPNMemoryLimit=$level

	trace "server HPNMemoryLimit=$level direct connect"
	${SSH} -F $OBJ/ssh_config somehost true
	if [ $? -ne 0 ]; then
		fail "ssh direct connect to server HPNMemoryLimit=$level failed"
	fi
	grep "HPN Memory Limit: $index (cap" $TEST_SSHD_LOGFILE >/dev/null ||
	    fail "server did not apply HPNMemoryLimit=$level"

	stop_sshd
done
