#  Test if we can set the memory levels and connect. 

tid="hpn memory limit connect"

# Test client-side HPNMemoryLimit settings
start_sshd

for level in default high max; do

	trace "client HPNMemoryLimit=$level direct connect"
	${SSH} -oHPNMemoryLimit=$level -F $OBJ/ssh_config somehost true
	if [ $? -ne 0 ]; then
		fail "ssh direct connect with HPNMemoryLimit=$level failed"
	fi

done
stop_sshd

# Test server-side HPNMemoryLimit settings
for level in default high max; do
	start_sshd -oHPNMemoryLimit=$level

	trace "server HPNMemoryLimit=$level direct connect"
	${SSH} -F $OBJ/ssh_config somehost true
	if [ $? -ne 0 ]; then
		fail "ssh direct connect to server HPNMemoryLimit=$level failed"
	fi

	stop_sshd
done
