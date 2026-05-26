#	Placed in the Public Domain.

tid="hpn metrics collection"

if [ "$(uname -s)" = "Darwin" ]; then
	skip "metrics not supported on this platform"
fi

METRICS_PATH=${OBJ}/test-metrics

start_sshd

trace "metrics file creation"
${SSH} -oMetrics=yes -oMetricsPath=${METRICS_PATH} \
    -F $OBJ/ssh_config somehost "cat ${DATA}" > ${COPY}
if [ $? -ne 0 ]; then
	fail "ssh with Metrics=yes failed"
fi
cmp ${DATA} ${COPY} || fail "corrupted copy with Metrics=yes"

if [ ! -f "${METRICS_PATH}.local" ]; then
	fail "local metrics file not created"
fi
if [ ! -s "${METRICS_PATH}.local" ]; then
	fail "local metrics file is empty"
fi

if [ ! -f "${METRICS_PATH}.remote" ]; then
	fail "remote metrics file not created"
fi
if [ ! -s "${METRICS_PATH}.remote" ]; then
	fail "remote metrics file is empty"
fi

rm -f ${COPY} ${METRICS_PATH}.local ${METRICS_PATH}.remote

stop_sshd
