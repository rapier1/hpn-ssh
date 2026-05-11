#!/usr/bin/env bash
# Phase 3 autotuning test, multi-file variant: 20 x 500 MiB separate files
# (10 GiB total) at 25ms RTT, -j 1 starting point.
# Each worker can transfer its own whole file - no shared-file contention.
# Compare 300ms NIC tx-rate distribution against the single-40GB-file run.

set -euo pipefail

SFTP=/tmp/hpn-parallel-sftp/bin/hpnsftp
SSH=/tmp/hpn-parallel-sftp/bin/hpnssh
HOST=juliet.psc.edu
PORT=2222
USER=rapier
IFACE=enp129s0f0np0
RTT_MS="${RTT_MS:-25}"
LOCAL_DIR="${LOCAL_DIR:-/home/rapier/claude-hpn-ssh/benchmark/testdata/large-files}"
REMOTE_DIR=/tmp/phase3-multifile
SAMPLE_MS=300

MODE="${1:-auto}"

LOG_DIR=/tmp/phase3-multifile-${MODE}-$(date +%s)
mkdir -p "${LOG_DIR}"
STDERR_LOG="${LOG_DIR}/hpnsftp.stderr"
TX_LOG="${LOG_DIR}/nic-tx.csv"
EVENT_LOG="${LOG_DIR}/scale-events.txt"

cleanup() {
    [ -n "${POLL_PID:-}" ] && kill "${POLL_PID}" 2>/dev/null || true
    [ -n "${TAIL_PID:-}" ] && kill "${TAIL_PID}" 2>/dev/null || true
    sudo tc qdisc del dev "${IFACE}" root 2>/dev/null || true
    echo "logs: ${LOG_DIR}"
}
trap cleanup EXIT

echo "=== Phase 3 multi-file test (mode=${MODE}, ${RTT_MS}ms RTT) ==="
echo "Dataset: ${LOCAL_DIR} ($(ls ${LOCAL_DIR} | wc -l) files, $(du -sh ${LOCAL_DIR} | cut -f1))"

sudo tc qdisc del dev "${IFACE}" root 2>/dev/null || true
sudo tc qdisc add dev "${IFACE}" root netem delay "${RTT_MS}ms"
ping -c 2 -4 -q "${HOST}" | tail -1

${SSH} -p "${PORT}" "${USER}@${HOST}" \
    "rm -rf ${REMOTE_DIR} && mkdir -p ${REMOTE_DIR}"

BATCH=$(mktemp /tmp/batch.XXXXXX.sftp)
echo "put -r ${LOCAL_DIR} ${REMOTE_DIR}" > "${BATCH}"

START_NS=$(date +%s%N)
echo "${START_NS} START" > "${EVENT_LOG}"
echo "elapsed_s,tx_bytes,delta_bytes,rate_mibps" > "${TX_LOG}"

(
    PREV=$(cat /sys/class/net/${IFACE}/statistics/tx_bytes)
    PREV_NS=$(date +%s%N)
    SAMPLE_S=$(awk "BEGIN { printf \"%.3f\", ${SAMPLE_MS}/1000 }")
    while true; do
        sleep "${SAMPLE_S}"
        NOW=$(cat /sys/class/net/${IFACE}/statistics/tx_bytes 2>/dev/null) || break
        NOW_NS=$(date +%s%N)
        DELTA=$((NOW - PREV))
        DT_NS=$((NOW_NS - PREV_NS))
        ELAPSED=$(awk "BEGIN { printf \"%.2f\", (${NOW_NS} - ${START_NS}) / 1e9 }")
        RATE=$(awk "BEGIN { printf \"%.1f\", ${DELTA} / 1048576.0 / (${DT_NS}/1e9) }")
        echo "${ELAPSED},${NOW},${DELTA},${RATE}" >> "${TX_LOG}"
        PREV=${NOW}
        PREV_NS=${NOW_NS}
    done
) &
POLL_PID=$!

(
    tail -F "${STDERR_LOG}" 2>/dev/null | while IFS= read -r line; do
        case "${line}" in
            *scaling\ up*|*scaling\ down*|*scale\ ceiling*)
                NOW_NS=$(date +%s%N)
                ELAPSED=$(awk "BEGIN { printf \"%.2f\", (${NOW_NS} - ${START_NS}) / 1e9 }")
                printf "%6.2fs  %s\n" "${ELAPSED}" "${line}" \
                    | tee -a "${EVENT_LOG}" >&2
                ;;
        esac
    done
) &
TAIL_PID=$!

JFLAG=()
if [ "${MODE}" = "auto" ]; then
    JFLAG=(-j "${STREAMS:-1}")
fi

echo "Starting hpnsftp ${JFLAG[*]:-(no -j)} ..."
${SFTP} "${JFLAG[@]}" -S "${SSH}" -P "${PORT}" \
    -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -o LogLevel=INFO \
    -b "${BATCH}" "${USER}@${HOST}" \
    > "${LOG_DIR}/hpnsftp.stdout" 2> "${STDERR_LOG}"
SFTP_RC=$?

kill "${POLL_PID}" 2>/dev/null || true
kill "${TAIL_PID}" 2>/dev/null || true

END_NS=$(date +%s%N)
TOTAL=$(awk "BEGIN { printf \"%.2f\", (${END_NS} - ${START_NS}) / 1e9 }")
FINAL_BYTES=$(${SSH} -p "${PORT}" "${USER}@${HOST}" \
    "du -sb ${REMOTE_DIR} | cut -f1")
EXPECTED=$(du -sb "${LOCAL_DIR}" | cut -f1)
AVG_MIBPS=$(awk "BEGIN { printf \"%.1f\", ${FINAL_BYTES} / ${TOTAL} / 1048576 }")

echo ""
echo "=== Summary (mode=${MODE}, multi-file) ==="
echo "Transfer rc:      ${SFTP_RC}"
echo "Total wall time:  ${TOTAL}s"
echo "Bytes:            ${FINAL_BYTES} (expected ${EXPECTED})"
echo "Average:          ${AVG_MIBPS} MiB/s"
echo ""
echo "NIC tx-rate distribution (${SAMPLE_MS}ms samples, MiB/s):"
awk -F, 'NR>1 && $4>0 {print $4}' "${TX_LOG}" \
    | sort -n \
    | awk '{a[NR]=$1} END {
        n=NR; if(n==0) exit;
        printf "  min=%.1f  p10=%.1f  p50=%.1f  p90=%.1f  max=%.1f  mean=", a[1], a[int(n*0.1)+1], a[int(n*0.5)+1], a[int(n*0.9)+1], a[n];
        s=0; for(i=1;i<=n;i++) s+=a[i]; printf "%.1f\n", s/n;
    }'
echo ""
echo "Scale events:"
cat "${EVENT_LOG}"

${SSH} -p "${PORT}" "${USER}@${HOST}" "rm -rf ${REMOTE_DIR}"
rm -f "${BATCH}"
