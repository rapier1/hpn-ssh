#!/usr/bin/env bash
# Phase 3 autotuning test: 40 GiB single file, j=1 starting point, 25ms RTT.
# Captures hpnsftp stderr (scale events) and samples NIC tx_bytes every 300ms
# so we can see the actual interface throughput at the same granularity as
# external monitors.

set -euo pipefail

SFTP=/tmp/hpn-parallel-sftp/bin/hpnsftp
SSH=/tmp/hpn-parallel-sftp/bin/hpnssh
HOST=juliet.psc.edu
PORT=2222
USER=rapier
IFACE=enp129s0f0np0
RTT_MS=25
LOCAL_FILE=/tmp/phase3-bigtest/40gb.bin
REMOTE_DIR=/tmp/phase3-bigtest
REMOTE_FILE="${REMOTE_DIR}/40gb.bin"
SAMPLE_MS=300                    # NIC sampling interval

# Mode: "auto" (with -j 1 = autotuning) or "direct" (no -j = plain sftp)
MODE="${1:-auto}"

LOG_DIR=/tmp/phase3-autoscale-${MODE}-$(date +%s)
mkdir -p "${LOG_DIR}"
STDERR_LOG="${LOG_DIR}/hpnsftp.stderr"
TX_LOG="${LOG_DIR}/nic-tx.csv"
EVENT_LOG="${LOG_DIR}/scale-events.txt"

cleanup() {
    [ -n "${SFTP_PID:-}" ] && kill "${SFTP_PID}" 2>/dev/null || true
    [ -n "${POLL_PID:-}" ] && kill "${POLL_PID}" 2>/dev/null || true
    [ -n "${TAIL_PID:-}" ] && kill "${TAIL_PID}" 2>/dev/null || true
    sudo tc qdisc del dev "${IFACE}" root 2>/dev/null || true
    echo "logs: ${LOG_DIR}"
}
trap cleanup EXIT

echo "=== Phase 3 autotuning test (mode=${MODE}, ${RTT_MS}ms RTT) ==="
echo "Logs: ${LOG_DIR}"

if [ ! -f "${LOCAL_FILE}" ]; then
    echo "Creating 40 GiB test file..."
    mkdir -p /tmp/phase3-bigtest
    dd if=/dev/zero of="${LOCAL_FILE}" bs=1M count=40960 status=progress
fi

echo "Setting up netem ${RTT_MS}ms one-way on ${IFACE}..."
sudo tc qdisc del dev "${IFACE}" root 2>/dev/null || true
sudo tc qdisc add dev "${IFACE}" root netem delay "${RTT_MS}ms"
ping -c 2 -4 -q "${HOST}" | tail -1

${SSH} -p "${PORT}" "${USER}@${HOST}" \
    "mkdir -p ${REMOTE_DIR} && rm -f ${REMOTE_FILE}"

BATCH=$(mktemp /tmp/batch.XXXXXX.sftp)
echo "put ${LOCAL_FILE} ${REMOTE_FILE}" > "${BATCH}"

START_NS=$(date +%s%N)
echo "${START_NS} START" > "${EVENT_LOG}"
echo "elapsed_s,tx_bytes,delta_bytes,rate_mibps" > "${TX_LOG}"

# ── NIC poll loop: sample tx_bytes every SAMPLE_MS, report rate ──────────────
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

# ── Tail scale events from stderr ────────────────────────────────────────────
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

# ── Run hpnsftp ──────────────────────────────────────────────────────────────
JFLAG=()
if [ "${MODE}" = "auto" ]; then
    JFLAG=(-j 1)
fi
echo "Starting hpnsftp ${JFLAG[*]:-(no -j)} ..."
${SFTP} "${JFLAG[@]}" -S "${SSH}" -P "${PORT}" \
    -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    -b "${BATCH}" "${USER}@${HOST}" \
    > "${LOG_DIR}/hpnsftp.stdout" 2> "${STDERR_LOG}"
SFTP_RC=$?

kill "${POLL_PID}" 2>/dev/null || true
kill "${TAIL_PID}" 2>/dev/null || true

# ── Summary ──────────────────────────────────────────────────────────────────
END_NS=$(date +%s%N)
TOTAL=$(awk "BEGIN { printf \"%.2f\", (${END_NS} - ${START_NS}) / 1e9 }")
FINAL_SIZE=$(${SSH} -p "${PORT}" "${USER}@${HOST}" "stat -c%s ${REMOTE_FILE}")
EXPECTED=$(stat -c%s "${LOCAL_FILE}")
AVG_MIBPS=$(awk "BEGIN { printf \"%.1f\", ${FINAL_SIZE} / ${TOTAL} / 1048576 }")

echo ""
echo "=== Summary (mode=${MODE}) ==="
echo "Transfer rc:      ${SFTP_RC}"
echo "Total wall time:  ${TOTAL}s"
echo "Bytes:            ${FINAL_SIZE} (expected ${EXPECTED})"
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

${SSH} -p "${PORT}" "${USER}@${HOST}" "rm -f ${REMOTE_FILE}"
rm -f "${BATCH}"
