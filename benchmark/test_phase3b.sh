#!/usr/bin/env bash
# Phase 3b byte-range parallelism functional test.
# Uploads a 500 MiB file with j=4 (should split into 4 ranges), verifies
# remote checksum matches local checksum.  Also tests j=1 as a sanity
# baseline (whole-file path, no range splitting).

set -euo pipefail

SFTP=/tmp/hpn-parallel-sftp/bin/hpnsftp
SSH=/tmp/hpn-parallel-sftp/bin/hpnssh
HOST=juliet.psc.edu
PORT=2222
USER=rapier
LOCAL_FILE=/home/rapier/claude-hpn-ssh/benchmark/testdata/large-files/file_00
REMOTE_DIR=/tmp/phase3b-test
REMOTE_FILE="${REMOTE_DIR}/file_00"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[0;33m'
RST='\033[0m'

pass() { echo -e "${GRN}PASS${RST}: $*"; }
fail() { echo -e "${RED}FAIL${RST}: $*"; exit 1; }
info() { echo -e "${YLW}INFO${RST}: $*"; }

# ── Setup ─────────────────────────────────────────────────────────────────────
info "Local file: $(ls -lh "${LOCAL_FILE}" | awk '{print $5, $NF}')"
info "Computing local sha256..."
LOCAL_SUM=$(sha256sum "${LOCAL_FILE}" | awk '{print $1}')
info "Local sha256: ${LOCAL_SUM}"

info "Creating remote directory..."
${SSH} -p "${PORT}" "${USER}@${HOST}" "mkdir -p ${REMOTE_DIR}"

run_upload_test() {
    local streams=$1
    local label="j=${streams}"

    info "--- ${label} upload ---"
    ${SSH} -p "${PORT}" "${USER}@${HOST}" "rm -f ${REMOTE_FILE}"

    if [ "${streams}" -eq 1 ]; then
        # j=1: single-stream (no parallel flag at all, baseline)
        info "Running single-stream upload..."
        ${SFTP} -P "${PORT}" -b - "${USER}@${HOST}" <<EOF
put ${LOCAL_FILE} ${REMOTE_FILE}
EOF
    else
        info "Running ${streams}-stream upload (range split expected)..."
        ${SFTP} -P "${PORT}" -j "${streams}" -b - "${USER}@${HOST}" <<EOF
put ${LOCAL_FILE} ${REMOTE_FILE}
EOF
    fi

    info "Verifying remote checksum for ${label}..."
    REMOTE_SUM=$(${SSH} -p "${PORT}" "${USER}@${HOST}" \
        "sha256sum ${REMOTE_FILE} | awk '{print \$1}'")
    info "Remote sha256: ${REMOTE_SUM}"

    if [ "${LOCAL_SUM}" = "${REMOTE_SUM}" ]; then
        pass "${label}: checksums match"
    else
        fail "${label}: checksum MISMATCH — local=${LOCAL_SUM} remote=${REMOTE_SUM}"
    fi

    REMOTE_SIZE=$(${SSH} -p "${PORT}" "${USER}@${HOST}" \
        "stat -c%s ${REMOTE_FILE}")
    LOCAL_SIZE=$(stat -c%s "${LOCAL_FILE}")
    if [ "${LOCAL_SIZE}" = "${REMOTE_SIZE}" ]; then
        pass "${label}: file size matches (${LOCAL_SIZE} bytes)"
    else
        fail "${label}: size mismatch — local=${LOCAL_SIZE} remote=${REMOTE_SIZE}"
    fi
}

# ── Tests ─────────────────────────────────────────────────────────────────────
run_upload_test 1    # baseline: whole-file, no range split
run_upload_test 2    # 2 ranges
run_upload_test 4    # 4 ranges

# ── Cleanup ───────────────────────────────────────────────────────────────────
info "Cleaning up remote..."
${SSH} -p "${PORT}" "${USER}@${HOST}" "rm -rf ${REMOTE_DIR}"

echo ""
echo -e "${GRN}All Phase 3b tests passed.${RST}"
