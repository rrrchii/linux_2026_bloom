#!/bin/bash
# P1 hotspot with repeat=1 — insert path clearer (minimal reload dilution).
# Writes perf_hotspot_{shared,percpu}_4t_r1.{data,txt}; does NOT touch *_4t.txt (repeat 50).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

THREADS="${THREADS:-4}"

run_one() {
	local mode="$1"
	local data="perf_hotspot_${mode}_${THREADS}t_r1.data"
	local report="perf_hotspot_${mode}_${THREADS}t_r1.txt"

	echo "=== ${mode} → ${report} ==="
	MODE="$mode" THREADS="$THREADS" REPEAT=1 \
		DATA_FILE="$data" REPORT_FILE="$report" \
		"$SCRIPT_DIR/run_perf_hotspot.sh"
}

run_one shared
run_one percpu

echo ""
echo "=== repeat-1 hotspot done ==="
echo "  perf_hotspot_shared_${THREADS}t_r1.txt"
echo "  perf_hotspot_percpu_${THREADS}t_r1.txt"
echo "(repeat-50 logs unchanged: perf_hotspot_*_${THREADS}t.txt)"
