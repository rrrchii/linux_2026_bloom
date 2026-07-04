#!/bin/bash
# P1: perf record + report — find CPU hotspots during Bloom insert benchmark.
#
# Usage:
#   sudo ./run_perf_hotspot.sh                          # shared, 4 threads, repeat 50
#   sudo ./run_perf_hotspot_r1.sh                       # repeat 1 → *_r1.{data,txt} (compare)
#   sudo MODE=percpu THREADS=6 ./run_perf_hotspot.sh
#   sudo REPORT_ONLY=1 ./run_perf_hotspot.sh            # re-report existing .data

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="${MODE:-shared}"
THREADS="${THREADS:-4}"
REPEAT="${REPEAT:-50}"
FREQ="${FREQ:-999}"
REPORT_ONLY="${REPORT_ONLY:-0}"
DATA_FILE="${DATA_FILE:-perf_hotspot_${MODE}_${THREADS}t.data}"
REPORT_FILE="${REPORT_FILE:-perf_hotspot_${MODE}_${THREADS}t.txt}"

# shellcheck source=cpufreq_perf.sh
source "$SCRIPT_DIR/cpufreq_perf.sh"
trap restore_cpufreq EXIT

if [[ "$(id -u)" -ne 0 ]]; then
	echo "error: run as root (sudo $0)" >&2
	exit 1
fi

save_cpufreq_state
set_cpufreq_performance

make -s

report_hotspots() {
	local data="$1"
	local out="$2"

	{
		echo "=== perf hotspot report ==="
		echo "data: ${data}"
		echo "date: $(date -Iseconds)"
		echo "mode: ${MODE}  threads: ${THREADS}  repeat: ${REPEAT}"
		echo ""

		echo "=== Top symbols (all DSOs, >= 0.5%) ==="
		perf report -i "$data" --stdio --no-children --sort=dso,symbol \
			--percent-limit=0.5 2>/dev/null || true
		echo ""

		echo "=== Bloom / BPF / bitops related ==="
		perf report -i "$data" --stdio --no-children --sort=symbol \
			--percent-limit=0.1 2>/dev/null | \
			grep -E 'bloom|set_bit|test_bit|jhash|bpf_map|bpf_prog_[0-9a-f]|test_run|__bpf|bloom_filter|native_|_find_next' | \
			grep -v 'bpf_prog_load' || \
			echo "(no matching symbols — try CONFIG_DEBUG_INFO or perf probe)"
		echo ""

		echo "=== Call graph (top 30 lines) ==="
		perf report -i "$data" --stdio --call-graph --percent-limit=1 2>/dev/null | head -80 || true
	} | tee "$out"
}

if [[ "$REPORT_ONLY" -eq 1 ]]; then
	[[ -f "$DATA_FILE" ]] || { echo "missing ${DATA_FILE}" >&2; exit 1; }
	report_hotspots "$DATA_FILE" "$REPORT_FILE"
	echo "=== done; report: ${REPORT_FILE} ==="
	exit 0
fi

echo "=== perf record: mode=${MODE} threads=${THREADS} repeat=${REPEAT} freq=${FREQ}Hz ==="
echo "output: ${DATA_FILE}"

perf record -o "$DATA_FILE" -F "$FREQ" -g --call-graph fp,16384 \
	-e cycles -- \
	./bloom_bench_kern_mc --mode "$MODE" --threads "$THREADS" \
	--repeat "$REPEAT" --no-cpufreq

report_hotspots "$DATA_FILE" "$REPORT_FILE"

echo ""
echo "=== done ==="
echo "  data:   ${DATA_FILE}"
echo "  report: ${REPORT_FILE}"
echo "  TUI:    perf report -i ${DATA_FILE}"
