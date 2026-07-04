#!/bin/bash
# perf cache stats for Bloom insert (1/2/4/6/8 threads, once each).
# MODE=shared (default) or MODE=percpu

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="${MODE:-shared}"
PERF_REPEAT="${PERF_REPEAT:-1}"
THREAD_LIST="${THREAD_LIST:-1 2 4 6 8}"
OUT_FILE="${OUT_FILE:-perf_cache_results_${MODE}.txt}"

# shellcheck source=cpufreq_perf.sh
source "$SCRIPT_DIR/cpufreq_perf.sh"
trap restore_cpufreq EXIT

if [[ "$(id -u)" -ne 0 ]]; then
	echo "error: run as root (sudo $0)" >&2
	exit 1
fi

save_cpufreq_state

echo "=== building bloom_bench_kern_mc ==="
make -s

run_perf_case() {
	local nr="$1"

	set_cpufreq_performance
	echo ""
	echo "################################################################"
	echo "### perf stat -d  mode=${MODE}  threads=${nr}  (cpufreq -> performance, 1 bench run)"
	echo "################################################################"
	echo "governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
	perf stat -d -r "$PERF_REPEAT" -- \
		./bloom_bench_kern_mc --mode "$MODE" --threads "$nr" --no-cpufreq 2>&1
}

{
	echo "eBPF Bloom insert — cache / perf sweep (mode=${MODE})"
	echo "date: $(date -Iseconds)"
	echo "method: set performance before each case; one benchmark run per case"
	echo "threads: ${THREAD_LIST}"
	echo "perf -r: ${PERF_REPEAT}"
	echo ""

	for nr in $THREAD_LIST; do
		run_perf_case "$nr"
	done
} | tee "$OUT_FILE"

echo ""
echo "=== done; full log: ${OUT_FILE} ==="
