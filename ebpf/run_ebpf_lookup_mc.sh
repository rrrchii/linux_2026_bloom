#!/bin/bash
# Multi-core kernel BPF Bloom positive lookup benchmark.
# Pass --mode shared|percpu (default: shared).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

USE_CPUFREQ=1
REPEAT="${REPEAT:-50}"
BENCH_ARGS=(--bench lookup --repeat "$REPEAT")

while [[ $# -gt 0 ]]; do
	case "$1" in
	--no-cpufreq)
		USE_CPUFREQ=0
		BENCH_ARGS+=("$1")
		shift
		;;
	*)
		BENCH_ARGS+=("$1")
		shift
		;;
	esac
done

if [[ "$(id -u)" -ne 0 ]]; then
	exec sudo "$0" "${BENCH_ARGS[@]}"
fi

if [[ "$USE_CPUFREQ" -eq 1 ]]; then
	# shellcheck source=cpufreq_perf.sh
	source "$SCRIPT_DIR/cpufreq_perf.sh"
	trap restore_cpufreq EXIT
	save_cpufreq_state
fi

echo "=== building multicore BPF Bloom lookup benchmark ==="
make -s

echo "=== running multi-core kernel BPF bloom lookup (positive) ==="
./bloom_bench_kern_mc "${BENCH_ARGS[@]}"

echo "done."
