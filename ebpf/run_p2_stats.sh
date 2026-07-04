#!/bin/bash
# P2: stat_inc overhead A/B (with vs --no-stats). Requires root for BPF.
set -euo pipefail
cd "$(dirname "$0")"
make -q bloom_bench_kern_mc bloom.bpf.o || make

OUT="${1:-p2_stat_inc_results.txt}"
REPEAT="${REPEAT:-50}"
THREADS="${THREADS:-4}"

run_case() {
	local label="$1"
	shift
	echo "=== $label ==="
	"$@" 2>&1 | tee -a "$OUT"
	echo "" | tee -a "$OUT"
}

: > "$OUT"
echo "P2 stat_inc A/B  date=$(date -Iseconds)  repeat=$REPEAT  threads=$THREADS" | tee -a "$OUT"
echo "" | tee -a "$OUT"

for mode in shared percpu; do
	for t in 1 "$THREADS"; do
		run_case "${mode} ${t}t WITH stats" \
			sudo ./bloom_bench_kern_mc --mode "$mode" --threads "$t" \
			--repeat "$REPEAT" --no-cpufreq
		run_case "${mode} ${t}t NO stats" \
			sudo ./bloom_bench_kern_mc --mode "$mode" --threads "$t" \
			--repeat "$REPEAT" --no-cpufreq --no-stats
	done
done

echo "Wrote $OUT"
