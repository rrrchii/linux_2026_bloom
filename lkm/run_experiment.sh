#!/bin/bash
# Bloom Filter for Network Flow Membership Test
# Uses ftrace function_graph to measure bloom_insert_test / lookup_test duration.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TRACE_DIR="/sys/kernel/tracing"
if [[ ! -d "$TRACE_DIR" ]]; then
	TRACE_DIR="/sys/kernel/debug/tracing"
fi

if [[ ! -d "$TRACE_DIR" ]]; then
	echo "error: ftrace not available (need CONFIG_FUNCTION_TRACER)" >&2
	exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
	echo "error: run as root (needed for insmod and ftrace)" >&2
	exit 1
fi

echo "=== building module ==="
make -s

unload_bloom_lkm() {
	if [[ ! -d /sys/module/bloom_lkm ]]; then
		return 0
	fi
	echo "unloading existing bloom_lkm module..."
	if ! rmmod bloom_lkm; then
		echo "error: failed to unload bloom_lkm (module may be in use)" >&2
		echo "       try manually: sudo rmmod bloom_lkm" >&2
		exit 1
	fi
}

echo "=== cleaning up previous run ==="
unload_bloom_lkm

echo "=== setting up ftrace (function_graph) ==="
echo 0 > "$TRACE_DIR/tracing_on"
echo nop > "$TRACE_DIR/current_tracer"
echo > "$TRACE_DIR/set_graph_function"
echo > "$TRACE_DIR/set_ftrace_filter"
echo function_graph > "$TRACE_DIR/current_tracer"
echo 1 > "$TRACE_DIR/options/funcgraph-abstime"
echo 1 > "$TRACE_DIR/options/funcgraph-duration"

echo "=== loading bloom_lkm ==="
if [[ -d /sys/module/bloom_lkm ]]; then
	echo "error: bloom_lkm is still loaded after cleanup" >&2
	exit 1
fi
insmod bloom_lkm.ko
if [[ ! -e /proc/bloom_experiment/run ]]; then
	echo "error: /proc/bloom_experiment/run not found after insmod" >&2
	rmmod bloom_lkm 2>/dev/null || true
	exit 1
fi

# Module symbols are available after insmod.
trace_filter_added=0
for fn in bloom_insert_test bloom_positive_lookup_test bloom_negative_lookup_test; do
	if echo "$fn" >> "$TRACE_DIR/set_graph_function" 2>/dev/null; then
		trace_filter_added=1
	else
		echo "warning: ftrace cannot trace $fn (rebuild module after code update)" >&2
	fi
done
if [[ "$trace_filter_added" -eq 0 ]]; then
	echo "warning: no ftrace graph filters set; use dmesg ktime results" >&2
fi

echo > "$TRACE_DIR/trace"
echo 1 > "$TRACE_DIR/tracing_on"

echo "=== running experiment ==="
echo 1 > /proc/bloom_experiment/run

sleep 1
echo 0 > "$TRACE_DIR/tracing_on"

echo
echo "=== kernel log (dmesg) ==="
dmesg | tail -20 | grep -E 'bloom_lkm|Bloom Filter|Insert|lookup|False positive' || true

echo
echo "=== ftrace timing (function_graph duration) ==="
TRACE_FILE="$SCRIPT_DIR/trace_result.txt"
grep -E 'bloom_(insert|positive_lookup|negative_lookup)_test' "$TRACE_DIR/trace" \
	| grep -E '\| *\|' > "$TRACE_FILE" || true

if [[ -s "$TRACE_FILE" ]]; then
	awk '
		/bloom_insert_test\(\)/ && !/->/ { fn="insert"; next }
		/bloom_positive_lookup_test\(\)/ && !/->/ { fn="positive_lookup"; next }
		/bloom_negative_lookup_test\(\)/ && !/->/ { fn="negative_lookup"; next }
		/\| *\| *[0-9]/ {
			if (fn != "") {
				match($0, /\| *\| *([0-9.]+) us/, a)
				if (a[1] != "") {
					total[fn] += a[1]
					count[fn]++
				}
			}
		}
		END {
			for (f in total)
				printf "%s_test ftrace total: %.3f us (%d calls)\n",
					f, total[f], count[f]
		}
	' "$TRACE_FILE"
else
	echo "(no matching ftrace entries; check $TRACE_FILE or dmesg ktime results)"
fi

echo
echo "=== unloading module ==="
unload_bloom_lkm

echo "done."
