#!/bin/bash
# ftrace function_graph on profile_stage_set_bit (S5 only).
#
# Note: set_bit() itself is static inline asm (lock bts/orb) — ftrace cannot
# enter it. This script traces the noinline wrapper and explains the inner path.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TRACE_DIR="/sys/kernel/tracing"
[[ -d "$TRACE_DIR" ]] || TRACE_DIR="/sys/kernel/debug/tracing"
[[ -d "$TRACE_DIR" ]] || { echo "error: ftrace not available" >&2; exit 1; }
[[ "$(id -u)" -eq 0 ]] || { echo "error: run as root" >&2; exit 1; }

TRACE_OUT="$SCRIPT_DIR/setbit_ftrace.txt"

trace_opt() {
	local opt="$1" val="$2" path="$TRACE_DIR/options/$opt"

	if [[ -e "$path" ]]; then
		echo "$val" > "$path"
	else
		echo "note: ftrace option $opt not available, skipping" >&2
	fi
}

unload_module() {
	if [[ -d /sys/module/bloom_build_profile ]]; then
		echo "unloading bloom_build_profile..."
		rmmod bloom_build_profile || {
			echo "error: rmmod bloom_build_profile failed" >&2
			exit 1
		}
	fi
}

echo "=== building ==="
make -s bloom_build_profile.ko
echo "build ok"

unload_module

echo "=== ftrace setup (function_graph) ==="
echo 0 > "$TRACE_DIR/tracing_on"
echo nop > "$TRACE_DIR/current_tracer"
echo > "$TRACE_DIR/set_graph_function"
echo > "$TRACE_DIR/set_ftrace_filter"
echo function_graph > "$TRACE_DIR/current_tracer"
trace_opt funcgraph-abstime 1
trace_opt funcgraph-duration 1
trace_opt funcgraph-overhead 1
trace_opt funcgraph-tail 0

echo "=== loading module ==="
insmod bloom_build_profile.ko

trace_filter_added=0
for fn in profile_stage_set_bit bloom_run_setbit_ftrace_target; do
	if echo "$fn" >> "$TRACE_DIR/set_graph_function" 2>/dev/null; then
		trace_filter_added=1
	elif echo "bloom_build_profile:$fn" >> "$TRACE_DIR/set_graph_function" 2>/dev/null; then
		trace_filter_added=1
	else
		echo "warning: cannot add ftrace filter for $fn" >&2
	fi
done
[[ "$trace_filter_added" -eq 1 ]] || echo "warning: no graph filters set" >&2

echo > "$TRACE_DIR/trace"
echo 1 > "$TRACE_DIR/tracing_on"

echo "=== running S5 set_bit only (10000 * k ops) ==="
echo 1 > /proc/bloom_build_profile/run_setbit

sleep 1
echo 0 > "$TRACE_DIR/tracing_on"

echo > "$TRACE_OUT"
grep -E 'profile_stage_set_bit|bloom_run_setbit_ftrace_target' "$TRACE_DIR/trace" \
	>> "$TRACE_OUT" || true

echo
echo "=== dmesg (S5 ktime) ==="
dmesg | tail -10 | grep -E 'set_bit ftrace|S5 set_bit|bloom_build_profile' || true

echo
echo "=== ftrace function_graph (saved to setbit_ftrace.txt) ==="
if grep -q 'profile_stage_set_bit' "$TRACE_OUT" 2>/dev/null; then
	grep -E '\| *\|' "$TRACE_OUT" | head -20
	echo "..."
	grep 'profile_stage_set_bit' "$TRACE_OUT" | grep -v '\->' | head -5
else
	echo "(no graph entries — check setbit_ftrace.txt and dmesg above)"
fi

echo
echo "=== what set_bit does internally (x86, not visible to ftrace) ==="
cat <<'EOF'
set_bit(nr, addr)  [linux/bitops.h]
  └─ arch_set_bit(nr, addr)  [inline asm in arch/x86/include/asm/bitops.h]
       ├─ variable nr:  LOCK; bts nr, (addr)     ← atomic bit test-and-set
       └─ constant nr:  LOCK; orb mask, byte(addr) ← atomic byte OR

Each call: atomic RMW on the cache line holding that bit (~26 ns/op in your S5).
__set_bit (S5b): same bts/orb but WITHOUT lock prefix → faster, not SMP-safe.

ftrace sees: bloom_run_setbit_ftrace_target() → profile_stage_set_bit()
ftrace does NOT see: 100,000 inline set_bit / arch_set_bit expansions inside the loop.
EOF

echo
echo "=== disassemble profile_stage_set_bit (look for lock/bts) ==="
if command -v objdump >/dev/null; then
	objdump -d bloom_build_profile.ko 2>/dev/null \
		| awk '/<profile_stage_set_bit>:/,/^$/' \
		| grep -E 'lock|bts|orb|<profile_stage_set_bit>' \
		| head -20 || echo "(no disassembly output)"
else
	echo "(objdump not found)"
fi

unload_module
echo "done."
