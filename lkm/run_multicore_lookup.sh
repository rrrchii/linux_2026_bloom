#!/bin/bash
# Multi-core Bloom positive lookup: shared bitmap vs per-CPU bitmap.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ "$(id -u)" -ne 0 ]]; then
	echo "error: run as root" >&2
	exit 1
fi

unload_module() {
	if [[ -d /sys/module/bloom_build_profile ]]; then
		rmmod bloom_build_profile
	fi
}

echo "=== building ==="
make -s bloom_build_profile.ko
echo "build ok"

unload_module

echo "=== loading module ==="
insmod bloom_build_profile.ko

echo "=== running multi-core lookup benchmark (1/2/4/8 threads) ==="
echo 1 > /proc/bloom_build_profile/run_multicore_lookup

echo
echo "=== kernel log ==="
dmesg | tail -35 | grep -E 'Multi-core Bloom Lookup|mkn|build:|----|threads|shared|per-cpu|interpret|online cpus|MISMATCH' || true

echo
echo "=== unloading ==="
unload_module
echo "done."
