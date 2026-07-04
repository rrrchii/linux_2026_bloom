#!/bin/bash
# Profile Bloom filter insert stages (no lookup).

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

echo "=== building bloom_build_profile.ko ==="
make -s bloom_build_profile.ko

unload_module

echo "=== loading module ==="
insmod bloom_build_profile.ko

echo "=== running build profile ==="
echo 1 > /proc/bloom_build_profile/run

echo
echo "=== kernel log ==="
dmesg | tail -25 | grep -E 'bloom_build_profile|Bloom Build|stage|bottleneck|baseline|fixed mkn|----|S[0-9]|insert path|hash subtotal|bitmap subtotal' || true

echo
echo "=== unloading module ==="
unload_module

echo "done."
