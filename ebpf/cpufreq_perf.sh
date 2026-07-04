#!/bin/bash
# Pin CPU frequency for stable micro-benchmarks; restore on exit.

set_governor_all() {
	local gov="$1"
	local f

	for f in /sys/devices/system/cpu/cpu[0-9]*/cpufreq/scaling_governor; do
		[[ -f "$f" ]] || continue
		echo "$gov" > "$f"
	done
}

save_cpufreq_state() {
	local gov_path="/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
	local turbo_path="/sys/devices/system/cpu/intel_pstate/no_turbo"

	[[ -f "$gov_path" ]] || return 0
	SAVED_CPUFREQ_GOVERNOR=$(cat "$gov_path")
	if [[ -f "$turbo_path" ]]; then
		SAVED_CPUFREQ_NO_TURBO=$(cat "$turbo_path")
	fi
}

set_cpufreq_performance() {
	local gov_path="/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
	local turbo_path="/sys/devices/system/cpu/intel_pstate/no_turbo"

	[[ -f "$gov_path" ]] || return 0

	if [[ -z "${SAVED_CPUFREQ_GOVERNOR:-}" ]]; then
		SAVED_CPUFREQ_GOVERNOR=$(cat "$gov_path")
	fi

	set_governor_all performance

	if [[ -f "$turbo_path" && -z "${SAVED_CPUFREQ_NO_TURBO:-}" ]]; then
		SAVED_CPUFREQ_NO_TURBO=$(cat "$turbo_path")
	fi
	# Uncomment to disable Turbo for even tighter timing:
	# echo 1 > "$turbo_path"
}

restore_cpufreq() {
	local turbo_path="/sys/devices/system/cpu/intel_pstate/no_turbo"

	[[ -n "${SAVED_CPUFREQ_GOVERNOR:-}" ]] || return 0
	set_governor_all "$SAVED_CPUFREQ_GOVERNOR"

	if [[ -f "$turbo_path" && -n "${SAVED_CPUFREQ_NO_TURBO:-}" ]]; then
		echo "$SAVED_CPUFREQ_NO_TURBO" > "$turbo_path"
	fi
}
