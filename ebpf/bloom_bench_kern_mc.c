// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
/*
 * Multi-core kernel BPF Bloom insert benchmark.
 *
 * --mode shared: bloom_insert_mc -> BPF_MAP_TYPE_BLOOM_FILTER
 * --mode percpu: bloom_insert_mc_percpu -> PERCPU_ARRAY bitmap
 * --bench lookup: positive lookup after untimed insert setup
 */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define FLOW_COUNT	10000
#define MAX_THREADS	8
#define CTRL_PKT_SIZE	64
#define BPF_OBJ_FILE	"bloom.bpf.o"
#define BLOOM_WORDS	2048
#define BENCH_REPEAT_DEFAULT	50

enum bench_mode {
	MODE_SHARED = 0,
	MODE_PERCPU,
};

enum bench_op {
	BENCH_INSERT = 0,
	BENCH_LOOKUP,
};

#define PROG_SHARED	"bloom_insert_mc"
#define PROG_PERCPU	"bloom_insert_mc_percpu"
#define PROG_SHARED_NOSTATS	"bloom_insert_mc_nostats"
#define PROG_PERCPU_NOSTATS	"bloom_insert_mc_percpu_nostats"
#define PROG_LOOKUP_SHARED	"bloom_lookup_mc"
#define PROG_LOOKUP_PERCPU	"bloom_lookup_mc_percpu"

static const char *insert_prog_name(enum bench_mode mode, bool no_stats)
{
	if (mode == MODE_PERCPU)
		return no_stats ? PROG_PERCPU_NOSTATS : PROG_PERCPU;
	return no_stats ? PROG_SHARED_NOSTATS : PROG_SHARED;
}

static const char *lookup_prog_name(enum bench_mode mode)
{
	return mode == MODE_PERCPU ? PROG_LOOKUP_PERCPU : PROG_LOOKUP_SHARED;
}

static const char *prog_name_for_mode(enum bench_mode mode, bool no_stats)
{
	return insert_prog_name(mode, no_stats);
}

static const char *mode_label(enum bench_mode mode)
{
	return mode == MODE_PERCPU ? "per-cpu" : "shared";
}

struct flow_key {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
} __attribute__((packed));

struct bench_ctrl {
	uint32_t start;
	uint32_t count;
};

struct percpu_bloom {
	uint64_t words[BLOOM_WORDS];
};

struct bench_result {
	double wall_ns;
	uint64_t push_ok;
	uint64_t push_err;
};

struct worker_arg {
	int prog_fd;
	int slot;
	int bind_cpu;
	int err;
};

static void bump_memlock(void)
{
	struct rlimit rlim = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim) && errno != EPERM)
		fprintf(stderr, "warn: setrlimit(RLIMIT_MEMLOCK): %s\n",
			strerror(errno));
}

static double elapsed_ns(const struct timespec *a, const struct timespec *b)
{
	return (double)(b->tv_sec - a->tv_sec) * 1e9 +
	       (double)(b->tv_nsec - a->tv_nsec);
}

static void flow_generate(struct flow_key *flow, int idx)
{
	flow->src_ip = htonl(0x0a000000 + (idx & 0xff));
	flow->dst_ip = htonl(0xc0a80000 + ((idx >> 8) & 0xff));
	flow->src_port = htons(1024 + (idx % 60000));
	flow->dst_port = htons(80 + (idx % 1000));
	flow->protocol = (idx & 1) ? IPPROTO_TCP : IPPROTO_UDP;
}

static void build_ctrl_packet(uint8_t *pkt, int slot)
{
	struct ethhdr *eth = (struct ethhdr *)pkt;

	memset(pkt, 0, CTRL_PKT_SIZE);
	eth->h_proto = htons(ETH_P_IP);
	pkt[sizeof(*eth)] = (uint8_t)slot;
}

static int fill_flow_array(int map_fd, struct flow_key *flows)
{
	uint32_t key;

	for (key = 0; key < FLOW_COUNT; key++) {
		if (bpf_map_update_elem(map_fd, &key, &flows[key], BPF_ANY))
			return -errno;
	}
	return 0;
}

static int fill_ctrl_array(int ctrl_fd, int nr_threads)
{
	int flows_per = FLOW_COUNT / nr_threads;
	int rem = FLOW_COUNT % nr_threads;
	int off = 0;
	int i;

	for (i = 0; i < nr_threads; i++) {
		struct bench_ctrl ctrl = {
			.start = (uint32_t)off,
			.count = (uint32_t)(flows_per + (i < rem ? 1 : 0)),
		};
		uint32_t key = (uint32_t)i;

		if (bpf_map_update_elem(ctrl_fd, &key, &ctrl, BPF_ANY))
			return -errno;
		off += (int)ctrl.count;
	}

	return off == FLOW_COUNT ? 0 : -EINVAL;
}

static int pick_cpus(int nr, int *cpus_out)
{
	cpu_set_t set;
	int n = 0;
	int cpu;

	if (sched_getaffinity(0, sizeof(set), &set))
		return -errno;

	for (cpu = 0; cpu < CPU_SETSIZE && n < nr; cpu++) {
		if (CPU_ISSET(cpu, &set))
			cpus_out[n++] = cpu;
	}

	return n == nr ? 0 : -EINVAL;
}

static void *run_slot_worker(void *argp)
{
	struct worker_arg *arg = argp;
	uint8_t pkt_in[CTRL_PKT_SIZE];
	uint8_t pkt_out[CTRL_PKT_SIZE];
	cpu_set_t set;
	LIBBPF_OPTS(bpf_test_run_opts, opts,
		    .data_in = pkt_in,
		    .data_size_in = sizeof(pkt_in),
		    .data_out = pkt_out,
		    .data_size_out = sizeof(pkt_out));

	CPU_ZERO(&set);
	CPU_SET(arg->bind_cpu, &set);
	pthread_setaffinity_np(pthread_self(), sizeof(set), &set);

	build_ctrl_packet(pkt_in, arg->slot);
	arg->err = bpf_prog_test_run_opts(arg->prog_fd, &opts);
	return NULL;
}

static int read_stat_sum(int stats_fd, int ncpus, uint32_t key, uint64_t *sum_out)
{
	uint64_t *vals;
	int i;

	vals = calloc((size_t)ncpus, sizeof(*vals));
	if (!vals)
		return -ENOMEM;
	if (bpf_map_lookup_elem(stats_fd, &key, vals)) {
		free(vals);
		return -errno;
	}

	*sum_out = 0;
	for (i = 0; i < ncpus; i++)
		*sum_out += vals[i];
	free(vals);
	return 0;
}

static int run_parallel_prog(int prog_fd, int stats_fd, int ncpus,
			     int nr_threads, int *cpus, bool count_stats,
			     struct bench_result *result)
{
	pthread_t threads[MAX_THREADS];
	struct worker_arg args[MAX_THREADS];
	struct timespec t0, t1;
	int i;

	memset(result, 0, sizeof(*result));

	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (i = 0; i < nr_threads; i++) {
		args[i].prog_fd = prog_fd;
		args[i].slot = i;
		args[i].bind_cpu = cpus[i];
		args[i].err = 0;
		if (pthread_create(&threads[i], NULL, run_slot_worker, &args[i]))
			return -errno;
	}

	for (i = 0; i < nr_threads; i++)
		pthread_join(threads[i], NULL);
	clock_gettime(CLOCK_MONOTONIC, &t1);

	for (i = 0; i < nr_threads; i++) {
		if (args[i].err)
			return args[i].err;
	}

	result->wall_ns = elapsed_ns(&t0, &t1);
	if (!count_stats) {
		result->push_ok = FLOW_COUNT;
		result->push_err = 0;
		return 0;
	}
	return read_stat_sum(stats_fd, ncpus, 0, &result->push_ok) ?:
	       read_stat_sum(stats_fd, ncpus, 1, &result->push_err);
}

static int sync_percpu_shards(int percpu_fd, int shard_fd, int nr_threads,
			      const int *cpus, int ncpus)
{
	struct percpu_bloom *all_values;
	uint32_t key0 = 0;
	int i;

	all_values = calloc((size_t)ncpus, sizeof(*all_values));
	if (!all_values)
		return -ENOMEM;
	if (bpf_map_lookup_elem(percpu_fd, &key0, all_values)) {
		free(all_values);
		return -errno;
	}

	for (i = 0; i < nr_threads; i++) {
		uint32_t shard_key = (uint32_t)i;

		if (bpf_map_update_elem(shard_fd, &shard_key,
					&all_values[cpus[i]], BPF_ANY)) {
			free(all_values);
			return -errno;
		}
	}
	free(all_values);
	return 0;
}

static int set_lookup_meta(int meta_fd, int nr_shards)
{
	uint32_t key = 0, val = (uint32_t)nr_shards;

	return bpf_map_update_elem(meta_fd, &key, &val, BPF_ANY) ? -errno : 0;
}

static int run_insert_setup(int flow_fd, int ctrl_fd, int insert_fd,
			    int percpu_fd, int shard_fd, int meta_fd,
			    enum bench_mode mode, int nr_threads, int *cpus,
			    int ncpus, struct flow_key *flows)
{
	struct bench_result throwaway;
	int insert_threads = mode == MODE_PERCPU ? nr_threads : 1;
	int err;

	err = fill_flow_array(flow_fd, flows);
	if (err)
		return err;
	err = fill_ctrl_array(ctrl_fd, insert_threads);
	if (err)
		return err;
	err = run_parallel_prog(insert_fd, -1, ncpus, insert_threads, cpus,
				false, &throwaway);
	if (err)
		return err;

	if (mode != MODE_PERCPU)
		return 0;

	err = sync_percpu_shards(percpu_fd, shard_fd, nr_threads, cpus, ncpus);
	if (err)
		return err;
	return set_lookup_meta(meta_fd, nr_threads);
}

static int run_one_case(const char *prog_name, int nr_threads, int *cpus,
			int ncpus, struct flow_key *flows, bool no_stats,
			struct bench_result *result)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_map *flow_map, *ctrl_map, *stats_map;
	int prog_fd, flow_fd, ctrl_fd, stats_fd;
	int err;

	obj = bpf_object__open_file(BPF_OBJ_FILE, NULL);
	if (!obj)
		return -ENOENT;

	err = bpf_object__load(obj);
	if (err)
		goto out;

	prog = bpf_object__find_program_by_name(obj, prog_name);
	flow_map = bpf_object__find_map_by_name(obj, "flow_array");
	ctrl_map = bpf_object__find_map_by_name(obj, "ctrl_array");
	stats_map = bpf_object__find_map_by_name(obj, "stats_map");
	if (!prog || !flow_map || !ctrl_map || (!no_stats && !stats_map)) {
		err = -ENOENT;
		goto out;
	}

	prog_fd = bpf_program__fd(prog);
	flow_fd = bpf_map__fd(flow_map);
	ctrl_fd = bpf_map__fd(ctrl_map);
	stats_fd = stats_map ? bpf_map__fd(stats_map) : -1;
	if (prog_fd < 0 || flow_fd < 0 || ctrl_fd < 0 ||
	    (!no_stats && stats_fd < 0)) {
		err = -EINVAL;
		goto out;
	}

	err = fill_flow_array(flow_fd, flows);
	if (err)
		goto out;
	err = fill_ctrl_array(ctrl_fd, nr_threads);
	if (err)
		goto out;
	err = run_parallel_prog(prog_fd, stats_fd, ncpus, nr_threads, cpus,
				!no_stats, result);

out:
	if (obj)
		bpf_object__close(obj);
	return err;
}

static int run_one_lookup_case(enum bench_mode mode, int nr_threads, int *cpus,
			       int ncpus, struct flow_key *flows,
			       struct bench_result *result)
{
	struct bpf_object *obj = NULL;
	struct bpf_program *insert_prog, *lookup_prog;
	struct bpf_map *flow_map, *ctrl_map, *stats_map;
	struct bpf_map *percpu_map, *shard_map, *meta_map;
	int insert_fd, lookup_fd, flow_fd, ctrl_fd, stats_fd;
	int percpu_fd = -1, shard_fd = -1, meta_fd = -1;
	int err;

	obj = bpf_object__open_file(BPF_OBJ_FILE, NULL);
	if (!obj)
		return -ENOENT;

	err = bpf_object__load(obj);
	if (err)
		goto out;

	insert_prog = bpf_object__find_program_by_name(obj,
			insert_prog_name(mode, true));
	lookup_prog = bpf_object__find_program_by_name(obj,
			lookup_prog_name(mode));
	flow_map = bpf_object__find_map_by_name(obj, "flow_array");
	ctrl_map = bpf_object__find_map_by_name(obj, "ctrl_array");
	stats_map = bpf_object__find_map_by_name(obj, "stats_map");
	if (!insert_prog || !lookup_prog || !flow_map || !ctrl_map || !stats_map) {
		err = -ENOENT;
		goto out;
	}

	if (mode == MODE_PERCPU) {
		percpu_map = bpf_object__find_map_by_name(obj, "percpu_bloom");
		shard_map = bpf_object__find_map_by_name(obj, "bloom_shard");
		meta_map = bpf_object__find_map_by_name(obj, "lookup_meta");
		if (!percpu_map || !shard_map || !meta_map) {
			err = -ENOENT;
			goto out;
		}
		percpu_fd = bpf_map__fd(percpu_map);
		shard_fd = bpf_map__fd(shard_map);
		meta_fd = bpf_map__fd(meta_map);
		if (percpu_fd < 0 || shard_fd < 0 || meta_fd < 0) {
			err = -EINVAL;
			goto out;
		}
	}

	insert_fd = bpf_program__fd(insert_prog);
	lookup_fd = bpf_program__fd(lookup_prog);
	flow_fd = bpf_map__fd(flow_map);
	ctrl_fd = bpf_map__fd(ctrl_map);
	stats_fd = bpf_map__fd(stats_map);
	if (insert_fd < 0 || lookup_fd < 0 || flow_fd < 0 || ctrl_fd < 0 ||
	    stats_fd < 0) {
		err = -EINVAL;
		goto out;
	}

	err = run_insert_setup(flow_fd, ctrl_fd, insert_fd, percpu_fd, shard_fd,
			       meta_fd, mode, nr_threads, cpus, ncpus, flows);
	if (err)
		goto out;

	err = fill_ctrl_array(ctrl_fd, nr_threads);
	if (err)
		goto out;
	err = run_parallel_prog(lookup_fd, stats_fd, ncpus, nr_threads, cpus,
				true, result);

out:
	if (obj)
		bpf_object__close(obj);
	return err;
}

static int cmp_double(const void *a, const void *b)
{
	double da = *(const double *)a;
	double db = *(const double *)b;

	return (da > db) - (da < db);
}

static double median_ns(double *samples, int n)
{
	qsort(samples, (size_t)n, sizeof(*samples), cmp_double);
	if (n % 2)
		return samples[n / 2];
	return (samples[n / 2 - 1] + samples[n / 2]) / 2.0;
}

static int run_case_repeats(const char *prog_name, int nr_threads, int *cpus,
			    int ncpus, struct flow_key *flows, int repeat,
			    bool warmup, bool no_stats, struct bench_result *result,
			    double *min_ns, double *max_ns)
{
	double *samples;
	int i, err;

	samples = calloc((size_t)repeat, sizeof(*samples));
	if (!samples)
		return -ENOMEM;

	if (warmup) {
		struct bench_result throwaway;

		err = run_one_case(prog_name, nr_threads, cpus, ncpus, flows,
				   no_stats, &throwaway);
		if (err) {
			free(samples);
			return err;
		}
	}

	for (i = 0; i < repeat; i++) {
		err = run_one_case(prog_name, nr_threads, cpus, ncpus, flows,
				   no_stats, result);
		if (err) {
			free(samples);
			return err;
		}
		samples[i] = result->wall_ns;
	}

	result->wall_ns = median_ns(samples, repeat);
	*min_ns = samples[0];
	*max_ns = samples[repeat - 1];
	free(samples);
	return 0;
}

static int run_lookup_case_repeats(enum bench_mode mode, int nr_threads,
				   int *cpus, int ncpus, struct flow_key *flows,
				   int repeat, bool warmup,
				   struct bench_result *result, double *min_ns,
				   double *max_ns)
{
	double *samples;
	int i, err;

	samples = calloc((size_t)repeat, sizeof(*samples));
	if (!samples)
		return -ENOMEM;

	if (warmup) {
		struct bench_result throwaway;

		err = run_one_lookup_case(mode, nr_threads, cpus, ncpus, flows,
					  &throwaway);
		if (err) {
			free(samples);
			return err;
		}
	}

	for (i = 0; i < repeat; i++) {
		err = run_one_lookup_case(mode, nr_threads, cpus, ncpus, flows,
					  result);
		if (err) {
			free(samples);
			return err;
		}
		samples[i] = result->wall_ns;
	}

	result->wall_ns = median_ns(samples, repeat);
	*min_ns = samples[0];
	*max_ns = samples[repeat - 1];
	free(samples);
	return 0;
}

static void pin_cpufreq_performance(int nr_threads)
{
	char path[128];
	FILE *fp;
	int cpu;

	if (geteuid() != 0)
		return;

	for (cpu = 0; cpu < 256; cpu++) {
		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_governor",
			 cpu);
		fp = fopen(path, "w");
		if (!fp)
			continue;
		fputs("performance", fp);
		fclose(fp);
	}

	fprintf(stderr, "cpufreq: performance (before threads=%d)\n", nr_threads);
}

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [--bench insert|lookup] [--mode shared|percpu] [--threads N] [--repeat N] [--warmup] [--no-cpufreq] [--no-stats]\n"
		"  default: insert benchmark, shared map, 1/2/4/6/8 threads, repeat %d\n"
		"  --bench lookup: positive lookup after untimed insert setup\n"
		"  --mode percpu: PERCPU_ARRAY bitmap (current CPU copy only)\n"
		"  --no-stats: skip stat_inc in BPF (no push_ok/push_err from map)\n"
		"  --threads N: run only N threads (1..%d)\n"
		"  --repeat N: repeat each case N times, report median [min-max]\n"
		"  --warmup: one untimed run before each case (only with --repeat > 1)\n"
		"  --no-cpufreq: do not set performance governor\n",
		prog, MAX_THREADS, BENCH_REPEAT_DEFAULT);
}

static enum bench_op parse_bench(const char *s)
{
	if (!strcmp(s, "insert"))
		return BENCH_INSERT;
	if (!strcmp(s, "lookup"))
		return BENCH_LOOKUP;
	fprintf(stderr, "invalid --bench %s (use insert or lookup)\n", s);
	exit(1);
}

static enum bench_mode parse_mode(const char *s)
{
	if (!strcmp(s, "shared"))
		return MODE_SHARED;
	if (!strcmp(s, "percpu") || !strcmp(s, "per-cpu"))
		return MODE_PERCPU;
	fprintf(stderr, "invalid --mode %s (use shared or percpu)\n", s);
	exit(1);
}

int main(int argc, char **argv)
{
	struct flow_key *flows;
	struct bench_result result;
	int cpus[MAX_THREADS];
	int nr_list[] = { 1, 2, 4, 6, 8 };
	int nr_list_len = (int)(sizeof(nr_list) / sizeof(nr_list[0]));
	int only_threads = 0;
	int repeat = BENCH_REPEAT_DEFAULT;
	bool warmup = false;
	bool use_cpufreq = true;
	bool no_stats = false;
	enum bench_mode mode = MODE_SHARED;
	enum bench_op bench = BENCH_INSERT;
	const char *prog_name;
	int ncpus, i;
	double baseline_ns = 0;
	int err;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--threads") && i + 1 < argc) {
			only_threads = atoi(argv[++i]);
			if (only_threads < 1 || only_threads > MAX_THREADS) {
				fprintf(stderr, "invalid --threads %d\n", only_threads);
				print_usage(argv[0]);
				return 1;
			}
			nr_list[0] = only_threads;
			nr_list_len = 1;
		} else if (!strcmp(argv[i], "--repeat") && i + 1 < argc) {
			repeat = atoi(argv[++i]);
			if (repeat < 1) {
				fprintf(stderr, "invalid --repeat %d\n", repeat);
				print_usage(argv[0]);
				return 1;
			}
		} else if (!strcmp(argv[i], "--mode") && i + 1 < argc) {
			mode = parse_mode(argv[++i]);
		} else if (!strcmp(argv[i], "--bench") && i + 1 < argc) {
			bench = parse_bench(argv[++i]);
		} else if (!strcmp(argv[i], "--warmup")) {
			warmup = true;
		} else if (!strcmp(argv[i], "--no-cpufreq")) {
			use_cpufreq = false;
		} else if (!strcmp(argv[i], "--no-stats")) {
			no_stats = true;
		} else if (!strcmp(argv[i], "--no-warmup")) {
			warmup = false;
		} else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
			print_usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "unknown argument: %s\n", argv[i]);
			print_usage(argv[0]);
			return 1;
		}
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	bump_memlock();

	ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0) {
		fprintf(stderr, "libbpf_num_possible_cpus failed\n");
		return 1;
	}
	if (pick_cpus(MAX_THREADS, cpus) && pick_cpus(4, cpus)) {
		fprintf(stderr, "not enough online cpus\n");
		return 1;
	}

	flows = calloc(FLOW_COUNT, sizeof(*flows));
	if (!flows) {
		perror("calloc");
		return 1;
	}
	for (i = 0; i < FLOW_COUNT; i++)
		flow_generate(&flows[i], i);

	prog_name = prog_name_for_mode(mode, no_stats);

	printf("=== eBPF Multi-core Bloom %s ===\n",
	       bench == BENCH_LOOKUP ? "Lookup (positive)" : "Insert");
	printf("object: %s  prog: %s  mode: %s",
	       BPF_OBJ_FILE,
	       bench == BENCH_LOOKUP ? lookup_prog_name(mode) : prog_name,
	       mode_label(mode));
	if (bench == BENCH_INSERT)
		printf("  stats: %s\n", no_stats ? "off" : "on");
	else
		printf("\n");
	if (bench == BENCH_LOOKUP) {
		if (mode == MODE_SHARED)
			printf("backend: bpf_map_peek_elem on BPF_MAP_TYPE_BLOOM_FILTER\n");
		else
			printf("backend: OR bloom_shard[0..N-1], k=%d (after per-CPU insert setup)\n",
			       10);
	} else if (mode == MODE_SHARED) {
		printf("backend: BPF_MAP_TYPE_BLOOM_FILTER (bpf_map_push_elem)\n");
	} else {
		printf("backend: PERCPU_ARRAY bitmap, m=%d k=%d (current CPU only)\n",
		       131072, 10);
	}
	printf("n=%d flows, pthread + bpf_prog_test_run\n", FLOW_COUNT);
	if (bench == BENCH_LOOKUP)
		printf("setup: untimed insert (%s) then timed lookup\n",
		       mode == MODE_PERCPU ? "N-thread per-CPU" : "1-thread shared");
	printf("cpufreq: %s before each case; %s per case\n",
	       use_cpufreq ? "performance" : "unchanged",
	       repeat > 1 ? (warmup ? "repeat+warmup" : "repeat") : "single run");
	printf("----------------------------------------------------------------\n");
	if (repeat > 1) {
		if (bench == BENCH_LOOKUP)
			printf("%7s  %22s  %11s  %8s  %10s  %10s\n",
			       "threads", "wall_ns [min-max]", "ops/sec", "speedup",
			       "lookup_hits", "lookup_miss");
		else
			printf("%7s  %22s  %11s  %8s  %10s  %10s\n",
			       "threads", "wall_ns [min-max]", "ops/sec", "speedup",
			       "push_ok", "push_err");
	} else {
		if (bench == BENCH_LOOKUP)
			printf("%7s  %11s  %11s  %8s  %10s  %10s\n",
			       "threads", "wall_ns", "ops/sec", "speedup",
			       "lookup_hits", "lookup_miss");
		else
			printf("%7s  %11s  %11s  %8s  %10s  %10s\n",
			       "threads", "wall_ns", "ops/sec", "speedup", "push_ok",
			       "push_err");
	}
	printf("----------------------------------------------------------------\n");

	for (i = 0; i < nr_list_len; i++) {
		double ops, speedup, min_ns = 0, max_ns = 0;
		int nr = nr_list[i];

		if (nr > ncpus || nr > MAX_THREADS)
			continue;

		if (use_cpufreq)
			pin_cpufreq_performance(nr);

		if (repeat > 1) {
			if (bench == BENCH_LOOKUP)
				err = run_lookup_case_repeats(mode, nr, cpus, ncpus,
							      flows, repeat, warmup,
							      &result, &min_ns,
							      &max_ns);
			else
				err = run_case_repeats(prog_name, nr, cpus, ncpus,
						       flows, repeat, warmup,
						       no_stats, &result, &min_ns,
						       &max_ns);
		} else if (bench == BENCH_LOOKUP) {
			err = run_one_lookup_case(mode, nr, cpus, ncpus, flows,
						  &result);
		} else {
			err = run_one_case(prog_name, nr, cpus, ncpus, flows,
					   no_stats, &result);
		}
		if (err) {
			fprintf(stderr, "nr=%d failed: %d\n", nr, err);
			free(flows);
			return 1;
		}

		if (nr == 1 || only_threads)
			baseline_ns = result.wall_ns;
		ops = result.wall_ns > 0 ? (double)FLOW_COUNT * 1e9 / result.wall_ns : 0;
		speedup = baseline_ns > 0 ? baseline_ns / result.wall_ns : 1.0;

		if (repeat > 1) {
			char wall_buf[64];

			snprintf(wall_buf, sizeof(wall_buf), "%.0f [%.0f-%.0f]",
				 result.wall_ns, min_ns, max_ns);
			printf("%7d  %22s  %11.0f  %7.2fx  %10llu  %10llu\n",
			       nr, wall_buf, ops, speedup,
			       (unsigned long long)result.push_ok,
			       (unsigned long long)result.push_err);
		} else {
			printf("%7d  %11.0f  %11.0f  %7.2fx  %10llu  %10llu\n",
			       nr, result.wall_ns, ops, speedup,
			       (unsigned long long)result.push_ok,
			       (unsigned long long)result.push_err);
		}
	}

	printf("----------------------------------------------------------------\n");

	free(flows);
	return 0;
}
