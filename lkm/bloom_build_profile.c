// SPDX-License-Identifier: GPL-2.0
/*
 * Bloom filter build (insert) stage profiler.
 * Fixed mkn experiment: measure where insert time is spent.
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/in.h>
#include <linux/uaccess.h>
#include <linux/jhash.h>
#include <linux/bitmap.h>
#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/cpumask.h>
#include <linux/wait.h>
#include <linux/atomic.h>

#define MC_MAX_THREADS	8

#define BLOOM_BITS	131072
#define BLOOM_BITS_MASK	(BLOOM_BITS - 1)
#define BLOOM_WORDS	(BLOOM_BITS / BITS_PER_LONG)
#define BLOOM_K		10
#define FLOW_COUNT	10000

#define JHASH_INITVAL_H1	0xbc9f1d34
#define JHASH_INITVAL_H2	0x7f4a7c15

struct flow_key {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	u8 protocol;
} __packed;

struct build_stage_times {
	s64 flow_gen_ns;
	s64 bitmap_zero_ns;
	s64 jhash_h1_ns;
	s64 jhash_h2_ns;
	s64 pos_calc_ns;
	s64 set_bit_ns;
	s64 full_insert_ns;
};

static unsigned long bloom[BLOOM_WORDS];
static struct proc_dir_entry *profile_proc_dir;

static void flow_generate(struct flow_key *flow, int idx)
{
	flow->src_ip = cpu_to_be32(0x0a000000 + (idx & 0xff));
	flow->dst_ip = cpu_to_be32(0xc0a80000 + ((idx >> 8) & 0xff));
	flow->src_port = cpu_to_be16(1024 + (idx % 60000));
	flow->dst_port = cpu_to_be16(80 + (idx % 1000));
	flow->protocol = (idx & 1) ? IPPROTO_TCP : IPPROTO_UDP;
}

static u32 hash_h1(const struct flow_key *flow)
{
	return jhash(flow, sizeof(*flow), JHASH_INITVAL_H1) & BLOOM_BITS_MASK;
}

static u32 hash_h2_raw(const struct flow_key *flow)
{
	u32 h2 = jhash(flow, sizeof(*flow), JHASH_INITVAL_H2) & BLOOM_BITS_MASK;

	h2 |= 1;
	if (h2 >= BLOOM_BITS)
		h2 = 1;
	return h2;
}

static noinline void bloom_insert_flow(const struct flow_key *flow)
{
	u32 h1, h2;
	int i;

	h1 = hash_h1(flow);
	h2 = hash_h2_raw(flow);
	for (i = 0; i < BLOOM_K; i++)
		set_bit((h1 + i * h2) & BLOOM_BITS_MASK, bloom);
}

static s64 time_ns(ktime_t start, ktime_t end)
{
	return ktime_to_ns(ktime_sub(end, start));
}

static void profile_stage_flow_gen(struct flow_key *flows, s64 *out_ns)
{
	ktime_t start, end;
	int i;

	start = ktime_get();
	for (i = 0; i < FLOW_COUNT; i++)
		flow_generate(&flows[i], i);
	end = ktime_get();
	*out_ns = time_ns(start, end);
}

static void profile_stage_bitmap_zero(s64 *out_ns)
{
	ktime_t start, end;

	start = ktime_get();
	bitmap_zero(bloom, BLOOM_BITS);
	end = ktime_get();
	*out_ns = time_ns(start, end);
}

static void profile_stage_jhash_h1(const struct flow_key *flows, u32 *h1_out,
				   s64 *out_ns)
{
	ktime_t start, end;
	int i;

	start = ktime_get();
	for (i = 0; i < FLOW_COUNT; i++)
		h1_out[i] = hash_h1(&flows[i]);
	end = ktime_get();
	*out_ns = time_ns(start, end);
}

static void profile_stage_jhash_h2(const struct flow_key *flows, u32 *h2_out,
				   s64 *out_ns)
{
	ktime_t start, end;
	int i;

	start = ktime_get();
	for (i = 0; i < FLOW_COUNT; i++)
		h2_out[i] = hash_h2_raw(&flows[i]);
	end = ktime_get();
	*out_ns = time_ns(start, end);
}

static void profile_stage_pos_calc(const u32 *h1, const u32 *h2, u32 *pos_out,
				   s64 *out_ns)
{
	ktime_t start, end;
	int i, j;

	start = ktime_get();
	for (i = 0; i < FLOW_COUNT; i++) {
		for (j = 0; j < BLOOM_K; j++)
			pos_out[i * BLOOM_K + j] = (h1[i] + j * h2[i]) & BLOOM_BITS_MASK;
	}
	end = ktime_get();
	*out_ns = time_ns(start, end);
}

/* noinline: ftrace function_graph can attach here for S5 timing */
noinline s64 profile_stage_set_bit(const u32 *pos)
{
	ktime_t start, end;
	int i, j;

	bitmap_zero(bloom, BLOOM_BITS);
	start = ktime_get();
	for (i = 0; i < FLOW_COUNT; i++) {
		for (j = 0; j < BLOOM_K; j++)
			set_bit(pos[i * BLOOM_K + j], bloom);
	}
	end = ktime_get();
	return time_ns(start, end);
}

/* S5b: non-atomic __set_bit for LOCK overhead comparison */
noinline s64 profile_stage___set_bit(const u32 *pos)
{
	ktime_t start, end;
	int i, j;

	bitmap_zero(bloom, BLOOM_BITS);
	start = ktime_get();
	for (i = 0; i < FLOW_COUNT; i++) {
		for (j = 0; j < BLOOM_K; j++)
			__set_bit(pos[i * BLOOM_K + j], bloom);
	}
	end = ktime_get();
	return time_ns(start, end);
}

static void profile_stage_set_bit_timed(const u32 *pos, s64 *out_ns)
{
	*out_ns = profile_stage_set_bit(pos);
}

/*
 * Same pos[] and empty bitmap: set_bit vs __set_bit must yield identical
 * bitmap when only one CPU writes (no concurrent writers).
 */
static bool bloom_verify_set_bit_bitmap(const u32 *pos)
{
	unsigned long *atomic_map, *nonatomic_map;
	unsigned int bits_atomic, bits_nonatomic;
	int i, j, diff_bits;
	bool same;

	atomic_map = kmalloc_array(BLOOM_WORDS, sizeof(*atomic_map), GFP_KERNEL);
	nonatomic_map = kmalloc_array(BLOOM_WORDS, sizeof(*nonatomic_map), GFP_KERNEL);
	if (!atomic_map || !nonatomic_map) {
		pr_err("bloom_build_profile: bitmap verify alloc failed\n");
		kfree(atomic_map);
		kfree(nonatomic_map);
		return false;
	}

	bitmap_zero(bloom, BLOOM_BITS);
	for (i = 0; i < FLOW_COUNT; i++) {
		for (j = 0; j < BLOOM_K; j++)
			set_bit(pos[i * BLOOM_K + j], bloom);
	}
	bitmap_copy(atomic_map, bloom, BLOOM_BITS);
	bits_atomic = bitmap_weight(atomic_map, BLOOM_BITS);

	bitmap_zero(bloom, BLOOM_BITS);
	for (i = 0; i < FLOW_COUNT; i++) {
		for (j = 0; j < BLOOM_K; j++)
			__set_bit(pos[i * BLOOM_K + j], bloom);
	}
	bitmap_copy(nonatomic_map, bloom, BLOOM_BITS);
	bits_nonatomic = bitmap_weight(nonatomic_map, BLOOM_BITS);

	same = bitmap_equal(atomic_map, nonatomic_map, BLOOM_BITS);
	diff_bits = 0;
	if (!same) {
		for (i = 0; i < BLOOM_BITS; i++) {
			if (test_bit(i, atomic_map) != test_bit(i, nonatomic_map))
				diff_bits++;
		}
	}

	pr_info("=== bitmap verify: set_bit vs __set_bit ===\n");
	pr_info("cpu: %d (single writer, sequential, no concurrent access)\n",
		smp_processor_id());
	if (same) {
		pr_info("result: IDENTICAL — %u bits set in both bitmaps\n",
			bits_atomic);
	} else {
		pr_err("result: MISMATCH — %d bits differ (atomic=%u, nonatomic=%u)\n",
		       diff_bits, bits_atomic, bits_nonatomic);
	}

	kfree(atomic_map);
	kfree(nonatomic_map);
	return same;
}

static void profile_stage_full_insert(const struct flow_key *flows, s64 *out_ns)
{
	ktime_t start, end;
	int i;

	bitmap_zero(bloom, BLOOM_BITS);
	start = ktime_get();
	for (i = 0; i < FLOW_COUNT; i++)
		bloom_insert_flow(&flows[i]);
	end = ktime_get();
	*out_ns = time_ns(start, end);
}

static u32 pct_x100(s64 part, s64 whole)
{
	if (whole <= 0)
		return 0;
	return div64_u64(part * 10000, whole);
}

static void print_stage_line(const char *name, s64 total_ns, s64 baseline_ns,
			     int ops)
{
	u32 pct = pct_x100(total_ns, baseline_ns);
	s64 per_op = ops ? div_s64(total_ns, ops) : 0;

	pr_info("  %-28s %10lld ns  %6lld ns/op  %3u.%02u%%\n",
		name, total_ns, per_op, pct / 100, pct % 100);
}

static void bloom_run_build_profile(void)
{
	struct flow_key *flows;
	u32 *h1, *h2, *pos;
	struct build_stage_times t;
	s64 __set_bit_ns;

	flows = kmalloc_array(FLOW_COUNT, sizeof(*flows), GFP_KERNEL);
	h1 = kmalloc_array(FLOW_COUNT, sizeof(*h1), GFP_KERNEL);
	h2 = kmalloc_array(FLOW_COUNT, sizeof(*h2), GFP_KERNEL);
	pos = kmalloc_array(FLOW_COUNT * BLOOM_K, sizeof(*pos), GFP_KERNEL);
	if (!flows || !h1 || !h2 || !pos) {
		pr_err("bloom_build_profile: allocation failed\n");
		kfree(flows);
		kfree(h1);
		kfree(h2);
		kfree(pos);
		return;
	}

	profile_stage_flow_gen(flows, &t.flow_gen_ns);
	profile_stage_full_insert(flows, &t.full_insert_ns);
	profile_stage_bitmap_zero(&t.bitmap_zero_ns);
	profile_stage_jhash_h1(flows, h1, &t.jhash_h1_ns);
	profile_stage_jhash_h2(flows, h2, &t.jhash_h2_ns);
	profile_stage_pos_calc(h1, h2, pos, &t.pos_calc_ns);
	bloom_verify_set_bit_bitmap(pos);
	profile_stage_set_bit_timed(pos, &t.set_bit_ns);
	__set_bit_ns = profile_stage___set_bit(pos);

	pr_info("=== Bloom Build Profile (insert only) ===\n");
	pr_info("fixed mkn: m=%d bits (16 KB), k=%d, n=%d flows\n",
		BLOOM_BITS, BLOOM_K, FLOW_COUNT);
	pr_info("flow key: src_ip + dst_ip + src_port + dst_port + protocol\n");
	pr_info("hash: jhash + double hashing\n");
	pr_info("baseline: full insert = %lld ns (%lld ms)\n",
		t.full_insert_ns, div_s64(t.full_insert_ns, 1000000));
	pr_info("stage                         total time   per-op       %% of insert\n");
	pr_info("--------------------------------------------------------------------\n");
	print_stage_line("S0 flow generate", t.flow_gen_ns, t.full_insert_ns, FLOW_COUNT);
	print_stage_line("S1 bitmap zero", t.bitmap_zero_ns, t.full_insert_ns, 1);
	print_stage_line("S2 jhash h1", t.jhash_h1_ns, t.full_insert_ns, FLOW_COUNT);
	print_stage_line("S3 jhash h2", t.jhash_h2_ns, t.full_insert_ns, FLOW_COUNT);
	print_stage_line("S4 position calc (n*k)", t.pos_calc_ns, t.full_insert_ns,
			 FLOW_COUNT * BLOOM_K);
	print_stage_line("S5 set_bit (n*k)", t.set_bit_ns, t.full_insert_ns,
			 FLOW_COUNT * BLOOM_K);
	print_stage_line("S5b __set_bit non-atomic", __set_bit_ns, t.full_insert_ns,
			 FLOW_COUNT * BLOOM_K);
	print_stage_line("S6 full insert [baseline]", t.full_insert_ns, t.full_insert_ns,
			 FLOW_COUNT);

	pr_info("LOCK overhead hint (S5 - S5b): %lld ns\n",
		t.set_bit_ns - __set_bit_ns);

	pr_info("insert path sum (S2+S3+S4+S5): %lld ns (isolated stages, no pipeline overlap)\n",
		t.jhash_h1_ns + t.jhash_h2_ns + t.pos_calc_ns + t.set_bit_ns);
	pr_info("hash subtotal (S2+S3):         %lld ns\n",
		t.jhash_h1_ns + t.jhash_h2_ns);
	pr_info("bitmap subtotal (S5):          %lld ns\n", t.set_bit_ns);

	if (t.set_bit_ns >= t.jhash_h1_ns + t.jhash_h2_ns &&
	    t.set_bit_ns >= t.pos_calc_ns)
		pr_info("bottleneck hint: set_bit / bitmap write dominates\n");
	else if (t.jhash_h1_ns + t.jhash_h2_ns >= t.set_bit_ns)
		pr_info("bottleneck hint: jhash dominates -> consider jhash2, siphash, or cached hashes\n");
	else
		pr_info("bottleneck hint: position calc is minor; focus on hash and set_bit\n");

	kfree(flows);
	kfree(h1);
	kfree(h2);
	kfree(pos);
}

/* --- multi-core insert benchmark (shared vs per-CPU bitmap) --- */

static int mc_pick_cpus(int nr, int *cpus_out);

struct mc_worker_arg {
	const u32 *pos;
	unsigned long *bitmap;
	unsigned long **all_bitmaps;
	int nr_bitmaps;
	int flow_start;
	int flow_count;
	int worker_id;
	int bind_cpu;
	s64 worker_ns;
	int hits;
	struct completion done;
};

static wait_queue_head_t mc_start_wq;
static bool mc_start_flag;

static void mc_insert_pos_range_shared(const u32 *pos, unsigned long *bitmap,
				       int flow_start, int flow_count)
{
	int i, j;

	for (i = 0; i < flow_count; i++) {
		int fi = flow_start + i;

		for (j = 0; j < BLOOM_K; j++)
			set_bit(pos[fi * BLOOM_K + j], bitmap);
	}
}

static void mc_insert_pos_range_percpu(const u32 *pos, unsigned long *bitmap,
				       int flow_start, int flow_count)
{
	int i, j;

	for (i = 0; i < flow_count; i++) {
		int fi = flow_start + i;

		for (j = 0; j < BLOOM_K; j++)
			__set_bit(pos[fi * BLOOM_K + j], bitmap);
	}
}

/* --- multi-core lookup benchmark (shared vs per-CPU bitmap) --- */

static void mc_build_shared_bloom(const u32 *pos, unsigned long *bitmap)
{
	bitmap_zero(bitmap, BLOOM_BITS);
	mc_insert_pos_range_shared(pos, bitmap, 0, FLOW_COUNT);
}

static int mc_build_percpu_bloom(const u32 *pos, unsigned long **maps,
				 int nr_threads)
{
	int cpus[MC_MAX_THREADS];
	int got, i, flows_per, rem, off;

	got = mc_pick_cpus(nr_threads, cpus);
	if (got < nr_threads)
		return -1;

	flows_per = FLOW_COUNT / nr_threads;
	rem = FLOW_COUNT % nr_threads;
	off = 0;

	for (i = 0; i < nr_threads; i++) {
		int chunk = flows_per + (i < rem ? 1 : 0);

		bitmap_zero(maps[i], BLOOM_BITS);
		mc_insert_pos_range_percpu(pos, maps[i], off, chunk);
		off += chunk;
	}
	return 0;
}

static int mc_lookup_pos_range_shared(const u32 *pos, unsigned long *bitmap,
				      int flow_start, int flow_count)
{
	int i, j, hits = 0;

	for (i = 0; i < flow_count; i++) {
		int fi = flow_start + i;
		bool found = true;

		for (j = 0; j < BLOOM_K; j++) {
			if (!test_bit(pos[fi * BLOOM_K + j], bitmap)) {
				found = false;
				break;
			}
		}
		if (found)
			hits++;
	}
	return hits;
}

static bool mc_lookup_flow_percpu(const u32 *pos, int fi,
				  unsigned long **maps, int nr_maps)
{
	int j, c;

	for (j = 0; j < BLOOM_K; j++) {
		u32 bit = pos[fi * BLOOM_K + j];
		bool any_set = false;

		for (c = 0; c < nr_maps; c++) {
			if (test_bit(bit, maps[c])) {
				any_set = true;
				break;
			}
		}
		if (!any_set)
			return false;
	}
	return true;
}

static int mc_lookup_pos_range_percpu(const u32 *pos, unsigned long **maps,
				      int nr_maps, int flow_start,
				      int flow_count)
{
	int i, hits = 0;

	for (i = 0; i < flow_count; i++) {
		int fi = flow_start + i;

		if (mc_lookup_flow_percpu(pos, fi, maps, nr_maps))
			hits++;
	}
	return hits;
}

static int mc_lookup_shared_worker(void *data)
{
	struct mc_worker_arg *arg = data;
	ktime_t start, end;

	wait_event(mc_start_wq, mc_start_flag || kthread_should_stop());
	if (kthread_should_stop())
		return 0;
	start = ktime_get();
	arg->hits = mc_lookup_pos_range_shared(arg->pos, arg->bitmap,
					     arg->flow_start, arg->flow_count);
	end = ktime_get();
	arg->worker_ns = time_ns(start, end);
	complete(&arg->done);
	return 0;
}

static int mc_lookup_percpu_worker(void *data)
{
	struct mc_worker_arg *arg = data;
	ktime_t start, end;

	wait_event(mc_start_wq, mc_start_flag || kthread_should_stop());
	if (kthread_should_stop())
		return 0;
	start = ktime_get();
	arg->hits = mc_lookup_pos_range_percpu(arg->pos, arg->all_bitmaps,
					      arg->nr_bitmaps,
					      arg->flow_start, arg->flow_count);
	end = ktime_get();
	arg->worker_ns = time_ns(start, end);
	complete(&arg->done);
	return 0;
}

static s64 mc_run_lookup_benchmark(const u32 *pos, unsigned long *shared_bitmap,
				   int nr_threads, bool percpu_mode,
				   s64 *max_worker_ns_out, int *hits_out)
{
	struct mc_worker_arg args[MC_MAX_THREADS];
	struct task_struct *tasks[MC_MAX_THREADS];
	unsigned long *percpu_maps[MC_MAX_THREADS];
	int cpus[MC_MAX_THREADS];
	int i, got, flows_per, rem, off, total_hits = 0;
	ktime_t wall_start, wall_end;
	s64 max_worker_ns = 0;

	got = mc_pick_cpus(nr_threads, cpus);
	if (got < nr_threads)
		return -1;

	if (percpu_mode) {
		for (i = 0; i < nr_threads; i++) {
			percpu_maps[i] = kcalloc(BLOOM_WORDS, sizeof(unsigned long),
						 GFP_KERNEL);
			if (!percpu_maps[i])
				goto free_maps;
		}
		if (mc_build_percpu_bloom(pos, percpu_maps, nr_threads) < 0)
			goto free_maps;
	} else {
		mc_build_shared_bloom(pos, shared_bitmap);
		for (i = 0; i < nr_threads; i++)
			percpu_maps[i] = NULL;
	}

	init_waitqueue_head(&mc_start_wq);
	mc_start_flag = false;

	flows_per = FLOW_COUNT / nr_threads;
	rem = FLOW_COUNT % nr_threads;
	off = 0;

	for (i = 0; i < nr_threads; i++) {
		int chunk = flows_per + (i < rem ? 1 : 0);

		init_completion(&args[i].done);
		args[i].pos = pos;
		args[i].flow_start = off;
		args[i].flow_count = chunk;
		args[i].worker_id = i;
		args[i].bind_cpu = cpus[i];
		args[i].worker_ns = 0;
		args[i].hits = 0;
		args[i].bitmap = percpu_mode ? NULL : shared_bitmap;
		args[i].all_bitmaps = percpu_mode ? percpu_maps : NULL;
		args[i].nr_bitmaps = percpu_mode ? nr_threads : 0;

		tasks[i] = kthread_create(percpu_mode ? mc_lookup_percpu_worker :
					    mc_lookup_shared_worker,
					    &args[i], "bloom_mcl/%d", i);
		if (IS_ERR(tasks[i])) {
			nr_threads = i;
			goto stop_partial;
		}
		kthread_bind(tasks[i], cpus[i]);
		wake_up_process(tasks[i]);
		off += chunk;
	}

	wall_start = ktime_get();
	mc_start_flag = true;
	wake_up_all(&mc_start_wq);

	for (i = 0; i < nr_threads; i++)
		wait_for_completion(&args[i].done);
	wall_end = ktime_get();

	for (i = 0; i < nr_threads; i++) {
		total_hits += args[i].hits;
		if (args[i].worker_ns > max_worker_ns)
			max_worker_ns = args[i].worker_ns;
	}

	*hits_out = total_hits;
	*max_worker_ns_out = max_worker_ns;

	if (percpu_mode) {
		for (i = 0; i < nr_threads; i++)
			kfree(percpu_maps[i]);
	}
	return time_ns(wall_start, wall_end);

stop_partial:
	for (i = 0; i < nr_threads; i++) {
		if (!IS_ERR(tasks[i]))
			kthread_stop(tasks[i]);
	}
free_maps:
	if (percpu_mode) {
		for (i = 0; i < nr_threads; i++)
			kfree(percpu_maps[i]);
	}
	return -1;
}

static int mc_shared_worker(void *data)
{
	struct mc_worker_arg *arg = data;
	ktime_t start, end;

	wait_event(mc_start_wq, mc_start_flag || kthread_should_stop());
	if (kthread_should_stop())
		return 0;
	start = ktime_get();
	mc_insert_pos_range_shared(arg->pos, arg->bitmap,
				   arg->flow_start, arg->flow_count);
	end = ktime_get();
	arg->worker_ns = time_ns(start, end);
	complete(&arg->done);
	return 0;
}

static int mc_percpu_worker(void *data)
{
	struct mc_worker_arg *arg = data;
	ktime_t start, end;

	wait_event(mc_start_wq, mc_start_flag || kthread_should_stop());
	if (kthread_should_stop())
		return 0;
	start = ktime_get();
	mc_insert_pos_range_percpu(arg->pos, arg->bitmap,
				   arg->flow_start, arg->flow_count);
	end = ktime_get();
	arg->worker_ns = time_ns(start, end);
	complete(&arg->done);
	return 0;
}

static int mc_pick_cpus(int nr, int *cpus_out)
{
	int i, n = 0;

	for (i = 0; i < nr_cpu_ids && n < nr; i++) {
		if (cpu_online(i)) {
			cpus_out[n] = i;
			n++;
		}
	}
	return n;
}

static s64 mc_run_benchmark(const u32 *pos, unsigned long *shared_bitmap,
			    int nr_threads, bool percpu_mode,
			    s64 *max_worker_ns_out, unsigned int *bits_out)
{
	struct mc_worker_arg args[MC_MAX_THREADS];
	struct task_struct *tasks[MC_MAX_THREADS];
	unsigned long *percpu_maps[MC_MAX_THREADS];
	int cpus[MC_MAX_THREADS];
	int i, got, flows_per, rem, off;
	ktime_t wall_start, wall_end;
	s64 max_worker_ns = 0;

	got = mc_pick_cpus(nr_threads, cpus);
	if (got < nr_threads)
		return -1;

	if (percpu_mode) {
		for (i = 0; i < nr_threads; i++) {
			percpu_maps[i] = kcalloc(BLOOM_WORDS, sizeof(unsigned long),
						 GFP_KERNEL);
			if (!percpu_maps[i])
				goto free_maps;
			bitmap_zero(percpu_maps[i], BLOOM_BITS);
		}
	} else {
		bitmap_zero(shared_bitmap, BLOOM_BITS);
		for (i = 0; i < nr_threads; i++)
			percpu_maps[i] = NULL;
	}

	init_waitqueue_head(&mc_start_wq);
	mc_start_flag = false;

	flows_per = FLOW_COUNT / nr_threads;
	rem = FLOW_COUNT % nr_threads;
	off = 0;

	for (i = 0; i < nr_threads; i++) {
		int chunk = flows_per + (i < rem ? 1 : 0);

		init_completion(&args[i].done);
		args[i].pos = pos;
		args[i].flow_start = off;
		args[i].flow_count = chunk;
		args[i].worker_id = i;
		args[i].bind_cpu = cpus[i];
		args[i].worker_ns = 0;
		args[i].bitmap = percpu_mode ? percpu_maps[i] : shared_bitmap;

		tasks[i] = kthread_create(percpu_mode ? mc_percpu_worker :
					    mc_shared_worker,
					    &args[i], "bloom_mc/%d", i);
		if (IS_ERR(tasks[i])) {
			nr_threads = i;
			goto stop_partial;
		}
		kthread_bind(tasks[i], cpus[i]);
		wake_up_process(tasks[i]);
		off += chunk;
	}

	wall_start = ktime_get();
	mc_start_flag = true;
	wake_up_all(&mc_start_wq);

	for (i = 0; i < nr_threads; i++)
		wait_for_completion(&args[i].done);
	wall_end = ktime_get();

	for (i = 0; i < nr_threads; i++) {
		if (args[i].worker_ns > max_worker_ns)
			max_worker_ns = args[i].worker_ns;
	}

	if (percpu_mode) {
		unsigned int total_bits = 0;

		for (i = 0; i < nr_threads; i++)
			total_bits += bitmap_weight(percpu_maps[i], BLOOM_BITS);
		*bits_out = total_bits;
	} else {
		*bits_out = bitmap_weight(shared_bitmap, BLOOM_BITS);
	}

	*max_worker_ns_out = max_worker_ns;

	for (i = 0; i < nr_threads; i++)
		kfree(percpu_maps[i]);
	return time_ns(wall_start, wall_end);

stop_partial:
	for (i = 0; i < nr_threads; i++) {
		if (!IS_ERR(tasks[i]))
			kthread_stop(tasks[i]);
		kfree(percpu_maps[i]);
	}
	return -1;

free_maps:
	while (--i >= 0)
		kfree(percpu_maps[i]);
	return -1;
}

noinline void bloom_run_multicore_benchmark(void)
{
	struct flow_key *flows;
	u32 *h1, *h2, *pos;
	unsigned long *shared_bitmap, *golden_bitmap;
	unsigned int golden_bits;
	s64 dummy, golden_ns, wall_ns, max_worker_ns;
	s64 baseline_1t_shared_ns = 0;
	int i, nr_list[] = { 1, 2, 4, 8 };
	int nr_count = ARRAY_SIZE(nr_list);
	int online = num_online_cpus();

	flows = kmalloc_array(FLOW_COUNT, sizeof(*flows), GFP_KERNEL);
	h1 = kmalloc_array(FLOW_COUNT, sizeof(*h1), GFP_KERNEL);
	h2 = kmalloc_array(FLOW_COUNT, sizeof(*h2), GFP_KERNEL);
	pos = kmalloc_array(FLOW_COUNT * BLOOM_K, sizeof(*pos), GFP_KERNEL);
	shared_bitmap = kcalloc(BLOOM_WORDS, sizeof(*shared_bitmap), GFP_KERNEL);
	golden_bitmap = kcalloc(BLOOM_WORDS, sizeof(*golden_bitmap), GFP_KERNEL);
	if (!flows || !h1 || !h2 || !pos || !shared_bitmap || !golden_bitmap) {
		pr_err("bloom_build_profile: multicore alloc failed\n");
		goto out_free;
	}

	for (i = 0; i < FLOW_COUNT; i++)
		flow_generate(&flows[i], i);
	profile_stage_jhash_h1(flows, h1, &dummy);
	profile_stage_jhash_h2(flows, h2, &dummy);
	profile_stage_pos_calc(h1, h2, pos, &dummy);

	bitmap_zero(golden_bitmap, BLOOM_BITS);
	golden_ns = profile_stage_set_bit(pos);
	bitmap_copy(golden_bitmap, bloom, BLOOM_BITS);
	golden_bits = bitmap_weight(golden_bitmap, BLOOM_BITS);

	pr_info("=== Multi-core Bloom Insert Benchmark ===\n");
	pr_info("mkn: m=%d, k=%d, n=%d flows | online cpus=%d\n",
		BLOOM_BITS, BLOOM_K, FLOW_COUNT, online);
	pr_info("golden single-thread shared: %lld ns, %u distinct bits\n",
		golden_ns, golden_bits);
	pr_info("------------------------------------------------------------------------\n");
	pr_info("threads  mode          wall_ns   ops/sec   speedup  max_worker_ns  bits\n");
	pr_info("------------------------------------------------------------------------\n");

	for (i = 0; i < nr_count; i++) {
		int nr = nr_list[i];
		unsigned int bits;
		u32 speedup_x100;
		u64 ops_per_sec;

		if (nr > online)
			continue;

		wall_ns = mc_run_benchmark(pos, shared_bitmap, nr, false,
					   &max_worker_ns, &bits);
		if (wall_ns < 0) {
			pr_err("shared nr=%d failed\n", nr);
			continue;
		}
		if (nr == 1)
			baseline_1t_shared_ns = wall_ns;
		ops_per_sec = wall_ns > 0 ?
			div64_u64((u64)FLOW_COUNT * 1000000000ULL, wall_ns) : 0;
		speedup_x100 = baseline_1t_shared_ns > 0 ?
			div64_u64(baseline_1t_shared_ns * 100, wall_ns) : 100;

		pr_info("%7d  shared       %8lld %9llu   %3u.%02ux %11lld %6u%s\n",
			nr, wall_ns, ops_per_sec,
			speedup_x100 / 100, speedup_x100 % 100,
			max_worker_ns, bits,
			bits == golden_bits ? "" : " MISMATCH");

		wall_ns = mc_run_benchmark(pos, shared_bitmap, nr, true,
					   &max_worker_ns, &bits);
		if (wall_ns < 0) {
			pr_err("percpu nr=%d failed\n", nr);
			continue;
		}
		ops_per_sec = wall_ns > 0 ?
			div64_u64((u64)FLOW_COUNT * 1000000000ULL, wall_ns) : 0;
		speedup_x100 = baseline_1t_shared_ns > 0 ?
			div64_u64(baseline_1t_shared_ns * 100, wall_ns) : 100;

		pr_info("%7d  per-cpu      %8lld %9llu   %3u.%02ux %11lld %6u (sum)\n",
			nr, wall_ns, ops_per_sec,
			speedup_x100 / 100, speedup_x100 % 100,
			max_worker_ns, bits);
	}

	pr_info("------------------------------------------------------------------------\n");
	pr_info("interpret: shared speedup << nr threads => cache coherence contention\n");
	pr_info("           per-cpu faster scaling => private bitmap avoids line bouncing\n");

out_free:
	kfree(flows);
	kfree(h1);
	kfree(h2);
	kfree(pos);
	kfree(shared_bitmap);
	kfree(golden_bitmap);
}

noinline void bloom_run_multicore_lookup_benchmark(void)
{
	struct flow_key *flows;
	u32 *h1, *h2, *pos;
	unsigned long *shared_bitmap;
	s64 dummy, wall_ns, max_worker_ns;
	s64 baseline_1t_shared_ns = 0;
	int i, nr_list[] = { 1, 2, 4, 8 };
	int nr_count = ARRAY_SIZE(nr_list);
	int online = num_online_cpus();
	int hits;

	flows = kmalloc_array(FLOW_COUNT, sizeof(*flows), GFP_KERNEL);
	h1 = kmalloc_array(FLOW_COUNT, sizeof(*h1), GFP_KERNEL);
	h2 = kmalloc_array(FLOW_COUNT, sizeof(*h2), GFP_KERNEL);
	pos = kmalloc_array(FLOW_COUNT * BLOOM_K, sizeof(*pos), GFP_KERNEL);
	shared_bitmap = kcalloc(BLOOM_WORDS, sizeof(*shared_bitmap), GFP_KERNEL);
	if (!flows || !h1 || !h2 || !pos || !shared_bitmap) {
		pr_err("bloom_build_profile: multicore lookup alloc failed\n");
		goto out_free;
	}

	for (i = 0; i < FLOW_COUNT; i++)
		flow_generate(&flows[i], i);
	profile_stage_jhash_h1(flows, h1, &dummy);
	profile_stage_jhash_h2(flows, h2, &dummy);
	profile_stage_pos_calc(h1, h2, pos, &dummy);

	pr_info("=== Multi-core Bloom Lookup Benchmark (positive) ===\n");
	pr_info("mkn: m=%d, k=%d, n=%d flows | online cpus=%d\n",
		BLOOM_BITS, BLOOM_K, FLOW_COUNT, online);
	pr_info("build: same flows as insert; lookup expects %d/%d hits\n",
		FLOW_COUNT, FLOW_COUNT);
	pr_info("------------------------------------------------------------------------\n");
	pr_info("threads  mode          wall_ns   ops/sec   speedup  max_worker_ns  hits\n");
	pr_info("------------------------------------------------------------------------\n");

	for (i = 0; i < nr_count; i++) {
		int nr = nr_list[i];
		u32 speedup_x100;
		u64 ops_per_sec;

		if (nr > online)
			continue;

		wall_ns = mc_run_lookup_benchmark(pos, shared_bitmap, nr, false,
						  &max_worker_ns, &hits);
		if (wall_ns < 0) {
			pr_err("lookup shared nr=%d failed\n", nr);
			continue;
		}
		if (nr == 1)
			baseline_1t_shared_ns = wall_ns;
		ops_per_sec = wall_ns > 0 ?
			div64_u64((u64)FLOW_COUNT * 1000000000ULL, wall_ns) : 0;
		speedup_x100 = baseline_1t_shared_ns > 0 ?
			div64_u64(baseline_1t_shared_ns * 100, wall_ns) : 100;

		pr_info("%7d  shared       %8lld %9llu   %3u.%02ux %11lld %6d%s\n",
			nr, wall_ns, ops_per_sec,
			speedup_x100 / 100, speedup_x100 % 100,
			max_worker_ns, hits,
			hits == FLOW_COUNT ? "" : " MISMATCH");

		wall_ns = mc_run_lookup_benchmark(pos, shared_bitmap, nr, true,
						  &max_worker_ns, &hits);
		if (wall_ns < 0) {
			pr_err("lookup per-cpu nr=%d failed\n", nr);
			continue;
		}
		ops_per_sec = wall_ns > 0 ?
			div64_u64((u64)FLOW_COUNT * 1000000000ULL, wall_ns) : 0;
		speedup_x100 = baseline_1t_shared_ns > 0 ?
			div64_u64(baseline_1t_shared_ns * 100, wall_ns) : 100;

		pr_info("%7d  per-cpu      %8lld %9llu   %3u.%02ux %11lld %6d%s\n",
			nr, wall_ns, ops_per_sec,
			speedup_x100 / 100, speedup_x100 % 100,
			max_worker_ns, hits,
			hits == FLOW_COUNT ? "" : " MISMATCH");
	}

	pr_info("------------------------------------------------------------------------\n");
	pr_info("interpret: shared lookup is read-only -> should scale better than insert\n");
	pr_info("           per-cpu lookup ORs all copies -> k*N test_bit per query\n");

out_free:
	kfree(flows);
	kfree(h1);
	kfree(h2);
	kfree(pos);
	kfree(shared_bitmap);
}

noinline void bloom_run_bitmap_verify_only(void)
{
	struct flow_key *flows;
	u32 *h1, *h2, *pos;
	s64 dummy;
	int i;

	flows = kmalloc_array(FLOW_COUNT, sizeof(*flows), GFP_KERNEL);
	h1 = kmalloc_array(FLOW_COUNT, sizeof(*h1), GFP_KERNEL);
	h2 = kmalloc_array(FLOW_COUNT, sizeof(*h2), GFP_KERNEL);
	pos = kmalloc_array(FLOW_COUNT * BLOOM_K, sizeof(*pos), GFP_KERNEL);
	if (!flows || !h1 || !h2 || !pos) {
		pr_err("bloom_build_profile: verify alloc failed\n");
		kfree(flows);
		kfree(h1);
		kfree(h2);
		kfree(pos);
		return;
	}

	for (i = 0; i < FLOW_COUNT; i++)
		flow_generate(&flows[i], i);
	profile_stage_jhash_h1(flows, h1, &dummy);
	profile_stage_jhash_h2(flows, h2, &dummy);
	profile_stage_pos_calc(h1, h2, pos, &dummy);
	bloom_verify_set_bit_bitmap(pos);

	kfree(flows);
	kfree(h1);
	kfree(h2);
	kfree(pos);
}

/* ftrace target: run only S5 set_bit stage (prep done outside trace window) */
noinline void bloom_run_setbit_ftrace_target(void)
{
	int i;
	struct flow_key *flows;
	u32 *h1, *h2, *pos;
	s64 set_bit_ns, dummy;

	flows = kmalloc_array(FLOW_COUNT, sizeof(*flows), GFP_KERNEL);
	h1 = kmalloc_array(FLOW_COUNT, sizeof(*h1), GFP_KERNEL);
	h2 = kmalloc_array(FLOW_COUNT, sizeof(*h2), GFP_KERNEL);
	pos = kmalloc_array(FLOW_COUNT * BLOOM_K, sizeof(*pos), GFP_KERNEL);
	if (!flows || !h1 || !h2 || !pos) {
		pr_err("bloom_build_profile: setbit ftrace alloc failed\n");
		kfree(flows);
		kfree(h1);
		kfree(h2);
		kfree(pos);
		return;
	}

	for (i = 0; i < FLOW_COUNT; i++)
		flow_generate(&flows[i], i);
	profile_stage_jhash_h1(flows, h1, &dummy);
	profile_stage_jhash_h2(flows, h2, &dummy);
	profile_stage_pos_calc(h1, h2, pos, &dummy);

	pr_info("=== set_bit ftrace target (S5 only) ===\n");
	set_bit_ns = profile_stage_set_bit(pos);
	pr_info("S5 set_bit total: %lld ns (%d ops)\n",
		set_bit_ns, FLOW_COUNT * BLOOM_K);

	kfree(flows);
	kfree(h1);
	kfree(h2);
	kfree(pos);
}

static ssize_t profile_proc_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	bloom_run_build_profile();
	return count;
}

static ssize_t setbit_proc_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	bloom_run_setbit_ftrace_target();
	return count;
}

static ssize_t verify_proc_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	bloom_run_bitmap_verify_only();
	return count;
}

static ssize_t multicore_proc_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	bloom_run_multicore_benchmark();
	return count;
}

static ssize_t multicore_lookup_proc_write(struct file *file,
					   const char __user *buf,
					   size_t count, loff_t *ppos)
{
	bloom_run_multicore_lookup_benchmark();
	return count;
}

static const struct proc_ops profile_proc_ops = {
	.proc_write = profile_proc_write,
};

static const struct proc_ops setbit_proc_ops = {
	.proc_write = setbit_proc_write,
};

static const struct proc_ops verify_proc_ops = {
	.proc_write = verify_proc_write,
};

static const struct proc_ops multicore_proc_ops = {
	.proc_write = multicore_proc_write,
};

static const struct proc_ops multicore_lookup_proc_ops = {
	.proc_write = multicore_lookup_proc_write,
};

static int __init bloom_build_profile_init(void)
{
	profile_proc_dir = proc_mkdir("bloom_build_profile", NULL);
	if (!profile_proc_dir)
		return -ENOMEM;

	if (!proc_create("run", 0200, profile_proc_dir, &profile_proc_ops)) {
		proc_remove(profile_proc_dir);
		return -ENOMEM;
	}

	if (!proc_create("run_setbit", 0200, profile_proc_dir, &setbit_proc_ops)) {
		proc_remove(profile_proc_dir);
		return -ENOMEM;
	}

	if (!proc_create("run_verify", 0200, profile_proc_dir, &verify_proc_ops)) {
		proc_remove(profile_proc_dir);
		return -ENOMEM;
	}

	if (!proc_create("run_multicore", 0200, profile_proc_dir,
			 &multicore_proc_ops)) {
		proc_remove(profile_proc_dir);
		return -ENOMEM;
	}

	if (!proc_create("run_multicore_lookup", 0200, profile_proc_dir,
			 &multicore_lookup_proc_ops)) {
		proc_remove(profile_proc_dir);
		return -ENOMEM;
	}

	pr_info("bloom_build_profile loaded (m=%d, k=%d, n=%d)\n",
		BLOOM_BITS, BLOOM_K, FLOW_COUNT);
	pr_info("trigger: echo 1 > /proc/bloom_build_profile/run\n");
	pr_info("setbit ftrace: echo 1 > /proc/bloom_build_profile/run_setbit\n");
	pr_info("bitmap verify: echo 1 > /proc/bloom_build_profile/run_verify\n");
	pr_info("multicore: echo 1 > /proc/bloom_build_profile/run_multicore\n");
	pr_info("multicore lookup: echo 1 > /proc/bloom_build_profile/run_multicore_lookup\n");
	return 0;
}

static void __exit bloom_build_profile_exit(void)
{
	proc_remove(profile_proc_dir);
	pr_info("bloom_build_profile unloaded\n");
}

module_init(bloom_build_profile_init);
module_exit(bloom_build_profile_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bloom filter insert/lookup stage profiler");