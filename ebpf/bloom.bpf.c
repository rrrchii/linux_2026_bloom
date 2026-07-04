// SPDX-License-Identifier: GPL-2.0
/*
 * Multi-core Bloom insert + lookup benchmark.
 *
 * Shared: bloom_insert_mc -> BPF_MAP_TYPE_BLOOM_FILTER (bpf_map_push_elem)
 * Per-CPU: bloom_insert_mc_percpu -> PERCPU_ARRAY bitmap (current CPU only)
 *
 * Lookup: bloom_lookup_mc -> bpf_map_peek_elem
 *         bloom_lookup_mc_percpu -> OR bloom_shard[0..nr_shards-1]
 *
 * Userspace fills flow_array and ctrl_array; each thread bpf_prog_test_run()
 * with a control packet (Ethernet + slot byte).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct flow_key {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	__u8 protocol;
} __attribute__((packed));

#define FLOW_COUNT	10000
#define MAX_THREADS	8
#define BLOOM_BITS	131072
#define BLOOM_WORDS	(BLOOM_BITS / 64)
#define BLOOM_K		10

struct bench_ctrl {
	__u32 start;
	__u32 count;
};

struct loop_ctx {
	const struct bench_ctrl *ctrl;
};

struct percpu_bloom {
	__u64 words[BLOOM_WORDS];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct flow_key);
	__uint(max_entries, FLOW_COUNT);
} flow_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct bench_ctrl);
	__uint(max_entries, MAX_THREADS);
} ctrl_array SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_BLOOM_FILTER);
	__type(value, struct flow_key);
	__uint(max_entries, FLOW_COUNT);
	__uint(map_extra, BLOOM_K);
} bloom_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, struct percpu_bloom);
	__uint(max_entries, 1);
} percpu_bloom SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct percpu_bloom);
	__uint(max_entries, MAX_THREADS);
} bloom_shard SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} lookup_meta SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 2);
} stats_map SEC(".maps");

enum stat_key {
	STAT_PUSH_OK = 0,
	STAT_PUSH_ERR,
};

enum lookup_stat {
	STAT_LOOKUP_HIT = STAT_PUSH_OK,
	STAT_LOOKUP_MISS = STAT_PUSH_ERR,
};

static __always_inline void stat_inc(__u32 key)
{
	__u64 *cnt = bpf_map_lookup_elem(&stats_map, &key);

	if (cnt)
		__sync_fetch_and_add(cnt, 1);
}

static __always_inline __u32 mix32(__u32 x)
{
	x ^= x >> 16;
	x *= 0x7feb352d;
	x ^= x >> 15;
	x *= 0x846ca68b;
	x ^= x >> 16;
	return x;
}

static __always_inline __u32 flow_hash_seed(const struct flow_key *flow, __u32 seed)
{
	__u32 h = seed;

	h ^= (__u32)flow->src_ip;
	h = mix32(h);
	h ^= (__u32)flow->dst_ip;
	h = mix32(h);
	h ^= ((__u32)flow->src_port << 16) | (__u32)flow->dst_port;
	h = mix32(h);
	h ^= (__u32)flow->protocol;
	return mix32(h);
}

static __always_inline void flow_hash_pair(const struct flow_key *flow,
					   __u32 *h1_out, __u32 *h2_out)
{
	__u32 h1, h2;

	h1 = flow_hash_seed(flow, 0xbc9f1d34) & (BLOOM_BITS - 1);
	h2 = flow_hash_seed(flow, 0x7f4a7c15) & (BLOOM_BITS - 1);
	h2 |= 1;
	if (h2 >= BLOOM_BITS)
		h2 = 1;

	*h1_out = h1;
	*h2_out = h2;
}

static __always_inline void percpu_set_bit(struct percpu_bloom *bitmap, __u32 bit)
{
	__u32 word = bit >> 6;
	__u32 off = bit & 63;

	bitmap->words[word] |= (1ULL << off);
}

static __always_inline void percpu_set_k_bits(struct percpu_bloom *bitmap,
					      __u32 h1, __u32 h2)
{
	percpu_set_bit(bitmap, (h1 + 0 * h2) & (BLOOM_BITS - 1));
	percpu_set_bit(bitmap, (h1 + 1 * h2) & (BLOOM_BITS - 1));
	percpu_set_bit(bitmap, (h1 + 2 * h2) & (BLOOM_BITS - 1));
	percpu_set_bit(bitmap, (h1 + 3 * h2) & (BLOOM_BITS - 1));
	percpu_set_bit(bitmap, (h1 + 4 * h2) & (BLOOM_BITS - 1));
	percpu_set_bit(bitmap, (h1 + 5 * h2) & (BLOOM_BITS - 1));
	percpu_set_bit(bitmap, (h1 + 6 * h2) & (BLOOM_BITS - 1));
	percpu_set_bit(bitmap, (h1 + 7 * h2) & (BLOOM_BITS - 1));
	percpu_set_bit(bitmap, (h1 + 8 * h2) & (BLOOM_BITS - 1));
	percpu_set_bit(bitmap, (h1 + 9 * h2) & (BLOOM_BITS - 1));
}

static __always_inline __u32 percpu_test_bit(const struct percpu_bloom *bitmap,
					     __u32 bit)
{
	__u32 word = bit >> 6;
	__u32 off = bit & 63;

	return !!(bitmap->words[word] & (1ULL << off));
}

static __always_inline __u32 bit_set_in_any_shard(__u32 nr_shards, __u32 bit)
{
	struct percpu_bloom *b;
	__u32 k;

	k = 0;
	if (nr_shards > 0) {
		b = bpf_map_lookup_elem(&bloom_shard, &k);
		if (b && percpu_test_bit(b, bit))
			return 1;
	}
	k = 1;
	if (nr_shards > 1) {
		b = bpf_map_lookup_elem(&bloom_shard, &k);
		if (b && percpu_test_bit(b, bit))
			return 1;
	}
	k = 2;
	if (nr_shards > 2) {
		b = bpf_map_lookup_elem(&bloom_shard, &k);
		if (b && percpu_test_bit(b, bit))
			return 1;
	}
	k = 3;
	if (nr_shards > 3) {
		b = bpf_map_lookup_elem(&bloom_shard, &k);
		if (b && percpu_test_bit(b, bit))
			return 1;
	}
	k = 4;
	if (nr_shards > 4) {
		b = bpf_map_lookup_elem(&bloom_shard, &k);
		if (b && percpu_test_bit(b, bit))
			return 1;
	}
	k = 5;
	if (nr_shards > 5) {
		b = bpf_map_lookup_elem(&bloom_shard, &k);
		if (b && percpu_test_bit(b, bit))
			return 1;
	}
	k = 6;
	if (nr_shards > 6) {
		b = bpf_map_lookup_elem(&bloom_shard, &k);
		if (b && percpu_test_bit(b, bit))
			return 1;
	}
	k = 7;
	if (nr_shards > 7) {
		b = bpf_map_lookup_elem(&bloom_shard, &k);
		if (b && percpu_test_bit(b, bit))
			return 1;
	}
	return 0;
}

static __always_inline __u32 percpu_bloom_lookup(__u32 nr_shards, __u32 h1, __u32 h2)
{
	if (!bit_set_in_any_shard(nr_shards, (h1 + 0 * h2) & (BLOOM_BITS - 1)))
		return 0;
	if (!bit_set_in_any_shard(nr_shards, (h1 + 1 * h2) & (BLOOM_BITS - 1)))
		return 0;
	if (!bit_set_in_any_shard(nr_shards, (h1 + 2 * h2) & (BLOOM_BITS - 1)))
		return 0;
	if (!bit_set_in_any_shard(nr_shards, (h1 + 3 * h2) & (BLOOM_BITS - 1)))
		return 0;
	if (!bit_set_in_any_shard(nr_shards, (h1 + 4 * h2) & (BLOOM_BITS - 1)))
		return 0;
	if (!bit_set_in_any_shard(nr_shards, (h1 + 5 * h2) & (BLOOM_BITS - 1)))
		return 0;
	if (!bit_set_in_any_shard(nr_shards, (h1 + 6 * h2) & (BLOOM_BITS - 1)))
		return 0;
	if (!bit_set_in_any_shard(nr_shards, (h1 + 7 * h2) & (BLOOM_BITS - 1)))
		return 0;
	if (!bit_set_in_any_shard(nr_shards, (h1 + 8 * h2) & (BLOOM_BITS - 1)))
		return 0;
	if (!bit_set_in_any_shard(nr_shards, (h1 + 9 * h2) & (BLOOM_BITS - 1)))
		return 0;
	return 1;
}

static long push_flow_shared_iter(__u32 iter, struct loop_ctx *loop_ctx)
{
	const struct bench_ctrl *ctrl = loop_ctx->ctrl;
	struct flow_key *flow;
	__u32 idx = ctrl->start + iter;
	int err;

	if (idx >= FLOW_COUNT)
		return 1;

	flow = bpf_map_lookup_elem(&flow_array, &idx);
	if (!flow)
		return 0;

	err = bpf_map_push_elem(&bloom_map, flow, BPF_ANY);
	if (err)
		stat_inc(STAT_PUSH_ERR);
	else
		stat_inc(STAT_PUSH_OK);
	return 0;
}

static long push_flow_shared_iter_nostats(__u32 iter, struct loop_ctx *loop_ctx)
{
	const struct bench_ctrl *ctrl = loop_ctx->ctrl;
	struct flow_key *flow;
	__u32 idx = ctrl->start + iter;

	if (idx >= FLOW_COUNT)
		return 1;

	flow = bpf_map_lookup_elem(&flow_array, &idx);
	if (!flow)
		return 0;

	bpf_map_push_elem(&bloom_map, flow, BPF_ANY);
	return 0;
}

static long push_flow_percpu_iter(__u32 iter, struct loop_ctx *loop_ctx)
{
	const struct bench_ctrl *ctrl = loop_ctx->ctrl;
	struct percpu_bloom *bitmap;
	struct flow_key *flow;
	__u32 zero = 0, h1, h2;
	__u32 idx = ctrl->start + iter;

	if (idx >= FLOW_COUNT)
		return 1;

	flow = bpf_map_lookup_elem(&flow_array, &idx);
	if (!flow)
		return 0;

	bitmap = bpf_map_lookup_elem(&percpu_bloom, &zero);
	if (!bitmap) {
		stat_inc(STAT_PUSH_ERR);
		return 0;
	}

	flow_hash_pair(flow, &h1, &h2);
	percpu_set_k_bits(bitmap, h1, h2);
	stat_inc(STAT_PUSH_OK);
	return 0;
}

static long push_flow_percpu_iter_nostats(__u32 iter, struct loop_ctx *loop_ctx)
{
	const struct bench_ctrl *ctrl = loop_ctx->ctrl;
	struct percpu_bloom *bitmap;
	struct flow_key *flow;
	__u32 zero = 0, h1, h2;
	__u32 idx = ctrl->start + iter;

	if (idx >= FLOW_COUNT)
		return 1;

	flow = bpf_map_lookup_elem(&flow_array, &idx);
	if (!flow)
		return 0;

	bitmap = bpf_map_lookup_elem(&percpu_bloom, &zero);
	if (!bitmap)
		return 0;

	flow_hash_pair(flow, &h1, &h2);
	percpu_set_k_bits(bitmap, h1, h2);
	return 0;
}

static long lookup_flow_shared_iter(__u32 iter, struct loop_ctx *loop_ctx)
{
	const struct bench_ctrl *ctrl = loop_ctx->ctrl;
	struct flow_key *flow;
	__u32 idx = ctrl->start + iter;

	if (idx >= FLOW_COUNT)
		return 1;

	flow = bpf_map_lookup_elem(&flow_array, &idx);
	if (!flow)
		return 0;

	if (bpf_map_peek_elem(&bloom_map, flow) == 0)
		stat_inc(STAT_LOOKUP_HIT);
	else
		stat_inc(STAT_LOOKUP_MISS);
	return 0;
}

static long lookup_flow_percpu_iter(__u32 iter, struct loop_ctx *loop_ctx)
{
	const struct bench_ctrl *ctrl = loop_ctx->ctrl;
	struct flow_key *flow;
	__u32 meta_key = 0, h1, h2, nr_shards;
	__u32 *nr_ptr;
	__u32 idx = ctrl->start + iter;

	if (idx >= FLOW_COUNT)
		return 1;

	flow = bpf_map_lookup_elem(&flow_array, &idx);
	if (!flow)
		return 0;

	nr_ptr = bpf_map_lookup_elem(&lookup_meta, &meta_key);
	if (!nr_ptr || *nr_ptr == 0) {
		stat_inc(STAT_LOOKUP_MISS);
		return 0;
	}
	nr_shards = *nr_ptr;

	flow_hash_pair(flow, &h1, &h2);
	if (percpu_bloom_lookup(nr_shards, h1, h2))
		stat_inc(STAT_LOOKUP_HIT);
	else
		stat_inc(STAT_LOOKUP_MISS);
	return 0;
}

static __always_inline int run_insert_mc(struct xdp_md *ctx,
					 long (*cb)(__u32, struct loop_ctx *))
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u8 *slot_ptr;
	__u32 slot;
	struct bench_ctrl *ctrl;
	struct loop_ctx loop_ctx;

	if (data + sizeof(struct ethhdr) + 1 > data_end)
		return XDP_ABORTED;

	slot_ptr = data + sizeof(struct ethhdr);
	slot = *slot_ptr;
	if (slot >= MAX_THREADS)
		return XDP_ABORTED;

	ctrl = bpf_map_lookup_elem(&ctrl_array, &slot);
	if (!ctrl)
		return XDP_ABORTED;

	loop_ctx.ctrl = ctrl;
	bpf_loop(ctrl->count, cb, &loop_ctx, 0);
	return XDP_PASS;
}

SEC("xdp")
int bloom_insert_mc(struct xdp_md *ctx)
{
	return run_insert_mc(ctx, push_flow_shared_iter);
}

SEC("xdp")
int bloom_insert_mc_nostats(struct xdp_md *ctx)
{
	return run_insert_mc(ctx, push_flow_shared_iter_nostats);
}

SEC("xdp")
int bloom_insert_mc_percpu(struct xdp_md *ctx)
{
	return run_insert_mc(ctx, push_flow_percpu_iter);
}

SEC("xdp")
int bloom_insert_mc_percpu_nostats(struct xdp_md *ctx)
{
	return run_insert_mc(ctx, push_flow_percpu_iter_nostats);
}

SEC("xdp")
int bloom_lookup_mc(struct xdp_md *ctx)
{
	return run_insert_mc(ctx, lookup_flow_shared_iter);
}

SEC("xdp")
int bloom_lookup_mc_percpu(struct xdp_md *ctx)
{
	return run_insert_mc(ctx, lookup_flow_percpu_iter);
}
