#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bitops.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/in.h>
#include <linux/uaccess.h>
#include <linux/jhash.h>

#define BLOOM_BITS	131072
#define BLOOM_BITS_MASK	(BLOOM_BITS - 1)
#define BLOOM_WORDS	(BLOOM_BITS / BITS_PER_LONG)
#define BLOOM_K		10
#define FLOW_COUNT	10000

struct flow_key {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_port;
	__be16 dst_port;
	u8 protocol;
} __packed;

static unsigned long bloom[BLOOM_WORDS];
static struct proc_dir_entry *bloom_proc_dir;

#define JHASH_INITVAL_H1	0xbc9f1d34
#define JHASH_INITVAL_H2	0x7f4a7c15

static u32 bloom_hash_pair(const struct flow_key *flow, u32 *h2_out)
{
	u32 h1 = jhash(flow, sizeof(*flow), JHASH_INITVAL_H1) & BLOOM_BITS_MASK;
	u32 h2 = jhash(flow, sizeof(*flow), JHASH_INITVAL_H2) & BLOOM_BITS_MASK;

	/* m is power-of-two; odd h2 gives full probe coverage with double hashing */
	h2 |= 1;
	if (h2 >= BLOOM_BITS)
		h2 = 1;

	*h2_out = h2;
	return h1;
}

static noinline void bloom_insert_flow(const struct flow_key *flow)
{
	u32 h1, h2;
	int i;

	h1 = bloom_hash_pair(flow, &h2);
	for (i = 0; i < BLOOM_K; i++) {
		u32 pos = (h1 + i * h2) & BLOOM_BITS_MASK;

		set_bit(pos, bloom);
	}
}

static noinline bool bloom_lookup_flow(const struct flow_key *flow)
{
	u32 h1, h2;
	int i;

	h1 = bloom_hash_pair(flow, &h2);
	for (i = 0; i < BLOOM_K; i++) {
		u32 pos = (h1 + i * h2) & BLOOM_BITS_MASK;

		if (!test_bit(pos, bloom))
			return false;
	}
	return true;
}

static void flow_generate_inserted(struct flow_key *flow, int idx)
{
	flow->src_ip = cpu_to_be32(0x0a000000 + (idx & 0xff));
	flow->dst_ip = cpu_to_be32(0xc0a80000 + ((idx >> 8) & 0xff));
	flow->src_port = cpu_to_be16(1024 + (idx % 60000));
	flow->dst_port = cpu_to_be16(80 + (idx % 1000));
	flow->protocol = (idx & 1) ? IPPROTO_TCP : IPPROTO_UDP;
}

static void flow_generate_negative(struct flow_key *flow, int idx)
{
	flow->src_ip = cpu_to_be32(0xac100000 + (idx & 0xff));
	flow->dst_ip = cpu_to_be32(0x64400000 + ((idx >> 8) & 0xff));
	flow->src_port = cpu_to_be16(20000 + (idx % 40000));
	flow->dst_port = cpu_to_be16(443 + (idx % 1000));
	flow->protocol = (idx & 1) ? IPPROTO_UDP : IPPROTO_TCP;
}

noinline s64 bloom_insert_test(const struct flow_key *flows, int n);
noinline s64 bloom_positive_lookup_test(const struct flow_key *flows, int n,
					int *hit_out);
noinline s64 bloom_negative_lookup_test(const struct flow_key *flows, int n,
					int *fp_out);

noinline s64 bloom_insert_test(const struct flow_key *flows, int n)
{
	ktime_t start, end;
	int i;

	start = ktime_get();
	for (i = 0; i < n; i++)
		bloom_insert_flow(&flows[i]);
	end = ktime_get();

	return ktime_to_ns(ktime_sub(end, start));
}

noinline s64 bloom_positive_lookup_test(const struct flow_key *flows,
					       int n, int *hit_out)
{
	ktime_t start, end;
	int i, hit = 0;

	start = ktime_get();
	for (i = 0; i < n; i++) {
		if (bloom_lookup_flow(&flows[i]))
			hit++;
	}
	end = ktime_get();

	*hit_out = hit;
	return ktime_to_ns(ktime_sub(end, start));
}

noinline s64 bloom_negative_lookup_test(const struct flow_key *flows,
					       int n, int *fp_out)
{
	ktime_t start, end;
	int i, fp = 0;

	start = ktime_get();
	for (i = 0; i < n; i++) {
		if (bloom_lookup_flow(&flows[i]))
			fp++;
	}
	end = ktime_get();

	*fp_out = fp;
	return ktime_to_ns(ktime_sub(end, start));
}

static void bloom_run_flow_experiment(void)
{
	struct flow_key *inserted_flows, *negative_flows;
	s64 insert_ns, pos_lookup_ns, neg_lookup_ns;
	int i, hit, fp_count;
	u32 fp_rate_x100;

	inserted_flows = kmalloc_array(FLOW_COUNT, sizeof(*inserted_flows),
				       GFP_KERNEL);
	negative_flows = kmalloc_array(FLOW_COUNT, sizeof(*negative_flows),
				       GFP_KERNEL);
	if (!inserted_flows || !negative_flows) {
		pr_err("bloom_lkm: failed to allocate flow arrays\n");
		kfree(inserted_flows);
		kfree(negative_flows);
		return;
	}

	for (i = 0; i < FLOW_COUNT; i++)
		flow_generate_inserted(&inserted_flows[i], i);
	for (i = 0; i < FLOW_COUNT; i++)
		flow_generate_negative(&negative_flows[i], i);

	bitmap_zero(bloom, BLOOM_BITS);

	pr_info("=== Bloom Filter for Network Flow Membership Test ===\n");
	pr_info("flow key: src_ip + dst_ip + src_port + dst_port + protocol\n");
	pr_info("hash: jhash (Bob Jenkins, linux/jhash.h) + double hashing\n");
	pr_info("m=%d bits, k=%d, n=%d flows\n", BLOOM_BITS, BLOOM_K, FLOW_COUNT);

	insert_ns = bloom_insert_test(inserted_flows, FLOW_COUNT);
	pos_lookup_ns = bloom_positive_lookup_test(inserted_flows, FLOW_COUNT, &hit);
	neg_lookup_ns = bloom_negative_lookup_test(negative_flows, FLOW_COUNT, &fp_count);

	fp_rate_x100 = div64_u64((u64)fp_count * 10000, FLOW_COUNT);

	pr_info("Insert total time: %lld ns\n", insert_ns);
	pr_info("Positive lookup total time: %lld ns (hit %d / %d)\n",
		pos_lookup_ns, hit, FLOW_COUNT);
	pr_info("Negative lookup total time: %lld ns\n", neg_lookup_ns);
	pr_info("False positive count: %d\n", fp_count);
	pr_info("False positive rate: %d / %d (%u.%02u%%)\n",
		fp_count, FLOW_COUNT,
		fp_rate_x100 / 100, fp_rate_x100 % 100);

	kfree(inserted_flows);
	kfree(negative_flows);
}

static ssize_t bloom_proc_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	bloom_run_flow_experiment();
	return count;
}

static const struct proc_ops bloom_proc_ops = {
	.proc_write = bloom_proc_write,
};

static int __init bloom_init(void)
{
	bloom_proc_dir = proc_mkdir("bloom_experiment", NULL);
	if (!bloom_proc_dir) {
		pr_err("bloom_lkm: failed to create /proc/bloom_experiment\n");
		return -ENOMEM;
	}

	if (!proc_create("run", 0200, bloom_proc_dir, &bloom_proc_ops)) {
		proc_remove(bloom_proc_dir);
		pr_err("bloom_lkm: failed to create /proc/bloom_experiment/run\n");
		return -ENOMEM;
	}

	pr_info("bloom_lkm loaded (m=%d, k=%d)\n", BLOOM_BITS, BLOOM_K);
	pr_info("trigger experiment: echo 1 > /proc/bloom_experiment/run\n");
	return 0;
}

static void __exit bloom_exit(void)
{
	proc_remove(bloom_proc_dir);
	pr_info("bloom_lkm unloaded\n");
}

module_init(bloom_init);
module_exit(bloom_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bloom filter network flow membership experiment");
