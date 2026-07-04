# linux_2026_bloom

多核 Bloom Filter 實驗：比較 **shared bitmap** 與 **per-CPU bitmap** 在 **LKM** 與 **eBPF** 路徑上的 insert / lookup 效能。

## 目錄

| 路徑 | 內容 |
|------|------|
| `lkm/` | Kernel module 實驗（build profile、多核 insert/lookup、ftrace） |
| `ebpf/` | eBPF 實驗（ `BPF_MAP_TYPE_BLOOM_FILTER` vs `PERCPU_ARRAY`） |

## 快速重跑

### LKM

```bash
cd lkm
make
# 見各 run_*.sh；報告與數據在 HackMD
```

### eBPF

```bash
cd ebpf
make

# Insert / Lookup（預設 repeat 50）
sudo ./run_ebpf_kern_mc.sh
sudo ./run_ebpf_kern_mc.sh --mode percpu
sudo ./run_ebpf_lookup_mc.sh
sudo ./run_ebpf_lookup_mc.sh --mode percpu

# perf cache / hotspot
sudo ./run_perf_cache.sh
sudo MODE=percpu ./run_perf_cache.sh
sudo ./run_perf_hotspot.sh
sudo ./run_perf_hotspot_r1.sh
```