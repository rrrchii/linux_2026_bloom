# linux_2026_bloom

多核 Bloom Filter 實驗：比較 **shared bitmap** 與 **per-CPU bitmap** 在 **LKM** 與 **eBPF** 路徑上的 insert / lookup 效能。

## 目錄

| 路徑 | 內容 |
|------|------|
| `lkm/` | Kernel module 實驗（build profile、多核 insert/lookup、ftrace） |
| `ebpf/` | eBPF 實驗（官方 `BPF_MAP_TYPE_BLOOM_FILTER` vs `PERCPU_ARRAY`） |
| `BLOOM_BASELINE.md` | 基線與參數說明 |
| `lkm_ftrace.md` | LKM ftrace 筆記 |

實驗報告與原始 log（`REPORT.md`、insert / perf cache / hotspot）放在 HackMD，本 repo 不追蹤。

## 實驗重點

在 **6C12T（i7-10750H）** 上驗證 insert / lookup **取捨反轉**：

- **insert 為主** → **per-CPU**（避開 shared bitmap 競爭）
- **lookup 為主（≥4 thread）** → **shared**（只讀一份 Bloom 能 scale）

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

## 依賴

- Linux kernel headers（LKM）
- `clang`、`llvm-strip`、`libbpf`（eBPF）
- `perf`（cache / hotspot）
