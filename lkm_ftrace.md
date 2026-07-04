# LKM + ftrace 流程

```bash
# 1. 編譯
cd ~/linux_2026_bloom && make    # 產生 bloom_lkm.ko

# 2. 若已載入先卸載
lsmod | grep bloom && sudo rmmod bloom_lkm

# 3. 設定 ftrace
cd /sys/kernel/tracing
echo 16384 | sudo tee buffer_size_kb
echo 0 | sudo tee tracing_on
echo function_graph | sudo tee current_tracer
sudo sh -c 'echo > trace; echo > set_graph_function'
echo 1 | sudo tee tracing_on

# 4. 載入 module 觸發測試
cd ~/linux_2026_bloom && sudo insmod bloom_lkm.ko

# 5. 關閉並查看（有 bloom 函式與耗時即成功）
echo 0 | sudo tee /sys/kernel/tracing/tracing_on
sudo cat /sys/kernel/tracing/trace | grep bloom
sudo rmmod bloom_lkm
```
