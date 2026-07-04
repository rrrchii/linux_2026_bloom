# Bloom Filter Baseline — 驗證理論與實際

參考：[學長專題 — Bloom 配置](https://hackmd.io/3xHrIKPUTfmHkERXCa50Xw?both#5-%E5%AF%A6%E5%8B%99%E8%A8%AD%E8%A8%88-Bloom-filter-%E9%85%8D%E7%BD%AE)

## 理論

最佳雜湊函式數：$k^* = \frac{m}{n}\ln 2$

- $m$：bitmap 大小 · $n$：元素數 · $k$：雜湊函式數（jhash）

## 設定

模擬 kernel Network Flow：flow key = 五元組（`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`）。

| 參數 | 值 |
|------|-----|
| n | 10000 |
| m | 131072 bits（16 KB） |
| k（測試組） | 8、9、10 |
| lookup | positive / negative 各 10000 |

$k^* \approx \frac{131072}{10000} \times 0.693 \approx 9.08$ → 取 **k = 8, 9, 10** 比較。

## 結果

| k | Insert (ns) | Pos lookup (ns) | Neg lookup (ns) | FPR |
|--:|------------:|----------------:|----------------:|----:|
| 8 | 3,609,772 | 3,519,313 | 3,613,646 | 0.18% |
| 9 | 4,049,075 | 3,820,909 | 3,695,884 | **0.17%** |
| 10 | 4,429,637 | 4,001,472 | 3,846,868 | 0.19% |

理論 FPR（k=9）：$p \approx (1-e^{-kn/m})^k$，$kn/m \approx 0.687$ → **≈ 0.16%**；實測 **0.17%**（誤差約 0.01 個百分點）。

## 結論

- **k = 9** FPR 最低，與 $k^* \approx 9.08$ 一致 → 後續實驗 baseline（$m=131072, n=10000$）。
- Insert / lookup 隨 k 上升（$\propto k$），屬預期行為。

---

*LKM 操作：`lkm_ftrace.md` · 多核 eBPF：`ebpf/REPORT.md`*
