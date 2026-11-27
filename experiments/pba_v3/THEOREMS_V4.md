# PBA/3 定理草稿（A + B 路线）

状态：**草稿**。每条声称的可信度按其当前证明完成度标注。
所有编号与论文 §5 对应，数值证据来自 `results/a_core.json` 与 `results/b_segment.json`。

---

## 符号

- $K$：名单槽位数；$b$：单轮记录级抽查预算；$S$：分段数；$m$：被污染段数；$\rho=m/S$。
- $q_i$：审计者给槽位 $i$ 的风险分；$\pi$：服务器策略。
- $o_t \in \{\text{PASS},\text{FAIL},\text{INCONCLUSIVE}\}$：第 $t$ 轮验证输出。
- $\mathrm{TDR}$：被攻击轮中被抽中且返回 FAIL 的比例。
- $\mathrm{Inc}$：返回 `INCONCLUSIVE` 的审计调用数。

---

## Theorem A1（可得性反馈的可操纵性）

**陈述.** 设调度器 $\sigma$ 的权重满足 $q_i \leftarrow q_i + \alpha_f\mathbf{1}[o=\text{FAIL}] + \alpha_a\mathbf{1}[o=\text{INCONCLUSIVE}]$ 且 $\alpha_a>0$。存在一个服务器策略 $\pi^\ast$ 只使用历史可观察结果，使得在恒定目标 workload 下

$$\mathbb{E}[\mathrm{Inc}(\sigma,\pi^\ast)] \;\ge\; \mathbb{E}[\mathrm{Inc}(\text{uniform},\pi^\ast)] \cdot \frac{1}{f_{\text{hom}}}$$

其中 $f_{\text{hom}}$ 是均匀采样命中被扣证集合的概率，且

$$\mathrm{TDR}(\sigma,\pi^\ast) = \mathrm{TDR}(\text{uniform},\pi^\ast) = 0 .$$

**证明概要.** $\pi^\ast$ 固定目标集合 $T$，对 $i\in T$ 的每次证据请求返回不可得。由于 $\sigma$ 在观察到 `INCONCLUSIVE` 后提高 $q_i$，$T$ 中槽位的权重单调不减，故 $\Pr[\text{抽中}T]$ 单调不减并在若干轮后超过均匀采样的期望，进而 $\mathbb{E}[\mathrm{Inc}]$ 被放大。由于扣证回合不产生 FAIL，两个调度器的 $\mathrm{TDR}$ 同为 0。$\square$

**证据.** `a_core.json`：withholding workload，adaptive $\mathrm{Inc}\approx47$ vs uniform $\approx11$（$b=3$, $K=30$）。

**限制.** 该定理只覆盖"返回不可得"的对手。对"返回伪造失败"的对手需另立命题；对"随机化位置"的对手（random workload）增益消失，本定理不适用。

---

## Theorem A2（封存抽样与语义修复的作用范围）

**陈述.** 设 $\sigma_{\text{seal}}$ 用 $H(\text{bulletin},\text{round},\text{beacon})$ 固定挑战集，但保留 $\alpha_a>0$；设 $\sigma_{\text{navail}}$ 同时设 $\alpha_a=0$。则

1. $\mathrm{Inc}(\sigma_{\text{seal}},\pi^\ast) = \mathrm{Inc}(\sigma,\pi^\ast) + o(1)$：**仅封存不能缓解**；
2. $\mathrm{Inc}(\sigma_{\text{navail}},\pi^\ast) \le \mathrm{Inc}(\text{uniform},\pi^\ast) + o(1)$：**只有语义修复有效**。

**证明概要.** (1) 封存只决定"抽谁"，不改变"抽到后如何更新分数"。$\pi^\ast$ 的扣证与挑战集的不可预测性无关，因为在 $\sigma_{\text{seal}}$ 中 $q_i$ 仍随 `INCONCLUSIVE` 增长，注意力仍被拉向 $T$，故 $\mathrm{Inc}$ 不降。(2) 若 $\alpha_a=0$，$q_i$ 只在观察到 FAIL 时变化；扣证不改变任何权重，故选择分布与 uniform 在期望上一致，$\mathrm{Inc}$ 回到基线。$\square$

**证据（关键阴性结果）.** withholding workload：

| schedule | coverage | Inc |
|---|---|---|
| adaptive | 0.908 | 48.12 |
| sealed_adaptive | 0.922 | 48.88 |
| sealed_navail | 0.198 | 10.50 |
| uniform | 0.215 | 11.38 |

**论文表述要求.** 必须明确写"封存无效"，否则会被误读为"我们提供了封存机制"。这是本稿最有价值的反直觉结论。

---

## Theorem A3（分段和审计的漏检界）

**陈述.** 设服务器对 $S$ 段中的 $m$ 段发布了错误的段和，且每段内所有记录的贡献证明均正确。审计者无放回抽 $b$ 段并逐段重算，则

$$P_{\text{miss}} = \frac{\binom{S-m}{b}}{\binom{S}{b}} \le (1-\rho)^b,\qquad \rho=m/S .$$

**证明.** 漏检当且仅当抽中集合与 $m$ 个被污染段不交，计数即得；上界由 $\binom{S-m}{b}/\binom{S}{b}=\prod_{j=0}^{b-1}\frac{S-m-j}{S-j}\le(1-\rho)^b$ 得到。$\square$

**备注（必须写进论文）.** $\rho\to1$ 时界退化为平凡界 $1$。**这正是必须保留全量重放档的理由**：分段档只能抓住"局部化"的错误，均摊型伪造需要读全部记录才能反驳。把这一点写成 Remark，主动回应"为什么还要第四档"。

---

## Theorem A4（三档可判定事件严格分离）

**陈述.** 记 $\mathcal{E}_{\text{rec}}$、$\mathcal{E}_{\text{seg}}$、$\mathcal{E}_{\text{full}}$ 分别为三档能判定的不一致事件集合，则

$$\mathcal{E}_{\text{rec}} \subsetneq \mathcal{E}_{\text{seg}} \subsetneq \mathcal{E}_{\text{full}} .$$

**证明概要.** 包含关系：record 档只读被抽中记录的局部证据，任何在该读集之外的不一致都不可判定；segment 档的重算依赖全部记录的贡献，故能反驳 record 档看不到的段和错误；full 档读全部更新并重放，能反驳不改变段和但改变结果的伪造（例如把结果字节整体替换并重新签署段和）。严格性由构造给出：段和错误不被 record 档看到（`a_core` 中 forged-result 情形），均摊型结果伪造不被 segment 档看到（`b_segment` 中 $\rho=1$ 情形）。$\square$

---

## 待办

- [ ] A1 的形式化：需要定义"未观察槽位的权重不增长"并写成引理，目前只有直观论证。
- [ ] A3 的实验验证：`b_segment.json` 需确认每个格满足 `miss_empirical ≤ miss_bound + 0.01`。
- [ ] A4 的严格性构造：需要在 `b_segment` 里显式准备一个"段和正确但结果错误"的 fixture。

---

## 实证校验记录（2026-10-21）

### B 组判据修正

初版判据是 `miss_empirical <= (1-rho)^b`，200 seed 下 27 格中有 5 格"超界"。这是**判据错误，不是实现错误**：$(1-\rho)^b$ 是松上界，正确的零假设是精确超几何 $\binom{S-m}{b}/\binom{S}{b}$。按精确值做 $z$ 检验后，27 格中**没有一格超过 3 个标准差**（最大 $|z|=1.86$）。

论文里应写：实测漏检率与精确超几何一致（27/27 格内 $|z|<2$），并同时给出松上界作为设计用的解析界。

### A 组关键数字（40 seed，b=3，K=30）

| 情形 | coverage | Inc | TDR |
|---|---|---|---|
| adaptive / withholding | 0.925 | 49.02±0.73 | 0 |
| sealed_adaptive / withholding | 0.884 | 46.85±1.62 | 0 |
| sealed_navail / withholding | 0.179 | 9.50±0.95 | 0 |
| uniform / withholding | 0.204 | 10.80±1.07 | 0 |
| adaptive / persistent | 0.940 | 0 | 0.940±0.014 |
| uniform / persistent | 0.204 | 0 | 0.204±0.020 |
| adaptive / copycat | 0.857 | 0 | 0.857±0.041 |
| uniform / copycat | 0.101 | 0 | 0.101±0.013 |

结论：A1 成立（可得性反馈被放大 4.5 倍，TDR 恒为 0）；A2 成立且方向反直觉（封存无效，语义修复有效）；copycat 未能击破自适应调度，因此 A1 的表述必须限定在"可得性攻击"这一类对手上。
