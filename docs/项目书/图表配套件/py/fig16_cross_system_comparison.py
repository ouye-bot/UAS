# -*- coding: utf-8 -*-
"""图 16：同语句跨系统对比图（Python 数据图，300dpi PNG，对数轴逐柱标注）。
数据源：性能档案.md 总表:28（本系统）＋ plonky2-bench/REPORT-plonky2-auth.md:50-51/61-63（Plonky2 实测）。
正文图表位：2.3 节【图 16：同语句跨系统对比图】。
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.sans-serif"] = ["SimHei", "Microsoft YaHei"]
plt.rcParams["axes.unicode_minus"] = False

labels = ["电路规模\n（约束 / 域行）", "证明生成\n（秒）", "证明验证\n（秒）", "证明大小\n（字节）"]
ours = [19434, 14.514, 0.531, 16063712]
plonky2 = [524288, 73.089, 0.008, 269640]
ours_labels = ["19,434 条约束", "14.514 秒", "0.531 秒", "16,063,712 字节"]
plonky2_labels = ["524,288 个域行", "73.089 秒", "0.008 秒", "269,640 字节"]
units = ["约束 / 域行（非同单位）", "秒", "秒", "字节"]

fig, axes = plt.subplots(1, 4, figsize=(16, 5))
colors = {"ours": "#4472C4", "plonky2": "#ED7D31"}
titles = ["电路规模", "证明生成时延", "证明验证时延", "证明大小"]

for i, ax in enumerate(axes):
    o = ours[i]
    p = plonky2[i]
    bars = ax.bar([0, 1], [o, p], width=0.5, color=[colors["ours"], colors["plonky2"]], edgecolor="white")
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["本系统\n（透明设置）", "Plonky2\n（通用门约束）"], fontsize=9)
    ax.set_title(titles[i], fontsize=11, fontweight="bold")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    # 逐柱标注
    for bar, val in zip(bars, [o, p]):
        fmt = f"{val:,.0f}" if val >= 1 else f"{val:.3f}"
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.02, fmt,
                ha="center", va="bottom", fontsize=9, fontweight="bold")
    if i == 0:
        ax.set_ylabel(units[i], fontsize=9)
        ax.set_yscale("log")
        ax.set_ylim(1000, 2000000)
    elif i == 1:
        ax.set_ylabel("秒", fontsize=9)
        ax.set_ylim(0, 85)
    elif i == 2:
        ax.set_ylim(0, 0.7)
    elif i == 3:
        ax.set_ylabel("字节", fontsize=9)
        ax.set_ylim(0, 20000000)

fig.suptitle("同语句跨系统实测对比（本系统透明设置 vs Plonky2 通用门约束）\n约束数与域行数计量口径不同；公开输入域宽不同不可直接比；时延对比为能效参考",
             fontsize=12, fontweight="bold", y=1.02)
fig.tight_layout()
out = "../png/图16_同语句跨系统对比图.png"
fig.savefig(out, dpi=300, bbox_inches="tight", facecolor="white")
print("saved:", out)
plt.close(fig)
