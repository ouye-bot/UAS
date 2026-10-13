# -*- coding: utf-8 -*-
"""图 18：性能实测图（Python 数据图，300dpi PNG，承诺线对照）。
数据源：性能档案.md 总表:30/31/35（服务器窗三次取中位＋本机串行实测）。
正文图表位：3.3 节【图 18：性能对比图】。
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.sans-serif"] = ["SimHei", "Microsoft YaHei"]
plt.rcParams["axes.unicode_minus"] = False

# 数据
metrics = ["匿名准入\n证明生成", "匿名准入\n证明验证", "轨迹合规证书\n证明生成"]
measured = [14.514, 0.531, 4.175]
promises = [30, 5, 20]
colors = ["#4472C4", "#4472C4", "#4472C4"]
promise_colors = ["#ED7D31", "#ED7D31", "#ED7D31"]

fig, ax = plt.subplots(figsize=(9, 5.5))
x = np.arange(len(metrics))
w = 0.35

bars1 = ax.bar(x - w / 2, measured, w, label="实测值", color=colors, edgecolor="white")
bars2 = ax.bar(x + w / 2, promises, w, label="设计承诺", color=promise_colors, edgecolor="white", alpha=0.5)

# 逐柱标注
for i, (m, p) in enumerate(zip(measured, promises)):
    ax.text(x[i] - w / 2, m + 0.3, f"{m:.3f} 秒", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#333333")
    ax.text(x[i] + w / 2, p + 0.3, f"{p} 秒", ha="center", va="bottom", fontsize=9, color="#999999")

ax.set_xticks(x)
ax.set_xticklabels(metrics, fontsize=10)
ax.set_ylabel("耗时（秒）", fontsize=11)
ax.set_title("证明性能实测与设计承诺对照（云端服务器三次取中位）", fontsize=13, fontweight="bold", pad=14)
ax.legend(fontsize=10, loc="upper right")
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.grid(axis="y", alpha=0.3, linestyle="--")
ax.set_ylim(0, 36)

fig.tight_layout()
out = "../png/图18_性能对比图.png"
fig.savefig(out, dpi=300, bbox_inches="tight", facecolor="white")
print("saved:", out)
plt.close(fig)
