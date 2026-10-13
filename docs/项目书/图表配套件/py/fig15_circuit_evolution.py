# -*- coding: utf-8 -*-
"""图 15：匿名准入电路规模演进图（Python 数据图，300dpi PNG）。
数据源：docs/性能档案.md 总表:28（各代电路普查实测值）。
正文图表位：2.3 节【图 15：电路规模演进图】。
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams["font.sans-serif"] = ["SimHei", "Microsoft YaHei"]
plt.rcParams["axes.unicode_minus"] = False

# 各代电路普查实测值（性能档案.md:28 演进链）
versions = ["v1 初版", "v2 查表化", "v3 通道合并", "v4 约束重整", "v5 列共享前", "v6 SN 绑定", "v7 列共享（现行）"]
constraints = [104287, 44383, 38200, 20102, 19578, 19608, 19434]

fig, ax = plt.subplots(figsize=(10, 5.5))

x = np.arange(len(versions))
bars = ax.bar(x, constraints, width=0.55, color=["#4472C4"] * 6 + ["#ED7D31"], edgecolor="white", linewidth=0.8)

# 逐柱标注
for i, (xi, v) in enumerate(zip(x, constraints)):
    ax.text(xi, v + 1800, f"{v:,}", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#333333")

ax.set_xticks(x)
ax.set_xticklabels(versions, fontsize=9, rotation=14, ha="right")
ax.set_ylabel("约束条数", fontsize=11)
ax.set_title("匿名准入电路规模演进（各代电路普查实测值）", fontsize=13, fontweight="bold", pad=14)
ax.set_ylim(0, 120000)
ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{int(v/1000)}k" if v >= 1000 else str(int(v))))
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
ax.grid(axis="y", alpha=0.3, linestyle="--")

# 演进标注
ax.annotate("查表化", xy=(1, 44383), xytext=(1, 55000), ha="center", fontsize=8, color="#666666",
            arrowprops=dict(arrowstyle="->", color="#999999", lw=0.8))
ax.annotate("列共享", xy=(6, 19434), xytext=(5.4, 45000), ha="center", fontsize=8, color="#666666",
            arrowprops=dict(arrowstyle="->", color="#999999", lw=0.8))

fig.tight_layout()
out = "../png/图15_电路规模演进图.png"
fig.savefig(out, dpi=300, bbox_inches="tight", facecolor="white")
print("saved:", out)
plt.close(fig)
