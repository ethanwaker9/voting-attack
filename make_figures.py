import json
import os
import subprocess
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "final_paper", "figures")
os.makedirs(OUT, exist_ok=True)

plt.rcParams.update({
    "font.size": 8,
    "axes.labelsize": 8,
    "legend.fontsize": 7,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7,
    "axes.linewidth": 0.6,
    "lines.linewidth": 1.1,
    "figure.dpi": 200,
})


def save(fig, name):
    eps = os.path.join(OUT, name + ".eps")
    pdf = os.path.join(OUT, name + ".pdf")
    fig.savefig(eps, format="eps", bbox_inches="tight", pad_inches=0.02)
    subprocess.run(["epstopdf", eps, "--outfile=" + pdf], check=True)
    plt.close(fig)
    print("wrote", pdf)


def fig_leak(plots, results):
    d = plots["A2_hist"]
    real = np.array(d["real"])
    sim = np.array(d["sim"])
    fig, ax = plt.subplots(figsize=(3.35, 2.05))
    bins = np.linspace(0, 1.0593, 44)
    ax.hist(sim, bins=bins, histtype="step", color="#4c78a8", lw=1.2,
            label="simulated branch")
    ax.hist(real, bins=bins, histtype="step", color="#e45756", lw=1.2,
            label="real branch")
    ymax = 90
    ax.axvline(1.0, color="black", ls="--", lw=0.8)
    ax.fill_between([1.0, 1.0593], 0, ymax, color="#f2c14e", zorder=0)
    ax.annotate("only real branches\ncan land here\n(reveals the vote)",
                xy=(1.03, 55), xytext=(0.60, 74), fontsize=6.2,
                arrowprops=dict(arrowstyle="->", lw=0.6), ha="center")
    ax.set_xlabel(r"branch sub-challenge $c_j / 2^{255}$")
    ax.set_ylabel("count")
    ax.set_xlim(0, 1.0593)
    ax.set_ylim(0, ymax)
    ax.legend(loc="lower center", frameon=False, handlelength=1.6, ncol=2,
              bbox_to_anchor=(0.5, -0.02))
    save(fig, "fig_leak")


def fig_subgroup(plots, results):
    cum = plots["A3_recovery"]["cum"]
    qbits = plots["A3_recovery"]["q_bits"]
    n = [c[0] for c in cum]
    bits = [c[1] for c in cum]
    tms = [c[2] for c in cum]
    fig, ax = plt.subplots(figsize=(3.35, 2.05))
    ax.plot(n, bits, "o-", color="#4c78a8", ms=3.2, label="key bits recovered")
    ax.axhline(qbits, color="black", ls="--", lw=0.8)
    ax.text(n[1], qbits + 0.8, r"$\log_2 q=%d$ (full key)" % qbits, fontsize=6.4)
    ax.set_xlabel("confinement queries (small prime powers used)")
    ax.set_ylabel("key bits recovered", color="#4c78a8")
    ax.tick_params(axis="y", colors="#4c78a8")
    ax2 = ax.twinx()
    ax2.plot(n, tms, "s-", color="#e45756", ms=3.0, label="cumulative time")
    ax2.set_ylabel("cumulative time (ms)", color="#e45756")
    ax2.tick_params(axis="y", colors="#e45756")
    save(fig, "fig_subgroup")


def fig_cost(plots, results):
    v = plots["board_cost"]["verify"]
    c1 = plots["board_cost"]["construct_one_ms"]
    ns = [x[0] for x in v]
    ver = [x[1] for x in v]
    fig, ax = plt.subplots(figsize=(3.35, 2.05))
    ax.plot(ns, ver, "o-", color="#4c78a8", ms=3.2, label="honest board verification")
    ax.plot(ns, [c1] * len(ns), "s--", color="#e45756", ms=3.0,
            label="adversary ballot construction")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log")
    ax.set_xlabel("number of ballots on the board")
    ax.set_ylabel("wall-clock time (ms)")
    ax.legend(loc="upper left", frameon=False, handlelength=1.6)
    save(fig, "fig_cost")


def main():
    results = json.load(open(os.path.join(HERE, "results", "results.json")))
    plots = json.load(open(os.path.join(HERE, "results", "plotdata.json")))
    fig_leak(plots, results)
    fig_subgroup(plots, results)
    fig_cost(plots, results)


if __name__ == "__main__":
    main()
