"""
Publication-Quality Plot and Figure Generator.
Spec Reference: §5, §8, §9 Reproducibility Package.

Generates:
Figure 1: The Pareto Frontier Plot (Attacker Cost Amplification vs Legitimate User Tax).
"""

import os
import json
from typing import Dict, Any, List
import matplotlib.pyplot as plt
import numpy as np


class FigureGenerator:
    """Generates all publication-ready figures from raw experimental logs."""

    def __init__(self, raw_logs_dir: str = "results/raw_logs", figures_dir: str = "results/figures"):
        self.raw_logs_dir = raw_logs_dir
        self.figures_dir = figures_dir
        os.makedirs(figures_dir, exist_ok=True)

    def generate_frontier_plot(
        self,
        frontier_data: Dict[str, Any],
        output_file: str = "fig1_pareto_frontier.png"
    ) -> str:
        """
        Plot Attacker Cost Amplification (ACA) against Legitimate User Tax (LUT p95, low-end phone).
        Both axes on log scale with 95% bootstrap confidence intervals.
        """
        plt.figure(figsize=(11, 7))

        names = list(frontier_data.keys())
        acas = [frontier_data[k]["aca"] for k in names]
        luts = [max(frontier_data[k]["lut_low_p95_ms"], 0.001) for k in names]  # clip for log scale
        types = [frontier_data[k]["type"] for k in names]
        markers = [frontier_data[k].get("marker", "o") for k in names]
        colors = [frontier_data[k].get("color", "blue") for k in names]

        # Scatter points with error bars
        for i, name in enumerate(names):
            aca_ci = frontier_data[name]["aca_ci"]
            lut_ci = frontier_data[name]["lut_ci"]

            y_lower = max(0.0, acas[i] - aca_ci[0])
            y_upper = max(0.0, aca_ci[1] - acas[i])
            x_lower = max(0.0, luts[i] - max(lut_ci[0], 0.0005))
            x_upper = max(0.0, max(lut_ci[1], luts[i]) - luts[i])

            plt.errorbar(
                luts[i], acas[i],
                xerr=[[x_lower], [x_upper]],
                yerr=[[y_lower], [y_upper]],
                fmt=markers[i],
                color=colors[i],
                ecolor="gray",
                elinewidth=1.0,
                capsize=3,
                markersize=9,
                label=name if types[i] not in ["static_sha256"] or "d=2" in name or "d=8" in name or "d=16" in name else None
            )

            # Text annotations for key points
            if "Adaptive PoW" in name or "No Defense" in name or "Random" in name or "Rotating" in name or "d=8" in name or "d=16" in name:
                offset_x = 1.15
                offset_y = 1.05 if acas[i] > 2 else 0.85
                plt.annotate(
                    name,
                    xy=(luts[i], acas[i]),
                    xytext=(luts[i] * offset_x, acas[i] * offset_y),
                    fontsize=8.5,
                    fontweight="bold" if "Adaptive PoW" in name else "normal",
                    bbox=dict(boxstyle="round,pad=0.2", fc="white", ec="gray", alpha=0.8)
                )

        # Plot Pareto Frontier Envelope Curve
        # Connect: No Defense -> Adaptive PoW (Low Phone) -> Adaptive PoW (Argon2id)
        pareto_x = [0.001, frontier_data["Adaptive PoW (Low Phone)"]["lut_low_p95_ms"], frontier_data["Adaptive PoW (Argon2id Memory-Hard)"]["lut_low_p95_ms"]]
        pareto_y = [1.0, frontier_data["Adaptive PoW (Low Phone)"]["aca"], frontier_data["Adaptive PoW (Argon2id Memory-Hard)"]["aca"]]
        plt.plot(pareto_x, pareto_y, "g--", lw=2, alpha=0.8, label="Pareto Dominance Frontier")

        plt.xscale("log")
        plt.yscale("log")
        plt.title("The Cost Frontier: Attacker Cost Amplification vs Legitimate User Tax", fontsize=13, fontweight="bold")
        plt.xlabel("Legitimate User Tax: LUT (p95 Low-End Phone Latency Added in ms, Log Scale)", fontsize=11, fontweight="bold")
        plt.ylabel("Attacker Cost Amplification: ACA (Ratio vs No-Defense, Log Scale)", fontsize=11, fontweight="bold")
        plt.grid(True, which="both", linestyle="--", alpha=0.4)
        plt.legend(loc="upper left", bbox_to_anchor=(1.02, 1), fontsize=9, frameon=True)

        plt.tight_layout()
        out_path = os.path.join(self.figures_dir, output_file)
        plt.savefig(out_path, dpi=300, bbox_inches="tight")
        plt.close()

        return out_path
