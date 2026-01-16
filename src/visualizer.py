import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
import os
import sys
import textwrap

class ThreatVisualizer:
    def __init__(self, file_path):
        self.file_path = file_path
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        self.df = pd.read_csv(file_path)

    def plot_threat_dashboard(self):
        ALERT_THRESHOLD = 20
        MIN_RANK_COUNT = 10
        
        # Data Prep
        self.df['std_dev_clean'] = pd.to_numeric(self.df['std_dev'], errors='coerce').fillna(100.0)
        self.df['consistency'] = 1 / (self.df['std_dev_clean'] + 0.02)
        
        df_sorted = self.df.sort_values(by='risk_score', ascending=False).reset_index(drop=True)
        critical_mask = (df_sorted['risk_score'] >= ALERT_THRESHOLD) | (df_sorted.index < MIN_RANK_COUNT)
        
        critical_df = df_sorted[critical_mask].copy()
        normal_df = df_sorted[~critical_mask].copy()
        critical_df['rank'] = critical_df.index + 1

        # Setup Figure
        fig = plt.figure(figsize=(26, 13)) # Height increased slightly for extra text
        gs = gridspec.GridSpec(2, 3, width_ratios=[3, 1.3, 1.3], height_ratios=[5, 1.5])
        
        ax_plot = fig.add_subplot(gs[0, 0])
        ax_legend = fig.add_subplot(gs[0, 1])
        ax_vt = fig.add_subplot(gs[0, 2])
        ax_info = fig.add_subplot(gs[1, :])

        fig.suptitle('EXECUTIVE DNS THREAT INTELLIGENCE REPORT (v6.1)', fontsize=30, fontweight='bold', y=0.98)

        # --- 1. MAIN THREAT MAP ---
        sns.set_style("white")
        ax_plot.scatter(normal_df['entropy'], normal_df['consistency'], s=normal_df['count']*15, c='gray', alpha=0.10)
        
        scatter = ax_plot.scatter(
            critical_df['entropy'], critical_df['consistency'],
            s=(critical_df['count'] * critical_df['risk_score']) / 2 + 65,
            c=critical_df['risk_score'], cmap='Reds', alpha=0.85, edgecolors="black", linewidth=1.5, zorder=5
        )

        for i, row in critical_df.iterrows():
            vt_val = int(row.get('vt_malicious_count', 0))
            label = f"{int(row['rank'])}{'!' if vt_val > 0 else ''}"
            ax_plot.annotate(
                label, xy=(row['entropy'], row['consistency']),
                xytext=(10, 10), textcoords='offset points',
                fontsize=11, fontweight='bold',
                bbox=dict(boxstyle='circle,pad=0.2', fc='yellow' if vt_val > 0 else 'white', ec='black', alpha=0.9)
            )

        ax_plot.set_xlabel('Shannon Entropy (Complexity/Randomness Score)', fontsize=14, fontweight='bold')
        ax_plot.set_ylabel('Timing Consistency (Machine-like periodicity)', fontsize=14, fontweight='bold')
        plt.colorbar(scatter, ax=ax_plot, label='Composite Risk Score (0-100)')

        # --- 2. RANKED LIST ---
        ax_legend.set_facecolor('#fafafa')
        ax_legend.set_xticks([]); ax_legend.set_yticks([])
        legend_content = "RANKED INVESTIGATION LIST\n" + "="*30 + "\n\n"
        for i, row in critical_df.head(15).iterrows():
            wrapped_name = "\n    ".join(textwrap.wrap(row['query_name'], width=28))
            legend_content += f"#{int(row['rank'])} {wrapped_name}\n   Score: {row['risk_score']:.1f} | Events: {row['count']}\n\n"
        ax_legend.text(0.05, 0.98, legend_content, transform=ax_legend.transAxes, fontsize=10, verticalalignment='top', fontfamily='monospace')

        # --- 3. VIRUSTOTAL REPUTATION ---
        ax_vt.set_facecolor('#f4f7f6')
        ax_vt.set_xticks([]); ax_vt.set_yticks([])
        vt_content = "VIRUSTOTAL INTEL\n" + "="*30 + "\n\n"
        for i, row in critical_df.head(15).iterrows():
            vt_val = int(row.get('vt_malicious_count', 0))
            status = "POSITIVE (THREAT)" if vt_val > 0 else "NEGATIVE (CLEAN)"
            vt_content += f"#{int(row['rank'])}: {status}\n   ({vt_val} engines flagging)\n\n"
        ax_vt.text(0.05, 0.98, vt_content, transform=ax_vt.transAxes, fontsize=10, verticalalignment='top', fontfamily='monospace', fontweight='bold')

        # --- 4. DETAILED GUIDANCE & DISCLAIMER (Bottom) ---
        ax_info.set_facecolor('#1a252f')
        ax_info.set_xticks([]); ax_info.set_yticks([])
        
        info_text = (
            "• X-AXIS (ENTROPY): Measures domain randomness. Higher values (>3.5) indicate DGA (Domain Generation Algorithms).\n"
            "• Y-AXIS (CONSISTENCY): Measures timing regularity. High consistency suggests automated C2 beaconing patterns.\n"
            "• BUBBLE SIZE: Weighted by (Frequency × Risk). Larger bubbles represent high-volume anomalous traffic.\n"
            "• VIRUSTOTAL (VT): External validation. Yellow bubbles with (!) are confirmed threats in global intelligence feeds.\n\n"
            "DISCLAIMER: All findings presented in this dashboard are visualized using independent statistical algorithms and heuristic methodologies.\n"
            "These results are for informational purposes only and do not guarantee definitive outcomes or absolute certainty."
        )
        
        ax_info.text(0.5, 0.5, info_text, transform=ax_info.transAxes, 
                     fontsize=11, fontweight='bold', color='white',
                     ha='center', va='center', linespacing=1.5)

        # Save Final Output
        output_path = os.path.join("output", "plots", "dns_threat_intelligence_v6_1.png")
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        plt.savefig(output_path, dpi=300)
        print(f"[+] Final Dashboard with Disclaimer generated: {output_path}")

if __name__ == "__main__":
    enriched_file = os.path.join("output", "pcapfile2_enriched.csv")
    analyzed_file = os.path.join("output", "pcapfile2_analyzed.csv")
    target = enriched_file if os.path.exists(enriched_file) else analyzed_file
    
    try:
        viz = ThreatVisualizer(target)
        viz.plot_threat_dashboard()
    except Exception as e:
        print(f"[X] Visualization Error: {e}")