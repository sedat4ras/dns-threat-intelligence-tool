"""
DNS Traffic Analyzer (Advanced Version)
Phase 3: Risk Scoring, Whitelisting, and Data Export
Description: Analyzes DNS data, applies risk scores, and saves results for visualization.
"""

import pandas as pd
import numpy as np
import math
import os
import sys

class DNSAnalyzer:
    # Whitelist: Known safe services to reduce false positives
    WHITELIST = [
        'google.com', 'googleapis.com', 'gstatic.com', 
        'steamserver.net', 'microsoft.com', 'windows.com', 
        'whatsapp.net', 'discordapp.com', 'epicgames.com'
    ]

    def __init__(self, csv_path):
        self.csv_path = csv_path
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"CSV file not found: {csv_path}")
        
        # Load data and convert timestamp to datetime objects
        self.df = pd.read_csv(csv_path)
        self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])

    def calculate_entropy(self, domain):
        """Calculates Shannon Entropy for a domain name string."""
        if not domain or not isinstance(domain, str): return 0
        main_part = domain.split('.')[0]
        if not main_part: return 0
        probs = [float(main_part.count(c)) / len(main_part) for c in set(main_part)]
        entropy = -sum([p * math.log(p, 2) for p in probs])
        return round(entropy, 4)

    def calculate_risk_score(self, row):
        """Combines entropy and timing metrics into a risk score (0-100)."""
        score = 0
        
        # 1. Entropy Factor (Max 40 Points)
        # Entropy above 4.5 is considered highly random (DGA suspect)
        entropy_weight = min(row['entropy'] / 4.5, 1.0) * 40
        score += entropy_weight
        
        # 2. Beaconing Factor (Max 60 Points)
        # Low standard deviation indicates automated/robotic behavior
        if row['std_dev'] != "N/A" and row['count'] > 3:
            std_dev = float(row['std_dev'])
            # Jitter less than 0.1s gives max points, decreases as jitter increases
            jitter_score = max(0, 60 - (std_dev * 10)) 
            score += jitter_score

        # 3. Whitelist Check (Reduces score by 90% for known services)
        for safe_domain in self.WHITELIST:
            if safe_domain in row['query_name']:
                score = score * 0.1
        
        return round(min(score, 100), 2)

    def analyze_traffic(self):
        """Groups traffic, extracts stats, and calculates final risk scores."""
        results = []
        grouped = self.df.groupby(['source_ip', 'query_name'])

        for (src, domain), group in grouped:
            sorted_group = group.sort_values(by='timestamp')
            intervals = sorted_group['timestamp'].diff().dt.total_seconds().dropna()
            
            avg_interval = intervals.mean() if not intervals.empty else 0
            std_dev = intervals.std() if len(intervals) > 1 else -1
            entropy_score = self.calculate_entropy(domain)
            
            results.append({
                'source_ip': src,
                'query_name': domain,
                'avg_interval': round(avg_interval, 2),
                'std_dev': round(std_dev, 4) if std_dev != -1 else "N/A",
                'entropy': entropy_score,
                'count': len(group)
            })
            
        res_df = pd.DataFrame(results)
        # Apply risk scoring to each row
        res_df['risk_score'] = res_df.apply(self.calculate_risk_score, axis=1)
        return res_df

if __name__ == "__main__":
    # Usage: python src/analyzer.py output/pcapfile2.csv
    if len(sys.argv) > 1:
        TARGET_CSV = sys.argv[1]
    else:
        TARGET_CSV = os.path.join("output", "pcapfile1.csv")

    try:
        print(f"[*] Starting statistical analysis on: {TARGET_CSV}")
        analyzer = DNSAnalyzer(TARGET_CSV)
        results_df = analyzer.analyze_traffic()
        
        # EXPORTING RESULTS: Saves a new CSV for the visualizer
        analyzed_csv_path = TARGET_CSV.replace('.csv', '_analyzed.csv')
        results_df.to_csv(analyzed_csv_path, index=False)
        
        print("\n[!] Top Risk Analysis Results (Sorted by Risk Score):")
        top_risks = results_df.sort_values(by='risk_score', ascending=False).head(15)
        print(top_risks[['query_name', 'risk_score', 'entropy', 'std_dev', 'count']])
        
        print(f"\n[+] Analyzed data saved for visualization: {analyzed_csv_path}")
        
    except Exception as e:
        print(f"[X] Analysis Error: {e}")