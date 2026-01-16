import pandas as pd
import requests
import time
import os
import sys
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class ThreatEnricher:
    def __init__(self, file_path):
        self.file_path = file_path
        # Retrieve the key from environment variables
        self.api_key = os.getenv("VT_API_KEY")
        
        if not self.api_key:
            print("[X] Error: VT_API_KEY not found in .env file!")
            sys.exit(1)
            
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Analyzed file not found: {file_path}")
        self.df = pd.read_csv(file_path)

    def get_vt_score(self, domain):
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": self.api_key}
        
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return stats.get('malicious', 0)
            elif response.status_code == 429:
                return "RateLimited"
            else:
                return 0
        except Exception as e:
            print(f"[X] VT Query Error ({domain}): {e}")
            return 0

    def enrich_data(self, top_n=10):
        print(f"[*] Enriching top {top_n} domains with VirusTotal Intelligence...")
        
        self.df = self.df.sort_values(by='risk_score', ascending=False).reset_index(drop=True)
        self.df['vt_malicious_count'] = 0
        
        for i in range(min(top_n, len(self.df))):
            domain = self.df.loc[i, 'query_name']
            print(f"    [>] Querying VT for: {domain} ({i+1}/{top_n})")
            
            score = self.get_vt_score(domain)
            
            if score == "RateLimited":
                print("    [!] API Rate Limit! Waiting 60 seconds...")
                time.sleep(60)
                score = self.get_vt_score(domain)
            
            self.df.loc[i, 'vt_malicious_count'] = score if isinstance(score, int) else 0
            
            # Respect Public API limit: 4 requests per minute
            if i < top_n - 1:
                time.sleep(15)
        
        output_path = self.file_path.replace('_analyzed.csv', '_enriched.csv')
        self.df.to_csv(output_path, index=False)
        print(f"[+] Enriched data saved to: {output_path}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join("output", "pcapfile2_analyzed.csv")
    try:
        enricher = ThreatEnricher(target)
        enricher.enrich_data(top_n=10)
    except Exception as e:
        print(f"[X] Enrichment Error: {e}")