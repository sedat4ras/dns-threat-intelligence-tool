"""
DNS Beacon Intelligence & Threat Analyzer v1.0
Automated Folder Management & Dynamic File Input
"""

import subprocess
import os
import sys

def print_banner():
    # Banner kodun (Zülfikar) burada kalacak
    banner = r"""
                                      .
                                     / \
                                    /   \
                                   /     \
                                  /       \
                                 /         \
                                /           \
                               /             \
                              /               \
                             /                 \
                            /                   \
                           /                     \
                          /                       \
                         /                         \
                        /       _           _       \
                       |       (_)         (_)       |
                       |                             |
                        \                           /
                         \                         /
                          \                       /
                           \                     /
                            \                   /
                             \                 /
                              \               /
                               \             /
                                \           /
                                 \         /
                                  \       /
                                   \     /
                                    \   /
                                     \ /
                                      v
                                      |
                                      |
                                     _|_
                                    |___|

    ========================================================================================
    |                DNS BEACON INTELLIGENCE & THREAT ANALYZER v1.0                        |
    |            Advanced Heuristic Detection & Threat Intelligence Pipeline               |
    ========================================================================================
    """
    print(banner)

def run_pipeline(pcap_path):
    # --- AUTOMATED FOLDER MANAGEMENT ---
    # Kodun çalışması için gereken klasör yapısını kurar
    folders = ["data", "output", os.path.join("output", "plots")]
    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder)
            print(f"[*] Created missing directory: {folder}")

    filename = os.path.basename(pcap_path)
    base_name = os.path.splitext(filename)[0]
    
    raw_csv = os.path.join("output", f"{base_name}.csv")
    analyzed_csv = os.path.join("output", f"{base_name}_analyzed.csv")
    enriched_csv = os.path.join("output", f"{base_name}_enriched.csv")

    print_banner()
    print(f"[*] Starting Analysis on: {filename}")
    print("-" * 80)

    # STEP 1: Extraction
    print(f"\n[STEP 1/4] Extracting DNS queries from {filename}...")
    try:
        subprocess.run([sys.executable, "src/extractor.py", pcap_path], check=True)
    except subprocess.CalledProcessError:
        print("[X] Extraction failed.")
        return

    # STEP 2: Statistical Analysis
    print("\n[STEP 2/4] Calculating Heuristic Risk Scores...")
    try:
        subprocess.run([sys.executable, "src/analyzer.py", raw_csv], check=True)
    except subprocess.CalledProcessError:
        print("[X] Analysis failed.")
        return

    # STEP 3: VirusTotal Enrichment
    print("\n[STEP 3/4] Querying VirusTotal Intelligence...")
    try:
        subprocess.run([sys.executable, "src/enricher.py", analyzed_csv], check=True)
        final_data = enriched_csv
    except subprocess.CalledProcessError:
        print("[!] Enrichment skipped, visualizing analyzed data only.")
        final_data = analyzed_csv

    # STEP 4: Visualization
    print("\n[STEP 4/4] Rendering Intelligence Dashboard...")
    try:
        subprocess.run([sys.executable, "src/visualizer.py", final_data], check=True)
    except subprocess.CalledProcessError:
        print("[X] Visualization failed.")
        return

    print("\n" + "="*80)
    print("[SUCCESS] Pipeline completed.")
    print(f"[REPORT] Check 'output/plots/' for the results of {base_name}.")
    print("="*80)

if __name__ == "__main__":
    # Eğer komut satırından dosya belirtilmediyse varsayılan dosyayı kullanır
    if len(sys.argv) > 1:
        target_pcap = sys.argv[1]
    else:
        # Klasör yoksa hata vermemesi için varsayılan dosya yolu
        target_pcap = os.path.join("data", "pcapfile2.pcapng")

    if not os.path.exists(target_pcap):
        # Sadece hata mesajını göster ve klasörleri oluştur (gelecek sefer için)
        os.makedirs("data", exist_ok=True)
        print(f"[X] Error: Input file '{target_pcap}' not found.")
        print("[!] Please place your PCAP file in the 'data/' folder and run again.")
    else:
        run_pipeline(target_pcap)