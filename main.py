"""
DNS Beacon Analyzer - Orchestrator (v6.1 - Zulfiqar Edition)
Description: Runs Extractor, Analyzer, Enricher, and Visualizer in sequence.
GitHub: Professional Integrated Pipeline with ASCII Signature
"""

import subprocess
import os
import sys

def print_banner():
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
    |                DNS BEACON INTELLIGENCE & THREAT ANALYZER v6.1                        |
    |            Advanced Heuristic Detection & Threat Intelligence Pipeline               |
    ========================================================================================
    """
    print(banner)

def run_pipeline(pcap_path):
    # 1. Configuration & Path Management
    os.makedirs("output", exist_ok=True)
    
    filename = os.path.basename(pcap_path)
    base_name = os.path.splitext(filename)[0]
    
    # Deriving all file paths based on input filename
    raw_csv = os.path.join("output", f"{base_name}.csv")
    analyzed_csv = os.path.join("output", f"{base_name}_analyzed.csv")
    enriched_csv = os.path.join("output", f"{base_name}_enriched.csv")

    print_banner() # Program başlarken logoyu basar
    print(f"[*] Starting Professional Threat Hunt for: {filename}")
    print("-" * 80)

    # STEP 1: Extraction
    print("\n[STEP 1/4] Extracting DNS queries from PCAP...")
    try:
        subprocess.run([sys.executable, "src/extractor.py", pcap_path], check=True)
    except subprocess.CalledProcessError:
        print("[X] Extraction failed. Pipeline stopped.")
        return

    # STEP 2: Statistical Analysis
    if os.path.exists(raw_csv):
        print("\n[STEP 2/4] Analyzing patterns and calculating risk scores...")
        try:
            subprocess.run([sys.executable, "src/analyzer.py", raw_csv], check=True)
        except subprocess.CalledProcessError:
            print("[X] Analysis failed. Pipeline stopped.")
            return
    else:
        print(f"[X] Error: {raw_csv} not found!")
        return

    # STEP 3: VirusTotal Enrichment
    if os.path.exists(analyzed_csv):
        print("\n[STEP 3/4] Enriching with VirusTotal Threat Intelligence...")
        print("[!] Note: This step respects API limits (15s delay per query).")
        try:
            # We pass the analyzed_csv to the enricher, it saves as _enriched.csv
            subprocess.run([sys.executable, "src/enricher.py", analyzed_csv], check=True)
            # If successful, next step uses enriched data
            final_data_to_plot = enriched_csv
        except subprocess.CalledProcessError:
            print("[!] Enrichment failed or API key error. Proceeding to visualize analysis only...")
            # Fallback: if enrichment fails, we use the analyzed_csv for visualization
            final_data_to_plot = analyzed_csv
    else:
        print(f"[X] Error: {analyzed_csv} not found!")
        return

    # STEP 4: Visualization
    if os.path.exists(final_data_to_plot):
        print(f"\n[STEP 4/4] Generating Visual Dashboard using {os.path.basename(final_data_to_plot)}...")
        try:
            subprocess.run([sys.executable, "src/visualizer.py", final_data_to_plot], check=True)
        except subprocess.CalledProcessError:
            print("[X] Visualization failed.")
            return
    else:
        print(f"[X] Error: {final_data_to_plot} not found!")
        return

    print("\n" + "="*80)
    print("[SUCCESS] Full Pipeline Completed.")
    print(f"[RESULTS] Check 'output/plots/' for the final executive dashboard.")
    print("="*80)

if __name__ == "__main__":
    # Optional: Allow passing a different PCAP file argument
    if len(sys.argv) > 1:
        target_pcap = sys.argv[1]
    else:
        # Default to our test file inside the data folder
        target_pcap = os.path.join("data", "pcapfile2.pcapng")

    if not os.path.exists(target_pcap):
        print(f"[X] Error: Input file {target_pcap} not found. Please check the path.")
    else:
        run_pipeline(target_pcap)