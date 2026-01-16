"""
DNS Data Extractor (Optimized)
Phase 1: Ingestion and Extraction
Description: Extracts DNS queries from PCAP and saves to CSV only if it doesn't exist.
"""

import pyshark
import pandas as pd
import os
import asyncio
import sys

class DNSDataExtractor:
    def __init__(self, file_path, output_dir="output"):
        self.file_path = file_path
        self.output_dir = output_dir
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"PCAP file not found: {file_path}")
        
        # Prepare the output path beforehand to check for existence
        input_filename = os.path.basename(self.file_path)
        self.raw_name = os.path.splitext(input_filename)[0]
        self.output_csv_path = os.path.join(self.output_dir, f"{self.raw_name}.csv")

    def extract_queries(self):
        # NEW: Check if the CSV already exists before starting the heavy pyshark process
        if os.path.exists(self.output_csv_path):
            print(f"[!] Skipping: {self.output_csv_path} already exists.")
            # We return the existing path so the pipeline can continue to analysis
            return pd.read_csv(self.output_csv_path)

        records = []
        print(f"[*] Analyzing {os.path.basename(self.file_path)} (This may take a while)...")
        
        capture = pyshark.FileCapture(self.file_path, display_filter='dns')

        for packet in capture:
            try:
                is_response = str(packet.dns.flags_response)
                if is_response in ['0', 'False']:
                    src_ip = packet.ip.src if hasattr(packet, 'ip') else (packet.ipv6.src if hasattr(packet, 'ipv6') else "Unknown")

                    records.append({
                        'timestamp': packet.sniff_time,
                        'source_ip': src_ip,
                        'query_name': packet.dns.qry_name,
                        'query_type': packet.dns.qry_type,
                        'packet_length': int(packet.length)
                    })
            except AttributeError:
                continue
        
        capture.close()
        df = pd.DataFrame(records)
        
        # Save after extraction
        if not df.empty:
            self.save_to_csv(df)
            
        return df

    def save_to_csv(self, df):
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            
        df.to_csv(self.output_csv_path, index=False)
        print(f"[+] Successfully saved: {self.output_csv_path}")

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    target_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join("data", "pcapfile2.pcapng")
    
    try:
        extractor = DNSDataExtractor(target_file)
        dns_df = extractor.extract_queries()
        if dns_df.empty:
            print("[!] No DNS queries found or processed.")
    except Exception as e:
        print(f"[X] Error: {e}")