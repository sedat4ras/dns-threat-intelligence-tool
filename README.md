DNS Beacon Intelligence & Threat Analyzer
A Heuristic and Intelligence-Driven DNS Traffic Analysis Pipeline.

This project is a modular, high-performance cybersecurity tool designed to detect C2 (Command and Control) Beacons and DGA (Domain Generation Algorithms) within raw network traffic. By combining mathematical entropy analysis, timing consistency (jitter) checks, and real-time VirusTotal Threat Intelligence, it transforms complex PCAP data into an actionable executive dashboard.

Project Goals and Vision
Traditional IDS/IPS systems often rely on static blacklists. This project aims to bypass that limitation by focusing on behavioral analysis:

Identify Zero-Day Threats: Spot malicious domains that have not been blacklisted yet by analyzing their mathematical randomness.

Detect Beaconing Patterns: Uncover automated malware communication that mimics machine-like periodicity.

Prioritize Alerts: Automatically rank the top threats to reduce alert fatigue for SOC analysts.

Bridge the Gap: Combine local statistical evidence with global threat intelligence (VirusTotal).

The Multi-Stage Pipeline (Working Principle)
The project follows a professional data engineering pipeline divided into four distinct stages:

1. Data Extraction (src/extractor.py)
Mechanism: Utilizes Pyshark to parse raw .pcap or .pcapng files.

Action: Filters specifically for DNS (UDP Port 53) traffic.

Output: Generates a structured CSV containing timestamps, source IPs, and queried domain names.

2. Heuristic Analysis (src/analyzer.py)
Shannon Entropy: Calculates the randomness of domain names. High entropy often indicates DGA-generated domains.

Timing Consistency (Inverse Jitter): Measures the interval between requests. Machines (malware) tend to be very consistent, while humans are random.

Risk Scoring: A composite 0-100 score is generated using a weighted formula of entropy, timing, and frequency.

3. Threat Intelligence Enrichment (src/enricher.py)
VirusTotal Integration: Automatically queries the most suspicious domains via the VT API.

Verification: Cross-references local heuristic findings with over 70 global antivirus engines.

4. Visual Intelligence Dashboard (src/visualizer.py)
The Matrix: A 3-panel executive view including Threat Map, Ranked List, and VT Reputation status.

Visual Alarms: Clearly marks domains confirmed as malicious by external intelligence for immediate attention.

How to Read the Dashboard
The final output is an Executive Intelligence Report (v1.0):

X-Axis (Entropy): Measures domain name randomness. High values (>3.5) are considered suspicious.

Y-Axis (Consistency): Represents machine-like behavior. High values indicate periodic C2 Beacons.

Bubble Size: Larger bubbles represent high-volume traffic.

VT Reputation Panel: Provides real-time Positive/Negative status from global vendors.

Technical Setup
Prerequisites
Python 3.9+

Wireshark (TShark) installed and added to PATH.

VirusTotal API Key.

Installation
Clone the repository to your local machine.

Install the required dependencies:

Bash

pip install -r requirements.txt
Configuration
Create a file named .env in the root directory and add your VirusTotal API key:

Plaintext

VT_API_KEY=your_secret_api_key_here
Usage and Commands
1. Default Mode
By default, the tool looks for data/pcapfile2.pcapng. If the folders data, output, and output/plots do not exist, the script will automatically create them.

Bash

python main.py
2. Specific PCAP Analysis
To analyze a specific PCAP file, provide the path as an argument. The tool will automatically name the outputs based on your filename:

Bash

python main.py data/your_custom_file.pcapng
3. Fast Visualization (Rendering Only)
If you have already processed a file and only want to re-render the dashboard:

Bash

python src/visualizer.py
Professional Disclaimer
DISCLAIMER: All findings presented in this dashboard are visualized using independent statistical algorithms and heuristic methodologies. These results are for informational purposes only and do not guarantee definitive outcomes or absolute certainty. Final human analysis is always recommended for security-critical decisions.

author : sedat4ras
