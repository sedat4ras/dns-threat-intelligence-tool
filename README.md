#  DNS Beacon Intelligence & Threat Analyzer

**A Heuristic and Intelligence-Driven DNS Traffic Analysis Pipeline.**

This project is a modular, high-performance cybersecurity tool designed to detect **C2 (Command and Control) Beacons** and **DGA (Domain Generation Algorithms)** within raw network traffic. By combining mathematical entropy analysis, timing consistency (jitter) checks, and real-time **VirusTotal Threat Intelligence**, it transforms complex PCAP data into an actionable executive dashboard.

---

## 🎯 Project Goals & Vision
Traditional IDS/IPS systems often rely on static blacklists. This project aims to bypass that limitation by focusing on **behavioral analysis**:
* **Identify Zero-Day Threats:** Spot malicious domains that haven't been blacklisted yet by analyzing their mathematical randomness.
* **Detect Beaconing Patterns:** Uncover automated malware communication that mimics machine-like periodicity.
* **Prioritize Alerts:** Automatically rank the top threats to reduce "alert fatigue" for SOC analysts.
* **Bridge the Gap:** Combine local statistical evidence with global threat intelligence (VirusTotal).

---

## ⚙️ The Multi-Stage Pipeline (Working Principle)
The project follows a professional data engineering pipeline divided into four distinct stages:

### 1. Data Extraction (`src/extractor.py`)
* **Mechanism:** Utilizes `Pyshark` to parse raw `.pcap` or `.pcapng` files.
* **Action:** Filters specifically for DNS (UDP Port 53) traffic.
* **Output:** Generates a structured CSV containing timestamps, source IPs, and queried domain names.

### 2. Heuristic Analysis (`src/analyzer.py`)
* **Shannon Entropy:** Calculates the randomness of domain names. High entropy often indicates DGA-generated domains.
* **Timing Consistency (Inverse Jitter):** Measures the interval between requests. Machines (malware) tend to be very consistent, while humans are random.
* **Risk Scoring:** A composite 0-100 score is generated using a weighted formula of entropy, timing, and frequency.

### 3. Threat Intelligence Enrichment (`src/enricher.py`)
* **VirusTotal Integration:** Automatically queries the top most suspicious domains via the VT API.
* **Verification:** Cross-references local heuristic findings with 70+ global antivirus engines.

### 4. Visual Intelligence Dashboard (`src/visualizer.py`)
* **The Matrix:** A 3-panel executive view including Threat Map, Ranked List, and VT Reputation status.
* **Visual Alarms:** Uses yellow "!" markers for domains confirmed as malicious by external intelligence.

---

## 📊 How to Read the Dashboard
The final output is an **Executive Intelligence Report (v6.1)**:
* **X-Axis (Entropy):** Measures domain name randomness. High values (>3.5) are suspicious.
* **Y-Axis (Consistency):** Represents machine-like behavior. High values indicate periodic C2 Beacons.
* **Bubble Size:** Larger bubbles represent high-volume traffic.
* **VT Reputation Panel:** Provides real-time "Positive/Negative" status from global vendors.

---

## 🛠️ Technical Setup

### Prerequisites
* Python 3.9+
* Wireshark (TShark) installed and added to PATH.
* VirusTotal API Key.

### Installation & Usage
1. Clone the repository and install dependencies:
   ```bash
   pip install -r requirements.txt
Create a .env file in the root directory:

Plaintext

VT_API_KEY=your_secret_api_key_here
Run the pipeline:

Bash

python main.py


🛡️ Professional Disclaimer
DISCLAIMER: All findings presented in this dashboard are visualized using independent statistical algorithms and heuristic methodologies. These results are for informational purposes only and do not guarantee definitive outcomes or absolute certainty. Final human analysis is always recommended.