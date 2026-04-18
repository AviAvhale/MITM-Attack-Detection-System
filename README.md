# MITM Attack Detection System

> Real-time Man-in-the-Middle attack detection engine that monitors network traffic for ARP spoofing, certificate anomalies, and latency spikes — with automated alerting and mitigation.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)
![IEEE](https://img.shields.io/badge/IEEE-Research%20Project-orange)

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Sample Output](#sample-output)
- [How It Works](#how-it-works)
- [Technologies Used](#technologies-used)
- [Authors](#authors)
- [License](#license)

---

## About

Man-in-the-Middle (MITM) attacks are among the most dangerous network security threats, allowing attackers to secretly intercept and alter communications between two parties. This project implements a **multi-layered detection system** that identifies MITM attacks in real-time by monitoring network traffic for three types of anomalies:

1. **ARP Spoofing** — Detects forged ARP replies that attempt to associate an attacker's MAC address with a legitimate IP.
2. **Certificate Changes** — Identifies unexpected TLS/SSL certificate modifications that indicate SSL stripping or proxy injection.
3. **Latency Anomalies** — Flags unusual round-trip time spikes caused by traffic rerouting through an attacker's machine.

The system automatically **alerts users** and **blocks compromised communication channels** when an attack is detected.

---

## Features

- **Real-time Detection** — Continuously monitors network parameters for anomalies
- **Three Detection Modules** — ARP spoofing, certificate change, and latency spike detection
- **Automated Mitigation** — Blocks attacker IPs and drops malicious traffic instantly
- **Event Logging** — Timestamped event log with severity levels (CRITICAL, HIGH, MEDIUM)
- **Statistics Dashboard** — Aggregated metrics from all three detector modules
- **Thread-Safe Design** — Uses locks for safe concurrent access to shared data
- **No External Dependencies** — Simulation runs with pure Python (no network access required)

---

## Architecture

```
+----------------------------------------------------------+
|              MITM Detection Engine                        |
|                                                          |
|  +----------------+  +-------------+  +---------------+  |
|  | ARP Spoofing   |  | Certificate |  | Latency       |  |
|  | Detector       |  | Change      |  | Anomaly       |  |
|  |                |  | Detector    |  | Detector      |  |
|  | - IP-MAC Table |  | - Cert Store|  | - RTT Baseline|  |
|  | - Spoof Count  |  | - Fingerprnt|  | - Spike Thres.|  |
|  +-------+--------+  +------+------+  +-------+-------+  |
|          |                   |                 |          |
|          v                   v                 v          |
|  +--------------------------------------------------+    |
|  |            Unified Event Queue                    |    |
|  |  [CRITICAL] [HIGH] [MEDIUM] [LOW]                 |    |
|  +--------------------------------------------------+    |
|          |                                                |
|          v                                                |
|  +--------------------------------------------------+    |
|  |        Alert & Mitigation System                  |    |
|  |  - Block attacker IP/MAC                          |    |
|  |  - Sever compromised connections                  |    |
|  |  - Log events for forensic analysis               |    |
|  +--------------------------------------------------+    |
+----------------------------------------------------------+
```

---

## Project Structure

```
MITM-Attack-Detection-System/
|
|-- mitm_detector.py      # Core detection engine with all three detector modules
|-- simulate_mitm.py      # Simulation script demonstrating all detection scenarios
|-- attacker (1).py       # Attacker simulation script (ARP spoofing)
|-- MITM (1).py           # Basic MITM detection script (ARP-based)
|-- README.md             # Project documentation
```

| File | Description |
|------|-------------|
| `mitm_detector.py` | Contains `ARPSpoofDetector`, `CertificateChangeDetector`, `LatencyAnomalyDetector`, and the unified `MITMDetectionEngine` class |
| `simulate_mitm.py` | Runs a full demonstration of all three attack scenarios without requiring actual network access |
| `attacker (1).py` | Simulates an ARP spoofing attacker sending forged packets |
| `MITM (1).py` | Standalone ARP-based MITM detection script |

---

## Installation

### Prerequisites

- Python 3.8 or higher

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/<your-username>/MITM-Attack-Detection-System.git
   cd MITM-Attack-Detection-System
   ```

2. **No additional dependencies required** — the simulation uses only Python standard libraries.

3. **For live network monitoring** (optional):
   ```bash
   pip install scapy
   ```
   > Note: Live packet sniffing requires [Npcap](https://npcap.com/) on Windows or `libpcap` on Linux.

---

## Usage

### Run the Full Simulation

```bash
python simulate_mitm.py
```

This demonstrates all three detection scenarios:
- **Scenario 1:** ARP Spoofing Detection & Mitigation
- **Scenario 2:** Certificate Change Detection & Alerting
- **Scenario 3:** Latency Anomaly Detection & Monitoring

### Run the Basic ARP Detector

```bash
python "MITM (1).py"
```
> Requires Scapy and Npcap/libpcap for live packet capture.

---

## Sample Output

```
=================================================================
  MITM ATTACK DETECTION SYSTEM - LIVE DEMONSTRATION
=================================================================
  Detects: ARP Spoofing | Certificate Changes | Latency Anomalies
  System will alert users and block compromised channels.

=================================================================
  SCENARIO 1: ARP SPOOFING DETECTION
=================================================================

[Step 1] Legitimate node '192.168.0.113' sends a valid ARP reply...
  [+] Learned new mapping: IP 192.168.0.113 -> MAC AA:BB:CC:DD:EE:FF

[Step 2] Attacker sends FORGED ARP reply claiming to be '192.168.0.113'...

  +=======================================================+
  | [!!] [CRITICAL] ALERT: ARP_SPOOF                      |
  +=======================================================+
  Source IP : 192.168.0.113
  Details   : ARP Spoofing detected! IP 192.168.0.113 changed MAC
              from AA:BB:CC:DD:EE:FF to 00:11:22:33:44:55

  [!!!] MITIGATION TRIGGERED [!!!]
  [*] Blocking compromised IP: 192.168.0.113 and MAC: 00:11:22:33:44:55
  [*] Connection severed. Traffic from malicious node dropped.

=================================================================
  SCENARIO 2: CERTIFICATE CHANGE DETECTION
=================================================================

  +=======================================================+
  | [!!] [CRITICAL] ALERT: CERT_CHANGE                    |
  +=======================================================+
  [*] SECURITY ALERT raised. Certificate mismatch logged.

=================================================================
  SCENARIO 3: LATENCY ANOMALY DETECTION
=================================================================

  [=] Baseline established: ~5.1 ms
  [!] Ping: RTT = 45.3 ms  <-- ABNORMAL!
  [*] Spike ratio: 8.88x baseline

-----------------------------------------------------------------
  DETECTION ENGINE STATISTICS
-----------------------------------------------------------------
  >> TOTAL ATTACKS DETECTED: 4
  >> TOTAL EVENTS LOGGED  : 4
-----------------------------------------------------------------
  [OK] All three detection mechanisms verified successfully.
  [OK] Alerting and automated mitigation demonstrated.
```

---

## How It Works

### 1. ARP Spoofing Detection

| Phase | Action |
|-------|--------|
| **Learn** | Stores the first IP → MAC mapping as the trusted baseline |
| **Detect** | Compares every new ARP reply against stored mappings |
| **Respond** | If MAC changes for a known IP → CRITICAL alert + block attacker |

### 2. Certificate Change Detection

| Phase | Action |
|-------|--------|
| **Learn** | Stores the TLS certificate fingerprint and issuer on first connection |
| **Detect** | Compares subsequent certificates against stored fingerprints |
| **Respond** | If fingerprint or issuer changes → CRITICAL/HIGH alert + warn user |

### 3. Latency Anomaly Detection

| Phase | Action |
|-------|--------|
| **Learn** | Collects RTT measurements to build a baseline (minimum 3 samples) |
| **Detect** | Flags any RTT exceeding 3x the baseline average |
| **Respond** | Logs the spike ratio and flags the host for enhanced monitoring |

---

## Technologies Used

| Technology | Purpose |
|------------|---------|
| **Python 3** | Core programming language |
| **Scapy** | Network packet crafting & sniffing (for live mode) |
| **Threading** | Thread-safe concurrent detection |
| **hashlib** | Event ID generation via MD5 hashing |
| **Queue** | Thread-safe event pipeline between detectors |

---

## Authors

- **Your Name** — Avinash Ganesh Avhale[GitHub Profile](https://github.com/AviAvhale)

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  <b>Built for IEEE Research | Network Security | MITM Detection</b>
</p>
