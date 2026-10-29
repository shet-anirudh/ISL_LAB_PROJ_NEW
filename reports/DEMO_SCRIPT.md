# Live Evaluation Demo & Defense Rehearsal Runbook (12–15 Minutes)
**Lead Coordinator:** Person 3 (Analysis & Forensics Lead)  
**Team Members:** Person 1 (Attacker VM), Person 2 (Victim Defense), Person 3 (Simulator & Forensics)

---

## 1. Role Assignments & Setup

| Team Member | Demo Role | Physical Station | Responsibilities |
| :--- | :--- | :--- | :--- |
| **Person 1** | **Terminal Driver (Attacker)** | Attacker VM (Kali) | Launches C2 Server, triggers exfiltration and encryption passes, executes spoofing demo. |
| **Person 2** | **Terminal Driver (Victim)** | Victim VM (Ubuntu) | Runs Honeypot Tripwire Monitor, TLS Backup Server, and post-attack recovery. |
| **Person 3 (YOU)** | **Lead Narrator & Forensic Lead** | Host / Victim Web UI | Explains threat architecture, monitors Live Containment Dashboard, runs PCAP parser & generates final incident report. |

---

## 2. Minute-by-Minute Live Demo Schedule

### [00:00 – 02:00] Introduction & Architecture Overview (Narrated by Person 3)
- Introduce the dual-VM isolated network architecture (`192.168.56.0/24`, Host-Only, no NAT).
- Display the clean dataset in `/home/victim/MILITARY_DATA/`:
  - `01_Operations/`
  - `02_Intelligence/`
  - `03_Media/`
  - `A_COMMAND_ARCHIVE/` (Honeypot canary directory)
- Show baseline SHA-256 hashes in `results/baseline_hashes.json`.

### [02:00 – 04:30] Phase 1: Pre-Attack TLS Backup & Defense Staging
- **Person 2 (Victim):** Starts the TLS-encrypted backup daemon:
  ```bash
  python3 victim/backup.py --server --port 9003
  python3 victim/backup.py --client --dir /home/victim/MILITARY_DATA
  ```
- **Person 2:** Arms the active Honeypot Tripwire Watcher:
  ```bash
  python3 victim/honeypot_monitor.py
  ```
- **Person 3:** Opens the Containment Operations Dashboard in the browser (`http://192.168.56.20:5000`):
  - Shows status: **ARMED**, `0` decoys touched, `0` files encrypted.

### [04:30 – 07:00] Phase 2: C2 Beaconing, Spoofing Demo & Exfiltration
- **Person 1 (Attacker):** Starts Wireshark / tshark capture in background:
  ```bash
  tshark -i eth0 -w /tmp/attack_trial.pcap &
  ```
- **Person 1 (Attacker):** Launches C2 Server and demonstrates authentication:
  ```bash
  python3 attacker/c2_server.py
  ```
- **Person 1:** Runs the C2 Spoofing demonstration (`tests/spoof_demo.py`):
  - Shows that forged commands without HMAC-SHA256 signature are **rejected**.
  - Shows authenticated `START_EXFIL` command accepted.
- **Person 1:** Starts `transfer_receiver.py` on port 9002; victim exfiltrates targeted files.

### [07:00 – 09:30] Phase 3: In-Situ Encryption & Immediate Tripwire Containment
- **Person 1 (Attacker):** Issues `START_ENCRYPT` via C2 to trigger `ransomware/simulator.py`.
- **Person 3 (Dashboard):** Highlights the live telemetry in the browser:
  - Simulator begins alphabetical traversal (`01_Operations`, `02_Intelligence`, `03_Media`).
  - As soon as traversal enters `A_COMMAND_ARCHIVE/` and touches a canary file:
    - Watchdog detects file modification in `< 150 ms`.
    - Resolves offending PID.
    - Sends immediate `SIGKILL` to simulator process.
  - **DASHBOARD FLASHES RED EMERGENCY BANNER:**
    `EMERGENCY TRIPWIRE TRIGGERED — MALWARE CONTAINED (PID: xxxx)`
  - Traversal is completely halted mid-attack!

### [09:30 – 11:30] Phase 4: Automated Post-Attack Restore & Integrity Verification
- **Person 2 (Victim):** Runs the automated restore script:
  ```bash
  python3 victim/backup.py --restore
  ```
- Verifies that all files match original SHA-256 baseline hashes (100% integrity recovery, 0 ransom paid).

### [11:30 – 14:00] Phase 5: PCAP Traffic Analysis & Automated Forensic Incident Report
- **Person 3:** Stops PCAP capture and parses flows into SQLite:
  ```bash
  python3 analysis/pcap_parser.py --pcap /tmp/attack_trial.pcap --db flows.sqlite
  ```
- Runs detection queries:
  - Flags C2 beaconing pattern (`TCP/9001`)
  - Flags high-volume exfiltration flow (`TCP/9002`)
- **Person 3:** Generates the structured markdown forensic report:
  ```bash
  python3 analysis/forensic_report.py --db flows.sqlite --output reports/final_incident_report.md
  ```
- Displays the merged timeline, 4 IOC categories, and the Honeypot vs. Traffic latency comparison table.

### [14:00 – 15:00] Conclusion & Q&A
- Present the 4 evaluation charts (`reports/charts/`):
  - 88%+ files saved ratio with honeypot vs 0% without.
  - Sub-second containment latency.
- Conclude demo and invite questions from the evaluators.
