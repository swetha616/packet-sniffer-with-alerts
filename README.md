# Network Packet Sniffer with Alert System

## Overview

This project is a **real-time network packet sniffer** built in Python. It captures network traffic, logs packet data into a SQLite database, detects anomalies such as flooding and port scans, and generates alerts in real-time. An optional GUI visualizes live traffic statistics.

## Features

* Real-time packet capture using **Scapy**
* Logs packet headers (IP, port, protocol, length, flags) to **SQLite**
* Detects anomalies:

  * Port scans
  * Flooding attacks (packets per second threshold)
  * SYN flood patterns
* Alerts printed on console 
* Optional GUI using **Matplotlib** for live traffic graphs
* CLI options for filtering, verbose printing, and demo packet counts

## Requirements

* Python 3.11+
* Packages:

  * scapy
  * matplotlib (optional, for GUI)

Install dependencies via pip:

```bash
pip install scapy matplotlib
```

## Files

* `sniffer.py` — main Python script for the sniffer
* `Project_Report.docx` — project report

## Usage

Run the sniffer (Windows as Admin / Linux with sudo):

```bash
python sniffer_complete.py --filter "ip" --verbose
```

### Options

* `--iface` : Network interface to capture from (default: auto)
* `--filter` : BPF filter string (e.g., `tcp or udp`)
* `--db` : Path to SQLite database (default: `traffic.db`)
* `--no-detect` : Disable anomaly detection
* `--summary` : Display traffic summary from DB
* `--gui` : Enable live graph display (requires matplotlib)
* `--verbose` : Print each packet header to console
* `--limit-rate` : Max prints/sec in verbose mode (default 0 = unlimited)
* `--count` : Stop after N packets (for demos)

### Example Commands

* Capture all IP traffic with GUI:

```bash
python sniffer_complete.py --filter "ip" --gui
```

* Capture with verbose headers:

```bash
python sniffer_complete.py --filter "tcp or udp" --verbose
```

* Display DB summary:

```bash
python sniffer_complete.py --summary
```

## Alerts

Alerts are triggered when traffic exceeds configured thresholds. Examples:

* Port scan detection: multiple destination ports accessed by the same source within a short time
* Flood detection: packets per second above threshold
* SYN flood pattern detection: high SYN-to-ACK ratio

Alerts are printed in console and stored in the SQLite database. Optional email notifications can be configured.

## How to Test

* Safely test alerts in a controlled network
* Use traffic generators or repeated ping/connection attempts for demo purposes

## Notes

* Run with administrative/root privileges for full packet capture
* Database file is auto-created on first run
* GUI is optional; can run in CLI-only mode

---

**Project by Swetha Prasad**
Final Project Submission: 08 September 2025
