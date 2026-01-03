# Python-Intusion-Detection-System

NETWORK INTRUSION DETECTION SYSTEM (IDS)

A Hybrid NIDS combining Rule-Based Heuristics and Unsupervised Machine Learning.

# CONCEPT

This system performs real-time packet analysis on live network traffic to detect suspicious behavior. Unlike static firewalls, it utilizes an Isolation Forest (Machine Learning) model alongside statistical thresholds to identify anomalies, port scanning, and DOS attempts dynamically.

## How It Works

The engine analyzes live traffic packets and extracts behavioral features to flag threats using a hybrid approach:
Heuristic Analysis: Immediate flagging of high-rate connections (>10/sec), volume anomalies (>30 connections), and Port Scanning behavior (>10 unique ports).
Machine Learning (Isolation Forest): An unsupervised algorithm that isolates anomalies by randomly partitioning data points. It automatically learns "normal" traffic patterns and flags deviations (outliers).
TCP Flag Inspection: specifically monitors TCP headers to detect SYN Flood attacks.

# FEATURES & LOGGING

The system continuously monitors the default network interface and generates real-time logs:
suspicious_ips.txt: Records IPs flagged by the ML model or heuristic thresholds.
alert.txt: Specific log for critical TCP SYN flood alerts.
Auto-Training: The ML model retrains itself every 100 packets to adapt to changing network conditions.

# QUICK START

## Prerequisites

Wireshark/Npcap: Must be installed for packet capture.
Python Libraries: pyshark, netifaces, numpy, scikit-learn.
Run the IDS

The script automatically detects your default gateway/interface and starts sniffing.
```bash
python simple_ids.py
```
> [!NOTE]
> Run as Administrator/Root to ensure access to network interfaces

# BUILD INFO

Stack: Python 3.x, Pyshark, Scikit-Learn
Algorithm: Isolation Forest (Anomaly Detection) & Statistical Thresholding