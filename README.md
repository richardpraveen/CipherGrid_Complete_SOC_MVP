# CipherGrid — Complete Working SOC MVP

## What this is
A defensive, end-to-end SOC demonstration for SIH. The dashboard is connected to a real FastAPI backend and ML detection pipeline.

Flow:
PCAP/CSV/Synthetic Flow -> Feature Processing -> Random Forest + Isolation Forest -> Threat + Confidence + Evidence -> Recommendation -> SQLite -> SHA-256 Ledger -> SOC Dashboard

## Windows setup

Open Command Prompt in this folder:

    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    python run.py

Then open:

    http://127.0.0.1:8000

## Dashboard functions

- Live SOC overview
- Safe synthetic flow generation
- CSV flow ingestion
- Random Forest known-threat classification
- Isolation Forest anomaly detection
- Six SIH threat categories
- Confidence and severity
- Supporting evidence
- Analyst recommendations
- SQLite event and flow storage
- SHA-256 hash-chained event ledger
- Ledger verification
- Responsive web dashboard

## Optional PCAP support

The project includes an optional PCAP endpoint. Install Scapy:

    pip install scapy

Then upload an authorized `.pcap` or `.pcapng` capture from the dashboard.

## Important

This is a functional MVP for SIH demonstration/development. It does not claim production-grade detection accuracy. Use only synthetic, laboratory, or authorized traffic. CipherGrid is passive decision-support and does not automatically block or attack traffic.
