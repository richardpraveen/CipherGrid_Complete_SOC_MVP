import hashlib
import random
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

THREATS = [
    "DDoS/Flooding",
    "C2 Beaconing",
    "DGA/DNS Tunnelling",
    "Encrypted-Session Threat",
    "Recon/Port Scanning",
    "Data Exfiltration"
]

FEATURES = [
    "bytes","packets","duration","iat_mean",
    "dst_count","dns_length","dns_entropy","app_bytes"
]

class Detector:
    def __init__(self):
        self.rf = RandomForestClassifier(
            n_estimators=180,
            random_state=42,
            class_weight="balanced"
        )
        self.iso = IsolationForest(
            n_estimators=160,
            contamination=0.08,
            random_state=42
        )
        self.train()

    def train(self):
        rng = np.random.default_rng(42)
        centers = {
            "DDoS/Flooding": [1.5e6,9000,2,.001,40,0,0,1.4e6],
            "C2 Beaconing": [18000,80,30,.38,2,0,0,17000],
            "DGA/DNS Tunnelling": [35000,200,15,.08,20,75,4,12000],
            "Encrypted-Session Threat": [220000,1200,90,.075,4,0,3.2,205000],
            "Recon/Port Scanning": [45000,700,18,.025,180,0,0,42000],
            "Data Exfiltration": [8e6,2500,240,.09,3,0,0,7.5e6],
        }
        scales = [2e5,1300,.5,.0003,10,12,.35,2e5]
        X, y = [], []
        for threat in THREATS:
            for _ in range(350):
                X.append(np.maximum(rng.normal(centers[threat], scales), 0))
                y.append(threat)
        self.rf.fit(np.array(X), np.array(y))

        benign = np.column_stack([
            rng.normal(60000,18000,1000),
            rng.normal(350,90,1000),
            rng.normal(20,7,1000),
            rng.normal(.08,.025,1000),
            rng.normal(3,1.2,1000),
            np.zeros(1000),
            np.zeros(1000),
            rng.normal(55000,16000,1000)
        ])
        self.iso.fit(benign)

    def predict(self, row):
        x = np.array([[float(row.get(k,0) or 0) for k in FEATURES]])
        probs = self.rf.predict_proba(x)[0]
        idx = int(np.argmax(probs))
        threat = self.rf.classes_[idx]
        confidence = float(probs[idx])
        anomaly = self.iso.predict(x)[0] == -1

        if anomaly and confidence < 0.58:
            threat = "Anomalous Behaviour"
            model = "Isolation Forest"
            confidence = max(.60, min(.99, .72 + (.58-confidence)*.5))
        else:
            model = "Random Forest + Isolation Forest" if anomaly else "Random Forest"

        severity = (
            "Critical" if confidence >= .90 else
            "High" if confidence >= .75 else
            "Medium" if confidence >= .60 else
            "Low"
        )
        if threat in ("DDoS/Flooding","Data Exfiltration") and severity == "High":
            severity = "Critical"

        return (
            threat, severity, round(confidence*100,2),
            build_evidence(row, threat, anomaly),
            recommendation(threat), model
        )

def build_evidence(r, threat, anomaly):
    b = float(r.get("bytes",0) or 0)
    p = float(r.get("packets",0) or 0)
    iat = float(r.get("iat_mean",0) or 0)
    dst = float(r.get("dst_count",0) or 0)
    dns_len = float(r.get("dns_length",0) or 0)
    dns_ent = float(r.get("dns_entropy",0) or 0)

    evidence = {
        "DDoS/Flooding": f"High traffic volume: {b:,.0f} bytes / {p:,.0f} packets",
        "C2 Beaconing": f"Periodic communication pattern; mean inter-arrival time {iat:.3f}s",
        "DGA/DNS Tunnelling": f"High DNS length/entropy: {dns_len:.0f} chars, entropy {dns_ent:.2f}",
        "Encrypted-Session Threat": "TLS/QUIC behavioural metadata combined with an unusual flow profile",
        "Recon/Port Scanning": f"High destination fan-out: {dst:.0f} destinations",
        "Data Exfiltration": f"Large outbound application volume: {b:,.0f} bytes",
        "Anomalous Behaviour": "Behavioural profile differs from the learned benign baseline"
    }.get(threat, f"{p:,.0f} packets and {b:,.0f} bytes observed")

    if anomaly:
        evidence += " | Isolation Forest flagged anomalous behaviour"
    return evidence

def recommendation(threat):
    return {
        "DDoS/Flooding": "Review upstream rate controls, source concentration and edge filtering; escalate to the network team.",
        "C2 Beaconing": "Investigate the communicating host, periodicity and destination; correlate with endpoint/SOC telemetry.",
        "DGA/DNS Tunnelling": "Inspect DNS queries and domains; review DNS controls and investigate affected hosts.",
        "Encrypted-Session Threat": "Review TLS/QUIC metadata, destination reputation and endpoint context without decrypting payloads.",
        "Recon/Port Scanning": "Investigate source host and destination fan-out; review segmentation and access-control policy.",
        "Data Exfiltration": "Validate the transfer, destination and business context; review egress controls and incident-response procedures.",
        "Anomalous Behaviour": "Compare the flow with its normal baseline and correlate with other security telemetry."
    }.get(threat, "Investigate the flow and correlate with other security telemetry.")

def now():
    return datetime.now(timezone.utc).isoformat()

def normalize(row):
    d = dict(row)
    for key in FEATURES:
        try:
            d[key] = float(d.get(key,0) or 0)
        except Exception:
            d[key] = 0.0

    d["timestamp"] = d.get("timestamp") or now()
    d["protocol"] = d.get("protocol") or "TCP"

    raw = "|".join(str(d.get(k,"")) for k in [
        "src_ip","dst_ip","src_port","dst_port","protocol","bytes","packets","timestamp"
    ])
    d["flow_id"] = d.get("flow_id") or hashlib.sha256(raw.encode()).hexdigest()[:16]
    return d

def event_hash(e):
    raw = "|".join(str(e[k]) for k in [
        "timestamp","flow_id","threat","severity","confidence",
        "evidence","recommendation","model","prev_hash"
    ])
    return hashlib.sha256(raw.encode()).hexdigest()

def simulate_one(threat="random"):
    rng = random.Random()
    choices = ["benign"] + THREATS
    threat = rng.choice(choices) if threat == "random" else threat

    centers = {
        "benign": (60000,350,20,.08,3,0,0,55000),
        "DDoS/Flooding": (1500000,9000,2,.001,40,0,0,1400000),
        "C2 Beaconing": (18000,80,30,.38,2,0,0,17000),
        "DGA/DNS Tunnelling": (35000,200,15,.08,20,75,4,12000),
        "Encrypted-Session Threat": (220000,1200,90,.075,4,0,3.2,205000),
        "Recon/Port Scanning": (45000,700,18,.025,180,0,0,42000),
        "Data Exfiltration": (8000000,2500,240,.09,3,0,0,7500000)
    }[threat]

    c = centers
    d = {
        "src_ip": f"10.0.{rng.randint(1,20)}.{rng.randint(2,250)}",
        "dst_ip": f"10.1.{rng.randint(1,20)}.{rng.randint(2,250)}",
        "src_port": rng.randint(1024,65000),
        "dst_port": rng.choice([53,80,443,8080,22]),
        "protocol": "TCP",
        "bytes": max(1,rng.randint(int(c[0]*.85),int(c[0]*1.15))),
        "packets": max(1,rng.randint(int(c[1]*.85),int(c[1]*1.15))),
        "duration": max(.1,rng.uniform(c[2]*.85,c[2]*1.15)),
        "iat_mean": max(.0001,rng.uniform(c[3]*.85,c[3]*1.15)),
        "dst_count": max(1,rng.randint(max(1,int(c[4]*.8)),max(2,int(c[4]*1.2)))),
        "dns_length": max(0,rng.randint(max(0,int(c[5]*.8)),max(1,int(c[5]*1.2)))) if c[5] else 0,
        "dns_entropy": max(0,rng.uniform(max(0,c[6]-.3),c[6]+.3)) if c[6] else 0,
        "app_bytes": max(1,rng.randint(int(c[7]*.85),int(c[7]*1.15)))
    }
    return normalize(d)

detector = Detector()
