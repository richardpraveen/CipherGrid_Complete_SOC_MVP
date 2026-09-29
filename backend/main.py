import csv, io, os, hashlib
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .db import init_db, connect, add_flow, add_event, get_events, get_flows, get_stats
from .detector import detector, normalize, simulate_one, event_hash

app = FastAPI(title="CipherGrid SOC API", version="1.0")
init_db()

BASE = os.path.join(os.path.dirname(__file__), "..")
app.mount("/static", StaticFiles(directory=os.path.join(BASE,"frontend")), name="static")

@app.get("/")
def home():
    return FileResponse(os.path.join(BASE,"frontend","index.html"))

def process_flow(row):
    r = normalize(row)
    threat, severity, confidence, evidence, recommendation, model = detector.predict(r)
    r.update(threat=threat, confidence=confidence)
    add_flow(r)

    db = connect()
    previous = db.execute("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
    db.close()
    prev_hash = previous["event_hash"] if previous else "GENESIS"

    event = {
        "timestamp": r["timestamp"],
        "flow_id": r["flow_id"],
        "threat": threat,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "recommendation": recommendation,
        "model": model,
        "prev_hash": prev_hash
    }
    event["event_hash"] = event_hash(event)
    add_event(event)
    return event

@app.get("/api/stats")
def stats():
    return get_stats()

@app.get("/api/events")
def events(limit:int=100):
    return get_events(min(500,max(1,limit)))

@app.get("/api/flows")
def flows(limit:int=100):
    return get_flows(min(500,max(1,limit)))

@app.post("/api/simulate")
def simulate(payload:dict):
    threat = payload.get("threat","random")
    count = min(50,max(1,int(payload.get("count",5))))
    result = [process_flow(simulate_one(threat)) for _ in range(count)]
    return {"created":len(result),"events":result}

@app.post("/api/upload-csv")
async def upload_csv(file:UploadFile=File(...)):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(400,"Please upload a CSV flow file.")
    data = (await file.read()).decode("utf-8-sig",errors="replace")
    result=[]
    for row in csv.DictReader(io.StringIO(data)):
        if row.get("src_ip") and row.get("dst_ip"):
            result.append(process_flow(row))
    return {"created":len(result),"events":result}

@app.post("/api/upload-pcap")
async def upload_pcap(file:UploadFile=File(...)):
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except Exception:
        raise HTTPException(501,"PCAP support is optional. Run: pip install scapy")

    data = await file.read()
    path = os.path.join(BASE,"upload_temp.pcap")
    with open(path,"wb") as f:
        f.write(data)

    try:
        packets = rdpcap(path)
    except Exception as exc:
        if os.path.exists(path): os.remove(path)
        raise HTTPException(400,f"Could not parse PCAP: {exc}")

    os.remove(path)
    flows={}
    for packet in packets:
        if IP not in packet:
            continue
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
        sport = int(packet[TCP].sport) if TCP in packet else int(packet[UDP].sport) if UDP in packet else 0
        dport = int(packet[TCP].dport) if TCP in packet else int(packet[UDP].dport) if UDP in packet else 0
        key=(packet[IP].src,packet[IP].dst,sport,dport,protocol)
        ts=float(packet.time)
        f=flows.setdefault(key,{
            "src_ip":packet[IP].src,"dst_ip":packet[IP].dst,
            "src_port":sport,"dst_port":dport,"protocol":protocol,
            "bytes":0,"packets":0,"first":ts,"last":ts,"times":[]
        })
        f["bytes"] += len(packet)
        f["packets"] += 1
        f["last"] = ts
        f["times"].append(ts)

    result=[]
    for f in flows.values():
        diffs=[f["times"][i]-f["times"][i-1] for i in range(1,len(f["times"]))]
        f["duration"]=f["last"]-f["first"]
        f["iat_mean"]=sum(diffs)/len(diffs) if diffs else 0
        f["dst_count"]=1
        f["dns_length"]=0
        f["dns_entropy"]=0
        f["app_bytes"]=f["bytes"]
        result.append(process_flow(f))
    return {"created":len(result),"events":result}

@app.get("/api/verify-ledger")
def verify_ledger():
    db=connect()
    rows=db.execute("SELECT * FROM events ORDER BY id").fetchall()
    db.close()

    previous="GENESIS"
    broken=[]
    for row in rows:
        event={k:row[k] for k in [
            "timestamp","flow_id","threat","severity","confidence",
            "evidence","recommendation","model","prev_hash"
        ]}
        expected=event_hash(event)
        if row["prev_hash"] != previous or row["event_hash"] != expected:
            broken.append(row["id"])
        previous=row["event_hash"]

    return {
        "valid": not broken,
        "events_checked": len(rows),
        "broken_event_ids": broken
    }
