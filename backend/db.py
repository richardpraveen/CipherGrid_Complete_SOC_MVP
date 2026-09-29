import sqlite3, os

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "ciphergrid.db")

def connect():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = connect()
    db.execute("""CREATE TABLE IF NOT EXISTS events(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, flow_id TEXT, threat TEXT, severity TEXT,
        confidence REAL, evidence TEXT, recommendation TEXT,
        model TEXT, prev_hash TEXT, event_hash TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS flows(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, flow_id TEXT, src_ip TEXT, dst_ip TEXT,
        protocol TEXT, bytes REAL, packets REAL, duration REAL,
        iat_mean REAL, dst_count REAL, dns_length REAL,
        dns_entropy REAL, app_bytes REAL, threat TEXT, confidence REAL)""")
    db.commit()
    db.close()

def add_flow(row):
    keys = ["timestamp","flow_id","src_ip","dst_ip","protocol","bytes",
            "packets","duration","iat_mean","dst_count","dns_length",
            "dns_entropy","app_bytes","threat","confidence"]
    db = connect()
    db.execute(
        "INSERT INTO flows (" + ",".join(keys) + ") VALUES (" +
        ",".join(["?"]*len(keys)) + ")",
        [row.get(k) for k in keys])
    db.commit()
    db.close()

def add_event(e):
    keys = ["timestamp","flow_id","threat","severity","confidence",
            "evidence","recommendation","model","prev_hash","event_hash"]
    db = connect()
    db.execute(
        "INSERT INTO events (" + ",".join(keys) + ") VALUES (" +
        ",".join(["?"]*len(keys)) + ")",
        [e[k] for k in keys])
    db.commit()
    db.close()

def get_events(limit=100):
    db = connect()
    rows = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

def get_flows(limit=100):
    db = connect()
    rows = db.execute("SELECT * FROM flows ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

def get_stats():
    db = connect()
    result = {
        "alerts": db.execute("SELECT COUNT(*) n FROM events").fetchone()["n"],
        "critical": db.execute("SELECT COUNT(*) n FROM events WHERE severity='Critical'").fetchone()["n"],
        "high": db.execute("SELECT COUNT(*) n FROM events WHERE severity='High'").fetchone()["n"],
        "medium": db.execute("SELECT COUNT(*) n FROM events WHERE severity='Medium'").fetchone()["n"],
        "flows": db.execute("SELECT COUNT(*) n FROM flows").fetchone()["n"],
        "threats": [dict(x) for x in db.execute(
            "SELECT threat, COUNT(*) n FROM events GROUP BY threat ORDER BY n DESC"
        ).fetchall()]
    }
    db.close()
    return result
