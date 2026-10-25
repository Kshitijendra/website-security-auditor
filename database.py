import json, sqlite3
def connect(path="instance/audits.db"):
    c = sqlite3.connect(path); c.row_factory = sqlite3.Row
    c.execute("""CREATE TABLE IF NOT EXISTS audits(id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, hostname TEXT,
                 started TEXT, completed TEXT, status TEXT, score INTEGER, report TEXT)""")
    c.execute("CREATE INDEX IF NOT EXISTS idx_host ON audits(hostname)")
    return c
def save(c, r):
    cur = c.execute("INSERT INTO audits(url,hostname,started,completed,status,score,report) VALUES(?,?,?,?,?,?,?)",
                    (r["url"], r["hostname"], r["started"], r["completed"], r["status"], r["score"], json.dumps(r)))
    c.commit(); return cur.lastrowid
def get(c, i):
    row = c.execute("SELECT report,id FROM audits WHERE id=?", (i,)).fetchone()
    return None if row is None else {**json.loads(row["report"]), "id": row["id"]}
def history(c, q=""):
    return c.execute("SELECT id,url,hostname,completed,status,score FROM audits WHERE hostname LIKE ? OR url LIKE ? ORDER BY id DESC LIMIT 100",
                     (f"%{q}%", f"%{q}%")).fetchall()
def delete(c, i):
    c.execute("DELETE FROM audits WHERE id=?", (i,)); c.commit()

def stats(c):
    """Aggregate real history (last 50 audits) for the dashboard."""
    rows = c.execute("SELECT id,hostname,completed,status,score,report FROM audits ORDER BY id DESC LIMIT 50").fetchall()
    scores = [r["score"] for r in rows if r["score"] is not None]
    sev, top = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}, {}
    for r in rows:
        for f in json.loads(r["report"]).get("findings", []):
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
            top[f["title"]] = top.get(f["title"], 0) + 1
    return {"total": c.execute("SELECT COUNT(*) FROM audits").fetchone()[0],
            "avg": round(sum(scores) / len(scores)) if scores else None,
            "best": max(scores) if scores else None, "worst": min(scores) if scores else None,
            "sev": sev, "sevmax": max(sev.values()) or 1, "top": sorted(top.items(), key=lambda x: -x[1])[:5],
            "recent": rows[:8], "trend": list(reversed(scores[:12]))}
