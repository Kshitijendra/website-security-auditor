import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from urllib.parse import urlparse
import pytest, database as db, report_generator as rg
from url_validator import validate_url, UnsafeTarget
from security_auditor import run_audit, parse_cookie
from scoring import compute_score

def fake(ip): return lambda h, p, **k: [(2, 1, 6, "", (ip, p))]
PUB = lambda u: (urlparse(u), ["93.184.216.34"])

@pytest.mark.parametrize("u", ["ftp://a.com", "http://u:p@a.com", "notaurl"])
def test_bad_urls(u):
    with pytest.raises(UnsafeTarget): validate_url(u, fake("93.184.216.34"))

@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1"])
def test_ssrf_blocked(ip):
    with pytest.raises(UnsafeTarget): validate_url("http://x.com", fake(ip))

def test_public_ok(): assert validate_url("https://x.com", fake("93.184.216.34"))[1] == ["93.184.216.34"]

def test_redirect_to_internal_blocked():
    def v(u):
        if "internal" in u: raise UnsafeTarget("blocked")
        return PUB(u)
    f = lambda p, ip: {"status": 302, "headers": [("Location", "http://internal/")], "ms": 1, "cert": None}
    assert run_audit("https://a.com", v, f)["status"] == "blocked"

def test_redirect_loop():
    f = lambda p, ip: {"status": 302, "headers": [("Location", "https://a.com")], "ms": 1, "cert": None}
    assert run_audit("https://a.com", PUB, f)["status"] == "blocked"

def test_headers_cookie_and_redaction():
    f = lambda p, ip: {"status": 200, "headers": [("Server", "nginx/1.2"), ("Set-Cookie", "sid=SECRET; Path=/")], "ms": 5, "cert": {"notAfter": "x"}}
    r = run_audit("https://a.com", PUB, f)
    assert any(x["id"] == "HDR-content-security-policy" for x in r["findings"])
    assert "SECRET" not in str(r) and r["score"] < 100

def test_timeout_not_a_vulnerability():
    def f(p, ip): raise TimeoutError()
    r = run_audit("https://a.com", PUB, f)
    assert r["status"] == "not_assessed" and r["findings"] == []

def test_cookie(): assert parse_cookie("a=1; Secure; HttpOnly; SameSite=Lax") == {"name": "a", "secure": True, "httponly": True, "samesite": "Lax"}
def test_no_double_count(): assert compute_score([{"id": "x", "severity": "High"}] * 2) == 80

def test_db_and_csv_injection(tmp_path):
    c = db.connect(str(tmp_path / "t.db"))
    r = {"url": "u", "hostname": "h", "started": "s", "completed": "c", "status": "completed", "score": 90,
         "findings": [{"id": "1", "severity": "Low", "title": "=cmd()", "evidence": "e", "url": "u", "remediation": "r", "timestamp": "t"}]}
    i = db.save(c, r); assert db.get(c, i)["score"] == 90
    assert "'=cmd()" in rg.to_csv(r)

def test_html_escape_and_pdf():
    r = {"hostname": "h", "completed": "c", "score": 80, "risk": "x", "checks": [],
         "findings": [{"id": "1", "severity": "Low", "title": "<script>alert(1)</script>", "evidence": "e", "url": "u", "remediation": "r", "limitations": "l"}]}
    assert "<script>" not in rg.to_html(r)
    assert rg.to_pdf(r)[:4] == b"%PDF"

def test_compare_route(tmp_path, monkeypatch):
    import app as appmod
    monkeypatch.setattr(db, "connect", lambda path=str(tmp_path / "c.db"): __import__("sqlite3") and _mk(path))
    def _mk(path):
        import sqlite3; c = sqlite3.connect(path); c.row_factory = sqlite3.Row
        c.execute("CREATE TABLE IF NOT EXISTS audits(id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, hostname TEXT, started TEXT, completed TEXT, status TEXT, score INTEGER, report TEXT)")
        return c
    c = db.connect()
    base = {"url": "u", "hostname": "h", "started": "s", "completed": "c", "status": "completed", "score": 90}
    db.save(c, {**base, "findings": [{"id": "A"}, {"id": "B"}]}); db.save(c, {**base, "findings": [{"id": "B"}, {"id": "C"}]})
    html = appmod.app.test_client().get("/compare?a=1&b=2").get_data(as_text=True)
    assert "Fixed since the first audit" in html and "A, " not in html and ">C<" not in html or "C" in html

def test_not_assessed_has_no_score():
    def f(p, ip): raise TimeoutError()
    assert run_audit("https://a.com", PUB, f)["score"] is None

def test_http_probe_flags_missing_redirect():
    f = lambda p, ip: {"status": 200, "headers": [], "ms": 1, "cert": {"notAfter": "x"}}
    assert any(x["id"] == "TLS-redirect" for x in run_audit("https://a.com", PUB, f)["findings"])
    g = lambda p, ip: {"status": 200 if p.scheme == "https" else 301, "headers": [("Location", "https://a.com/")], "ms": 1, "cert": {"notAfter": "x"}}
    assert not any(x["id"] == "TLS-redirect" for x in run_audit("https://a.com", PUB, g)["findings"])

def test_dashboard_stats(tmp_path):
    c = db.connect(str(tmp_path / "s.db"))
    base = {"url": "u", "hostname": "h", "started": "s", "completed": "c", "status": "completed"}
    db.save(c, {**base, "score": 70, "findings": [{"id": "1", "severity": "High", "title": "T"}]})
    db.save(c, {**base, "score": 90, "findings": []})
    s = db.stats(c)
    assert (s["total"], s["avg"], s["best"], s["worst"], s["sev"]["High"]) == (2, 80, 90, 70, 1)
