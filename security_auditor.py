"""Non-invasive audit: pinned-IP GET requests, manual redirect validation, evidence-based findings."""
import http.client, socket, ssl, time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse
from url_validator import validate_url, UnsafeTarget
from scoring import compute_score, risk_category

MAX_REDIRECTS, TIMEOUT = 5, 8
HEADERS = {
    "strict-transport-security": ("Medium", "HSTS missing", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "content-security-policy": ("Medium", "CSP missing", "Define a Content-Security-Policy restricting script sources."),
    "x-content-type-options": ("Low", "X-Content-Type-Options missing", "Set X-Content-Type-Options: nosniff"),
    "x-frame-options": ("Low", "X-Frame-Options missing", "Set X-Frame-Options: DENY or use CSP frame-ancestors."),
    "referrer-policy": ("Low", "Referrer-Policy missing", "Set Referrer-Policy: strict-origin-when-cross-origin"),
    "permissions-policy": ("Low", "Permissions-Policy missing", "Restrict browser features via Permissions-Policy."),
}

def fetch(p, ip):
    """One GET connected directly to the validated IP (no re-resolution); TLS verified against hostname."""
    port = p.port or (443 if p.scheme == "https" else 80)
    if p.scheme == "https":
        conn = http.client.HTTPSConnection(ip, port, timeout=TIMEOUT, context=ssl.create_default_context())
        def connect():
            s = socket.create_connection((ip, port), TIMEOUT)
            conn.sock = conn._context.wrap_socket(s, server_hostname=p.hostname)
        conn.connect = connect
    else:
        conn = http.client.HTTPConnection(ip, port, timeout=TIMEOUT)
    t = time.time()
    conn.request("GET", (p.path or "/") + ("?" + p.query if p.query else ""),
                 headers={"Host": p.netloc, "User-Agent": "WebsiteSecurityAuditor/1.0 (educational)"})
    r = conn.getresponse()
    cert = conn.sock.getpeercert() if p.scheme == "https" else None
    out = {"status": r.status, "headers": r.getheaders(), "ms": int((time.time() - t) * 1000), "cert": cert}
    conn.close()
    return out

def parse_cookie(raw):
    """Parse a Set-Cookie header into attributes only; the cookie VALUE is discarded."""
    parts = [x.strip() for x in raw.split(";")]
    attrs = {a.split("=")[0].lower(): (a.split("=", 1)[1] if "=" in a else True) for a in parts[1:]}
    return {"name": parts[0].split("=")[0], "secure": "secure" in attrs,
            "httponly": "httponly" in attrs, "samesite": attrs.get("samesite")}

def _f(fid, sev, title, evidence, url, fix):
    return {"id": fid, "severity": sev, "title": title, "evidence": evidence, "url": url, "remediation": fix,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "limitations": "Single GET request; CDN/WAF behaviour may differ per path."}

def analyze(resp, final_url, scheme):
    """Pure function: evidence -> (checks, findings). Easy to unit-test."""
    h = {}
    for k, v in resp["headers"]:
        h.setdefault(k.lower(), v)
    checks, findings = [], []
    for name, (sev, title, fix) in HEADERS.items():
        if name == "strict-transport-security" and scheme != "https":
            checks.append({"check": name, "status": "Not Assessed", "evidence": "Not served over HTTPS"}); continue
        ok = name in h
        checks.append({"check": name, "status": "Passed" if ok else "Finding", "evidence": h.get(name, "header absent")})
        if not ok:
            findings.append(_f("HDR-" + name, sev, title, "Header absent in response", final_url, fix))
    for k in ("server", "x-powered-by"):
        if k in h:
            checks.append({"check": k, "status": "Informational", "evidence": h[k]})
            findings.append(_f("INFO-" + k, "Informational", f"{k} discloses technology", f"{k}: {h[k]}", final_url,
                               "Remove or genericize version details."))
    for k, v in resp["headers"]:
        if k.lower() == "set-cookie":
            c = parse_cookie(v)
            for attr, sev in (("secure", "Medium"), ("httponly", "Medium"), ("samesite", "Low")):
                bad = not c[attr] if attr != "samesite" else c["samesite"] is None
                checks.append({"check": f"cookie:{c['name']}:{attr}", "status": "Finding" if bad else "Passed",
                               "evidence": f"{attr}={c[attr]}"})
                if bad:
                    findings.append(_f(f"CKE-{c['name']}-{attr}", sev, f"Cookie '{c['name']}' lacks {attr}",
                                       f"{attr} attribute missing", final_url, f"Set the {attr} attribute on the cookie."))
    if resp["status"] in (403, 429) or resp["status"] >= 500:
        checks.append({"check": "http-status", "status": "Informational", "evidence": f"HTTP {resp['status']}; results may be partial"})
    return checks, findings

def run_audit(url, validator=validate_url, fetcher=fetch):
    start = datetime.now(timezone.utc).isoformat()
    result = {"url": url, "started": start, "status": "completed", "checks": [], "findings": [], "redirects": []}
    try:
        cur, seen = url, set()
        for _ in range(MAX_REDIRECTS + 1):
            p, ips = validator(cur)          # every hop re-validated
            if cur in seen:
                raise UnsafeTarget("Redirect loop detected.")
            seen.add(cur)
            resp = fetcher(p, ips[0])
            loc = dict((k.lower(), v) for k, v in resp["headers"]).get("location")
            result["redirects"].append({"url": cur, "status": resp["status"]})
            if resp["status"] in (301, 302, 303, 307, 308) and loc:
                cur = urljoin(cur, loc); continue
            break
        else:
            raise UnsafeTarget("Too many redirects.")
        result["hostname"] = urlparse(cur).hostname
        result["duration_ms"] = resp["ms"]
        result["checks"], result["findings"] = analyze(resp, cur, p.scheme)
        if p.scheme == "https":
            try:  # probe plain HTTP once, without following redirects (host re-validated first)
                hp, hips = validator("http://" + p.netloc + "/")
                hr = fetcher(hp, hips[0])
                loc = dict((k.lower(), v) for k, v in hr["headers"]).get("location", "")
                ok = hr["status"] in (301, 302, 307, 308) and loc.startswith("https://")
                result["checks"].append({"check": "http-to-https-redirect", "status": "Passed" if ok else "Finding",
                                         "evidence": f"HTTP {hr['status']} Location={loc or 'none'}"})
                if not ok:
                    result["findings"].append(_f("TLS-redirect", "Medium", "HTTP is not redirected to HTTPS",
                        f"http:// returned {hr['status']}", "http://" + p.netloc + "/", "Redirect all HTTP traffic to HTTPS (301)."))
            except Exception:
                result["checks"].append({"check": "http-to-https-redirect", "status": "Not Assessed", "evidence": "HTTP port unreachable"})
            result["checks"].append({"check": "tls-certificate", "status": "Passed",
                                     "evidence": f"Verified; expires {resp['cert'].get('notAfter')}"})
        else:
            result["findings"].append(_f("TLS-none", "High", "Site not served over HTTPS", f"Final URL {cur}", cur,
                                         "Enable HTTPS and redirect HTTP to HTTPS."))
    except UnsafeTarget as e:
        result.update(status="blocked", error=str(e))
    except ssl.SSLCertVerificationError as e:
        result["findings"].append(_f("TLS-verify", "High", "TLS certificate verification failed", e.verify_message, url,
                                     "Install a valid certificate chain matching the hostname."))
    except (socket.timeout, TimeoutError):
        result.update(status="not_assessed", error="Connection timed out (not treated as a vulnerability).")
    except (OSError, http.client.HTTPException) as e:
        result.update(status="not_assessed", error=f"Connection failed: {type(e).__name__}")
    result.setdefault("hostname", urlparse(url).hostname)
    if result["status"] == "not_assessed":  # nothing was measured, so do not award a score
        result["score"], result["risk"] = None, "Not assessed"
    else:
        result["score"] = compute_score(result["findings"])
        result["risk"] = risk_category(result["score"])
    result["completed"] = datetime.now(timezone.utc).isoformat()
    return result
