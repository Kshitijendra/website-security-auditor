import csv, io, json
def _safe(v):  # CSV formula-injection guard
    v = str(v); return "'" + v if v[:1] in "=+-@\t\r" else v
def to_json(r): return json.dumps(r, indent=2)
def to_csv(r):
    o = io.StringIO(); w = csv.writer(o)
    w.writerow(["id", "severity", "title", "evidence", "url", "remediation", "timestamp"])
    for f in r["findings"]:
        w.writerow([_safe(f[k]) for k in ("id", "severity", "title", "evidence", "url", "remediation", "timestamp")])
    return o.getvalue()

from html import escape
from xml.sax.saxutils import escape as xesc
def to_html(r):
    """Printable report; every untrusted value is HTML-escaped."""
    rows = "".join(f"<h3>[{escape(f['severity'])}] {escape(f['title'])}</h3><p>Evidence: {escape(str(f['evidence']))}<br>"
                   f"URL: {escape(f['url'])}<br>Fix: {escape(f['remediation'])}<br>Limitations: {escape(f['limitations'])}</p>" for f in r["findings"])
    chk = "".join(f"<tr><td>{escape(c['check'])}</td><td>{escape(c['status'])}</td><td>{escape(str(c['evidence']))}</td></tr>" for c in r["checks"])
    return (f"<html><body style='font-family:sans-serif'><h1>Security Audit: {escape(r['hostname'] or '')}</h1>"
            f"<p>Time: {escape(r['completed'])} | Score: {r['score']}/100 (educational score) | {escape(r['risk'])}</p>"
            f"<h2>Checks performed</h2><table border=1 cellpadding=4>{chk}</table><h2>Findings</h2>{rows or 'None'}</body></html>")
def to_pdf(r):
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    s, buf = getSampleStyleSheet(), io.BytesIO()
    items = [Paragraph(f"Security Audit: {xesc(str(r['hostname']))}", s["Title"]),
             Paragraph(f"Score {r['score']}/100 (educational) - {xesc(r['risk'])} - {xesc(r['completed'])}", s["Normal"])]
    for f in r["findings"]:
        items += [Spacer(1, 8), Paragraph(f"<b>[{xesc(f['severity'])}] {xesc(f['title'])}</b>", s["Normal"]),
                  Paragraph(f"Evidence: {xesc(str(f['evidence']))}<br/>Fix: {xesc(f['remediation'])}<br/>Limitations: {xesc(f['limitations'])}", s["Normal"])]
    SimpleDocTemplate(buf).build(items)
    return buf.getvalue()
