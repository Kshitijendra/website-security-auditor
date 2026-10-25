from flask import Flask, Response, abort, redirect, render_template, request, url_for
import database as db, report_generator as rg
from security_auditor import run_audit
app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html", error=None)

@app.post("/audit")
def audit():
    r = run_audit(request.form.get("url", ""))
    if r["status"] == "blocked":
        return render_template("index.html", error=r["error"]), 400
    return redirect(url_for("view", audit_id=db.save(db.connect(), r)))

@app.route("/audit/<int:audit_id>")
def view(audit_id):
    r = db.get(db.connect(), audit_id) or abort(404)
    return render_template("result.html", result=r)

@app.route("/insights")
def insights():
    return render_template("insights.html", stats=db.stats(db.connect()))

@app.route("/history")
def history():
    return render_template("history.html", rows=db.history(db.connect(), request.args.get("q", "")))

@app.post("/delete/<int:audit_id>")
def delete(audit_id):
    if request.form.get("confirm") == "yes":
        db.delete(db.connect(), audit_id)
    return redirect(url_for("history"))

@app.route("/report/<int:audit_id>.<fmt>")
def report(audit_id, fmt):
    r = db.get(db.connect(), audit_id) or abort(404)
    if fmt == "json": return Response(rg.to_json(r), mimetype="application/json", headers={"Content-Disposition": "attachment; filename=audit.json"})
    if fmt == "csv": return Response(rg.to_csv(r), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=audit.csv"})
    if fmt == "html": return Response(rg.to_html(r), mimetype="text/html")
    if fmt == "pdf":
        try: return Response(rg.to_pdf(r), mimetype="application/pdf", headers={"Content-Disposition": "attachment; filename=audit.pdf"})
        except Exception: return render_template("index.html", history=[], result=None, error="PDF generation failed."), 500
    abort(404)

@app.route("/compare")
def compare():
    c = db.connect()
    a, b = db.get(c, request.args.get("a", type=int) or 0), db.get(c, request.args.get("b", type=int) or 0)
    if not a or not b or a["hostname"] != b["hostname"]:
        return render_template("index.html", history=[], result=None, error="Pick two audits of the same hostname."), 400
    ia, ib = {f["id"] for f in a["findings"]}, {f["id"] for f in b["findings"]}
    return render_template("compare.html", a=a, b=b, fixed=sorted(ia - ib), new=sorted(ib - ia), same=sorted(ia & ib))

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
