/* Radar: each blip is a real finding; distance from centre = severity (closer = worse). */
(function () {
  const form = document.getElementById("auditForm"), scan = document.getElementById("scan");
  if (form) form.addEventListener("submit", () => scan.classList.add("on"));
  const A = window.AUDIT, el = document.getElementById("radar");
  if (!A || !el) return;
  const R = {High: .3, Medium: .52, Low: .74, Informational: .92};
  const C = {High: "#ff4d3d", Medium: "#e0b04a", Low: "#3ee6d0", Informational: "#7e9a96"};
  let s = '<svg viewBox="-110 -110 220 220" role="img" aria-label="Radar of findings">';
  [.25, .5, .75, 1].forEach(r => s += `<circle r="${r * 100}" class="ring"/>`);
  s += '<line x1="-100" x2="100" class="ring"/><line y1="-100" y2="100" class="ring"/>';
  s += '<g class="sweep"><path d="M0 0 L100 0 A100 100 0 0 0 70.7 -70.7 Z"/></g>';
  A.findings.forEach((f, i) => {
    const a = i * 2.4, r = (R[f.severity] || .9) * 100;
    const t = f.title.replace(/&/g, "&amp;").replace(/</g, "&lt;");
    s += `<circle cx="${(r * Math.cos(a)).toFixed(1)}" cy="${(r * Math.sin(a)).toFixed(1)}" r="4.5" fill="${C[f.severity]}"><title>${t}</title></circle>`;
  });
  s += `<text class="score" y="12">${A.score == null ? "N/A" : A.score}</text></svg>`;
  el.innerHTML = s;
})();
