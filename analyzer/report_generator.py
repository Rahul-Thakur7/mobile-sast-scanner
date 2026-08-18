import html
from datetime import datetime, timezone
from .masvs_catalog import MASVS_CATEGORIES, MOBILE_TOP10, SEVERITY_ORDER, SEVERITY_WEIGHT
from .common import Report

SEVERITY_COLOR = {
    "CRITICAL": "#ff3b3b",
    "HIGH":     "#ff8a3d",
    "MEDIUM":   "#f2c94c",
    "LOW":      "#5db8ff",
    "INFO":     "#8a94a6",
    "PASS":     "#37c977",
}


def _esc(s):
    return html.escape(str(s)) if s is not None else ""


def _risk_score(report: Report):
    score = 0
    for f in report.findings:
        score += SEVERITY_WEIGHT.get(f.severity, 0)
    return score


def _grade(score):
    if score >= 80:  return ("F", "#ff3b3b")
    if score >= 50:  return ("D", "#ff5f4d")
    if score >= 30:  return ("C", "#ff8a3d")
    if score >= 12:  return ("B", "#f2c94c")
    return ("A", "#37c977")


def generate_html_report(report: Report) -> str:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in report.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    score = _risk_score(report)
    grade, grade_color = _grade(score)

    # group findings by MASVS category, ordered by severity within category
    sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    by_cat = {cat: [] for cat in MASVS_CATEGORIES}
    for f in report.findings:
        by_cat.setdefault(f.category, []).append(f)
    for cat in by_cat:
        by_cat[cat].sort(key=lambda f: sev_rank.get(f.severity, 99))

    cat_status = {}
    for cat, items in by_cat.items():
        if not items:
            cat_status[cat] = ("EMPTY", "#3a4150")
            continue
        worst = min(items, key=lambda f: sev_rank.get(f.severity, 99)).severity
        cat_status[cat] = (worst, SEVERITY_COLOR.get(worst, "#3a4150"))

    # group by OWASP Mobile Top 10 (2024) category too
    by_top10 = {t: [] for t in MOBILE_TOP10}
    for f in report.findings:
        if f.top10:
            by_top10.setdefault(f.top10, []).append(f)
    top10_status = {}
    for t in MOBILE_TOP10:
        items = by_top10.get(t, [])
        if not items:
            top10_status[t] = ("EMPTY", "#3a4150")
            continue
        worst = min(items, key=lambda f: sev_rank.get(f.severity, 99)).severity
        top10_status[t] = (worst, SEVERITY_COLOR.get(worst, "#3a4150"))

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ---- build category sections ----
    sections_html = []
    for cat, label in MASVS_CATEGORIES.items():
        items = by_cat.get(cat, [])
        status, color = cat_status[cat]
        findings_html = ""
        if not items:
            findings_html = '<p class="empty-note">No automated checks produced findings in this category for this platform.</p>'
        else:
            for f in items:
                sev_color = SEVERITY_COLOR.get(f.severity, "#8a94a6")
                manual_tag = '<span class="tag manual">manual verification</span>' if f.manual else ""
                top10_tag = f'<span class="tag top10">{_esc(f.top10)}</span>' if f.top10 else ""
                evidence_html = ""
                if f.evidence:
                    evidence_html = f'<pre class="evidence">{_esc(f.evidence)}</pre>'
                rec_html = ""
                if f.recommendation:
                    rec_html = f'<div class="rec"><span class="rec-label">Recommendation</span>{_esc(f.recommendation)}</div>'
                findings_html += f"""
                <div class="finding" style="--sev-color:{sev_color}">
                  <div class="finding-head">
                    <span class="sev-chip" style="background:{sev_color}">{f.severity}</span>
                    <span class="finding-title">{_esc(f.title)}</span>
                    {top10_tag}
                    {manual_tag}
                    <span class="check-id">{_esc(f.check_id)}</span>
                  </div>
                  <p class="finding-desc">{_esc(f.description)}</p>
                  {evidence_html}
                  {rec_html}
                  <p class="mastg-ref">{_esc(f.mastg_ref)}</p>
                </div>
                """
        sections_html.append(f"""
        <section class="category" id="cat-{cat.lower()}">
          <div class="category-head">
            <div class="cat-index" style="color:{color}">{'\u25CF' if status not in ('EMPTY',) else '\u25CB'}</div>
            <div>
              <h2>{_esc(cat)}</h2>
              <p class="cat-desc">{_esc(label)}</p>
            </div>
            <div class="cat-status" style="border-color:{color};color:{color}">{status}</div>
          </div>
          {findings_html}
        </section>
        """)

    matrix_cells = ""
    for cat in MASVS_CATEGORIES:
        status, color = cat_status[cat]
        matrix_cells += f'<a href="#cat-{cat.lower()}" class="matrix-cell" style="--c:{color}"><span class="mc-name">{cat}</span><span class="mc-status">{status}</span></a>'

    top10_cells = ""
    for t, label in MOBILE_TOP10.items():
        status, color = top10_status[t]
        top10_cells += (f'<div class="matrix-cell" style="--c:{color}">'
                         f'<span class="mc-name">{t} · {_esc(label)}</span><span class="mc-status">{status}</span></div>')

    sev_bars = ""
    total_findings = max(sum(counts.values()), 1)
    for sev in SEVERITY_ORDER:
        n = counts.get(sev, 0)
        pct = round(100 * n / total_findings, 1)
        sev_bars += f"""
        <div class="sev-row">
          <span class="sev-label" style="color:{SEVERITY_COLOR[sev]}">{sev}</span>
          <div class="sev-track"><div class="sev-fill" style="width:{pct}%;background:{SEVERITY_COLOR[sev]}"></div></div>
          <span class="sev-count">{n}</span>
        </div>"""

    permissions_html = ""
    if report.permissions:
        chips = "".join(f'<span class="perm-chip">{_esc(p.split(".")[-1])}</span>' for p in sorted(report.permissions))
        permissions_html = f'<div class="permissions"><h3>Declared permissions ({len(report.permissions)})</h3><div class="chips">{chips}</div></div>'

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Mobile AppSec Audit — {_esc(report.app_name)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Fraunces:opsz,wght@9..144,500;9..144,600;9..144,700&family=Inter:wght@400;500;600&display=swap');

  :root {{
    --bg: #0d1117;
    --bg-panel: #131a24;
    --bg-panel-2: #171f2b;
    --line: #232d3d;
    --ink: #e7ecf3;
    --ink-dim: #8b96a8;
    --accent: #37c977;
    --mono: 'JetBrains Mono', ui-monospace, monospace;
    --serif: 'Fraunces', Georgia, serif;
    --sans: 'Inter', -apple-system, sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--ink);
    font-family: var(--sans); line-height: 1.55;
  }}
  a {{ color: inherit; }}

  .cover {{
    position: relative; padding: 72px 48px 56px;
    background:
      radial-gradient(1200px 500px at 85% -10%, rgba(55,201,119,0.10), transparent 60%),
      linear-gradient(180deg, #0b0f16, var(--bg));
    border-bottom: 1px solid var(--line);
  }}
  .eyebrow {{
    font-family: var(--mono); font-size: 12px; letter-spacing: 0.16em; text-transform: uppercase;
    color: var(--accent); display:flex; gap:10px; align-items:center; margin-bottom: 18px;
  }}
  .eyebrow::before {{ content:''; width:7px; height:7px; border-radius:50%; background:var(--accent); box-shadow:0 0 12px var(--accent); }}
  h1.title {{
    font-family: var(--serif); font-weight: 600; font-size: 46px; letter-spacing: -0.01em;
    margin: 0 0 6px; max-width: 900px;
  }}
  .subtitle {{ color: var(--ink-dim); font-size: 15px; font-family: var(--mono); }}

  .cover-grid {{
    display:grid; grid-template-columns: 1fr auto; gap: 32px; align-items: end; margin-top: 40px;
  }}
  .meta-table {{ display:grid; grid-template-columns: repeat(4, auto); gap: 22px 40px; font-family: var(--mono); font-size: 13px; }}
  .meta-table div span.k {{ display:block; color: var(--ink-dim); font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 4px; }}
  .meta-table div span.v {{ color: var(--ink); font-size: 14px; word-break: break-all; }}

  .grade-badge {{
    width: 118px; height: 118px; border-radius: 50%; border: 3px solid {grade_color};
    display:flex; flex-direction:column; align-items:center; justify-content:center;
    font-family: var(--serif); flex-shrink:0;
    background: radial-gradient(circle at 30% 20%, rgba(255,255,255,0.05), transparent 70%);
  }}
  .grade-badge .g {{ font-size: 44px; font-weight:700; color:{grade_color}; line-height:1; }}
  .grade-badge .l {{ font-family: var(--mono); font-size: 9px; color: var(--ink-dim); letter-spacing:0.1em; margin-top:6px; }}

  .body-wrap {{ max-width: 1080px; margin: 0 auto; padding: 48px; }}

  .panel {{ background: var(--bg-panel); border: 1px solid var(--line); border-radius: 10px; padding: 28px; margin-bottom: 28px; }}
  .panel h2, .panel h3 {{ font-family: var(--serif); font-weight:600; margin-top:0; }}

  .summary-grid {{ display:grid; grid-template-columns: 1.1fr 1fr; gap: 24px; }}
  @media (max-width: 800px) {{ .summary-grid {{ grid-template-columns: 1fr; }} .cover-grid{{grid-template-columns:1fr;}} .meta-table{{grid-template-columns:repeat(2,auto);}} }}

  .sev-row {{ display:grid; grid-template-columns: 90px 1fr 30px; align-items:center; gap: 12px; margin-bottom: 10px; font-family: var(--mono); font-size: 12px; }}
  .sev-track {{ height: 8px; background: var(--bg-panel-2); border-radius: 4px; overflow:hidden; }}
  .sev-fill {{ height: 100%; border-radius: 4px; }}
  .sev-count {{ text-align:right; color: var(--ink-dim); }}

  .matrix {{ display:grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }}
  @media (max-width: 700px) {{ .matrix {{ grid-template-columns: repeat(2, 1fr); }} }}
  .top10-matrix {{ grid-template-columns: repeat(2, 1fr); }}
  @media (max-width: 700px) {{ .top10-matrix {{ grid-template-columns: 1fr; }} }}
  .matrix-cell {{
    text-decoration:none; border: 1px solid var(--line); border-left: 3px solid var(--c);
    background: var(--bg-panel-2); border-radius: 6px; padding: 12px 14px; display:flex; flex-direction:column; gap:4px;
    transition: transform .15s ease, border-color .15s ease;
  }}
  .matrix-cell:hover {{ transform: translateY(-2px); border-color: var(--c); }}
  .mc-name {{ font-family: var(--mono); font-size: 11px; color: var(--ink-dim); letter-spacing:0.05em; }}
  .mc-status {{ font-family: var(--mono); font-size: 13px; font-weight:600; color: var(--c); }}

  .permissions .chips {{ display:flex; flex-wrap:wrap; gap:6px; margin-top:10px; }}
  .perm-chip {{ font-family: var(--mono); font-size: 11px; padding: 4px 9px; background: var(--bg-panel-2); border:1px solid var(--line); border-radius: 20px; color: var(--ink-dim); }}

  .category {{ border-top: 1px solid var(--line); padding-top: 32px; margin-top: 32px; }}
  .category-head {{ display:grid; grid-template-columns: 28px 1fr auto; align-items:start; gap: 14px; margin-bottom: 18px; }}
  .cat-index {{ font-size: 20px; line-height:1; margin-top:4px; }}
  .category h2 {{ font-family: var(--serif); font-size: 24px; margin: 0; }}
  .cat-desc {{ color: var(--ink-dim); font-size: 13px; margin: 4px 0 0; }}
  .cat-status {{ font-family: var(--mono); font-size: 11px; border: 1px solid; border-radius: 20px; padding: 5px 12px; height: fit-content; letter-spacing:0.05em; }}

  .finding {{ background: var(--bg-panel); border: 1px solid var(--line); border-left: 3px solid var(--sev-color); border-radius: 8px; padding: 18px 20px; margin-bottom: 14px; }}
  .finding-head {{ display:flex; align-items:center; gap: 10px; flex-wrap:wrap; margin-bottom: 8px; }}
  .sev-chip {{ font-family: var(--mono); font-size: 10px; font-weight:700; color:#0b0f16; padding: 3px 8px; border-radius: 4px; letter-spacing:0.04em; }}
  .finding-title {{ font-weight: 600; font-size: 14.5px; }}
  .tag.manual {{ font-family: var(--mono); font-size: 10px; color: #d9a441; border: 1px solid #453b22; background: #241d10; padding: 2px 8px; border-radius: 4px; }}
  .tag.top10 {{ font-family: var(--mono); font-size: 10px; color: #7ea6ff; border: 1px solid #1f3358; background: #101c30; padding: 2px 8px; border-radius: 4px; font-weight:700; }}
  .check-id {{ margin-left: auto; font-family: var(--mono); font-size: 11px; color: var(--ink-dim); }}
  .finding-desc {{ font-size: 13.5px; color: #c3cad6; margin: 6px 0; }}
  .evidence {{ background: #0a0e14; border: 1px solid var(--line); border-radius: 6px; padding: 10px 12px; font-family: var(--mono); font-size: 11.5px; color: #9fe6b8; white-space: pre-wrap; word-break: break-word; margin: 10px 0; }}
  .rec {{ font-size: 13px; color: var(--ink-dim); margin-top: 8px; }}
  .rec-label {{ font-family: var(--mono); font-size: 10px; text-transform:uppercase; letter-spacing:0.06em; color: var(--accent); display:block; margin-bottom: 3px; }}
  .mastg-ref {{ font-family: var(--mono); font-size: 10.5px; color: #4a5568; margin: 10px 0 0; }}
  .empty-note {{ color: var(--ink-dim); font-size: 13px; font-style: italic; }}

  footer {{ max-width: 1080px; margin: 0 auto; padding: 20px 48px 60px; color: var(--ink-dim); font-family: var(--mono); font-size: 11.5px; border-top: 1px solid var(--line); }}
  footer p {{ margin: 6px 0; }}
</style>
</head>
<body>

<div class="cover">
  <div class="eyebrow">Static Application Security Testing · Mobile</div>
  <h1 class="title">{_esc(report.app_name)}</h1>
  <div class="subtitle">{_esc(report.package_id)} · v{_esc(report.version)} · {_esc(report.platform)}</div>

  <div class="cover-grid">
    <div class="meta-table">
      <div><span class="k">File</span><span class="v">{_esc(report.file_name)}</span></div>
      <div><span class="k">Size</span><span class="v">{report.file_size/1024/1024:.2f} MB</span></div>
      <div><span class="k">SHA-256</span><span class="v">{_esc(report.sha256[:24])}…</span></div>
      <div><span class="k">Generated</span><span class="v">{generated_at}</span></div>
      <div><span class="k">Min OS</span><span class="v">{_esc(report.min_os)}</span></div>
      <div><span class="k">Target OS</span><span class="v">{_esc(report.target_os)}</span></div>
      <div><span class="k">Findings</span><span class="v">{len(report.findings)} checks run</span></div>
      <div><span class="k">Methodology</span><span class="v">OWASP MASVS 2.x / MASTG</span></div>
    </div>
    <div class="grade-badge"><span class="g">{grade}</span><span class="l">RISK GRADE</span></div>
  </div>
</div>

<div class="body-wrap">

  <div class="panel">
    <div class="summary-grid">
      <div>
        <h2>Severity distribution</h2>
        {sev_bars}
      </div>
      <div>
        <h2>MASVS coverage matrix</h2>
        <div class="matrix">{matrix_cells}</div>
      </div>
    </div>
  </div>

  <div class="panel">
    <h2>OWASP Mobile Top 10 (2024) coverage</h2>
    <p style="color:var(--ink-dim);font-size:13px;margin-top:-6px;">Each finding below is tagged with its corresponding Top‑10 category (e.g. <span class="tag top10">M9</span>).</p>
    <div class="matrix top10-matrix">{top10_cells}</div>
  </div>

  {f'<div class="panel">{permissions_html}</div>' if permissions_html else ''}

  <div class="panel" style="border-color:#453b22;background:#171308;">
    <h3 style="color:#d9a441;">Scope &amp; methodology note</h3>
    <p style="font-size:13px;color:#c3b590;margin:0;">
      This report was produced by fully <strong>automated static analysis</strong> of the submitted package
      (manifest/plist parsing, binary header inspection, and string/pattern matching), mapped to OWASP MASVS
      categories and informed by the OWASP MASTG methodology. It is a triage aid, not a substitute for a full
      manual + dynamic penetration test: findings tagged <span class="tag manual">manual verification</span>
      require confirmation on a real device/emulator (runtime behavior, actual network traffic, business-logic
      and auth-flow testing, and tamper/bypass testing cannot be fully verified from the package alone).
      Some findings may be false positives — verify before remediating.
    </p>
  </div>

  {''.join(sections_html)}

</div>

<footer>
  <p>Generated by MASTG-Scan · static analysis engine · mapped to OWASP MASVS 2.x / OWASP MASTG</p>
  <p>Report is confidential — intended for the app owner and authorized security reviewers only.</p>
</footer>

</body>
</html>"""
    return html_doc
