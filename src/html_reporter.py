from __future__ import annotations

import json
from pathlib import Path
from typing import List

from finding import Finding


_SEV_COLORS = {"high": "#E24B4A", "medium": "#BA7517", "low": "#639922"}
_CHECK_COLORS = {
    "auth": "#378ADD",
    "bola": "#7F77DD",
    "method_exposure": "#D85A30",
    "error_leak": "#D4537E",
    "token_lifecycle": "#1D9E75",
}
_CHECK_LABELS = {
    "auth": "Auth",
    "bola": "BOLA",
    "method_exposure": "Method exposure",
    "error_leak": "Error leak",
    "token_lifecycle": "Token lifecycle",
}


class HtmlReporter:
    """
    Generates a self-contained HTML dashboard from a list of Finding objects.

    Usage:
        reporter = HtmlReporter(findings)
        reporter.write("report.html")      # write to disk
        html = reporter.render()           # get the HTML string directly
    """

    def __init__(self, findings: List[Finding]) -> None:
        self.findings = findings

    def write(self, output_path: str) -> None:
        Path(output_path).write_text(self.render(), encoding="utf-8")

    def render(self) -> str:
        sev_colors_json   = json.dumps(_SEV_COLORS)
        check_colors_json = json.dumps(_CHECK_COLORS)
        check_labels_json = json.dumps(_CHECK_LABELS)

        findings_json = json.dumps(
            [
                {
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "endpoint": f.endpoint,
                    "auth_context": f.auth_context or "",
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                }
                for f in self.findings
            ],
            ensure_ascii=False,
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>endpwnt scan report</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{ font-family: system-ui, sans-serif; background: #f5f5f3; color: #1a1a18; margin: 0; padding: 2rem 1rem; }}
  h1 {{ font-size: 20px; font-weight: 500; margin: 0 0 1.5rem; }}
  .metric-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 1.5rem; }}
  .metric {{ background: #fff; border: 0.5px solid rgba(0,0,0,0.1); border-radius: 8px; padding: 0.85rem 1rem; }}
  .metric-label {{ font-size: 12px; color: #666; margin: 0 0 4px; }}
  .metric-value {{ font-size: 22px; font-weight: 500; margin: 0; }}
  .charts-row {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 1.5rem; }}
  .chart-card {{ background: #fff; border: 0.5px solid rgba(0,0,0,0.1); border-radius: 12px; padding: 1rem 1.25rem; }}
  .chart-title {{ font-size: 13px; color: #666; margin: 0 0 12px; font-weight: 500; }}
  .legend {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 10px; font-size: 12px; color: #555; }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 2px; display: inline-block; margin-right: 4px; vertical-align: middle; }}
  .ep-bar-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; font-size: 12px; }}
  .ep-label {{ width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex-shrink: 0; }}
  .ep-bar-bg {{ flex: 1; background: #f0efeb; border-radius: 4px; height: 8px; }}
  .ep-bar-fill {{ height: 8px; border-radius: 4px; background: #378ADD; }}
  .ep-count {{ width: 20px; text-align: right; color: #888; }}
  .section-title {{ font-size: 12px; font-weight: 500; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin: 0 0 10px; }}
  .finding-row {{ background: #fff; border: 0.5px solid rgba(0,0,0,0.1); border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 8px; }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 4px; }}
  .badge {{ font-size: 11px; font-weight: 500; padding: 2px 8px; border-radius: 6px; flex-shrink: 0; }}
  .badge-high {{ background: #FCEBEB; color: #A32D2D; }}
  .badge-medium {{ background: #FAEEDA; color: #854F0B; }}
  .badge-low {{ background: #EAF3DE; color: #3B6D11; }}
  .finding-title {{ font-size: 14px; font-weight: 500; margin: 0; }}
  .finding-meta {{ font-size: 12px; color: #888; display: flex; gap: 16px; flex-wrap: wrap; }}
  .finding-detail {{ font-size: 12px; color: #666; margin-top: 6px; border-top: 0.5px solid rgba(0,0,0,0.08); padding-top: 6px; }}
  .rec {{ color: #185FA5; margin-top: 4px; }}
  @media (max-width: 600px) {{
    .metric-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .charts-row {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>
<h1>endpwnt scan report</h1>

<div class="metric-grid">
  <div class="metric"><p class="metric-label">Total findings</p><p class="metric-value" id="m-total"></p></div>
  <div class="metric"><p class="metric-label">High severity</p><p class="metric-value" style="color:#A32D2D" id="m-high"></p></div>
  <div class="metric"><p class="metric-label">Medium severity</p><p class="metric-value" style="color:#854F0B" id="m-med"></p></div>
  <div class="metric"><p class="metric-label">Endpoints affected</p><p class="metric-value" id="m-ep"></p></div>
</div>

<div class="charts-row">
  <div class="chart-card">
    <p class="chart-title">Findings by severity</p>
    <div class="legend" id="sev-legend"></div>
    <div style="position:relative;height:180px"><canvas id="sevChart"></canvas></div>
  </div>
  <div class="chart-card">
    <p class="chart-title">Findings by check type</p>
    <div class="legend" id="check-legend"></div>
    <div style="position:relative;height:180px"><canvas id="checkChart"></canvas></div>
  </div>
</div>

<div class="chart-card" style="margin-bottom:1.5rem">
  <p class="chart-title">Findings per endpoint</p>
  <div id="ep-bars"></div>
</div>

<p class="section-title">All findings</p>
<div id="findings-list"></div>

<script>
const SEV_COLORS = {sev_colors_json};
const CHECK_COLORS = {check_colors_json};
const CHECK_LABELS = {check_labels_json};

const findings = {findings_json};

document.getElementById('m-total').textContent = findings.length;
document.getElementById('m-high').textContent = findings.filter(f=>f.severity==='high').length;
document.getElementById('m-med').textContent = findings.filter(f=>f.severity==='medium').length;
document.getElementById('m-ep').textContent = new Set(findings.map(f=>f.endpoint)).size;

const sevCounts = {{}};
findings.forEach(f=>{{ sevCounts[f.severity]=(sevCounts[f.severity]||0)+1; }});
const sevOrder = ['high','medium','low'].filter(s=>sevCounts[s]);
document.getElementById('sev-legend').innerHTML = sevOrder.map(s=>
  `<span><span class="legend-dot" style="background:${{SEV_COLORS[s]}}"></span>${{s}} ${{sevCounts[s]}}</span>`
).join('');
new Chart(document.getElementById('sevChart'), {{
  type:'doughnut',
  data:{{ labels:sevOrder, datasets:[{{ data:sevOrder.map(s=>sevCounts[s]), backgroundColor:sevOrder.map(s=>SEV_COLORS[s]), borderWidth:0 }}] }},
  options:{{ responsive:true, maintainAspectRatio:false, plugins:{{ legend:{{ display:false }} }} }}
}});

const checkCounts = {{}};
findings.forEach(f=>{{ checkCounts[f.check_id]=(checkCounts[f.check_id]||0)+1; }});
const checkOrder = Object.keys(checkCounts);
document.getElementById('check-legend').innerHTML = checkOrder.map(c=>
  `<span><span class="legend-dot" style="background:${{CHECK_COLORS[c]||'#888'}}"></span>${{CHECK_LABELS[c]||c}} ${{checkCounts[c]}}</span>`
).join('');
new Chart(document.getElementById('checkChart'), {{
  type:'bar',
  data:{{ labels:checkOrder.map(c=>CHECK_LABELS[c]||c), datasets:[{{ data:checkOrder.map(c=>checkCounts[c]), backgroundColor:checkOrder.map(c=>CHECK_COLORS[c]||'#888'), borderRadius:4, borderWidth:0 }}] }},
  options:{{ responsive:true, maintainAspectRatio:false, plugins:{{ legend:{{ display:false }} }}, scales:{{ x:{{ ticks:{{ font:{{ size:11 }}, autoSkip:false }}, grid:{{ display:false }} }}, y:{{ ticks:{{ stepSize:1, font:{{ size:11 }} }}, grid:{{ color:'rgba(0,0,0,0.06)' }} }} }} }}
}});

const epCounts = {{}};
findings.forEach(f=>{{ epCounts[f.endpoint]=(epCounts[f.endpoint]||0)+1; }});
const epSorted = Object.entries(epCounts).sort((a,b)=>b[1]-a[1]);
const maxEp = epSorted[0][1];
document.getElementById('ep-bars').innerHTML = epSorted.map(([ep,n])=>
  `<div class="ep-bar-row">
    <span class="ep-label" title="${{ep}}">${{ep}}</span>
    <div class="ep-bar-bg"><div class="ep-bar-fill" style="width:${{Math.round(n/maxEp*100)}}%"></div></div>
    <span class="ep-count">${{n}}</span>
  </div>`
).join('');

document.getElementById('findings-list').innerHTML = findings.map(f=>
  `<div class="finding-row">
    <div class="finding-header">
      <span class="badge badge-${{f.severity}}">${{f.severity}}</span>
      <p class="finding-title">${{f.title}}</p>
    </div>
    <div class="finding-meta">
      <span>${{f.endpoint}}</span>
      <span>ctx: ${{f.auth_context}}</span>
      <span>check: ${{f.check_id}}</span>
    </div>
    <div class="finding-detail">
      <div>${{f.evidence}}</div>
      <div class="rec">&#8594; ${{f.recommendation}}</div>
    </div>
  </div>`
).join('');
</script>
</body>
</html>"""