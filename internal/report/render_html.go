package report

import (
	"bytes"
	"html/template"
	"sort"
	"time"

	"github.com/threatprism/threatprism/pkg/models"
)

// sortFindings returns findings ordered by descending severity then module.
func sortFindings(in []models.Finding) []models.Finding {
	out := make([]models.Finding, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity.Score() != out[j].Severity.Score() {
			return out[i].Severity.Score() > out[j].Severity.Score()
		}
		return out[i].Module < out[j].Module
	})
	return out
}

func renderHTML(r *models.Result, theme string) ([]byte, error) {
	funcs := template.FuncMap{
		"sev":      severityClass,
		"upper":    func(s models.Severity) string { return string(s) },
		"duration": func() string { return r.EndedAt.Sub(r.StartedAt).Round(time.Second).String() },
		"now":      func() string { return time.Now().Format("2006-01-02 15:04:05") },
		"severities": func() []string { return []string{"critical", "high", "medium", "low", "info"} },
	}
	tmpl, err := template.New("report").Funcs(funcs).Parse(dashboardHTML)
	if err != nil {
		return nil, err
	}
	data := struct {
		R        *models.Result
		Theme    string
		Findings []models.Finding
	}{R: r, Theme: theme, Findings: sortFindings(r.Findings)}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

const dashboardHTML = `<!DOCTYPE html>
<html lang="en" data-theme="{{.Theme}}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ThreatPrism Report — {{.R.Target.Host}}</title>
<style>
:root{
  --bg:#0b0e14; --panel:#141925; --panel2:#1b2130; --border:#242c3d;
  --text:#e6e9ef; --muted:#8b93a7; --accent:#5b8cff; --accent2:#22d3ee;
  --crit:#ff4d6d; --high:#ff8c42; --med:#ffd166; --low:#4cc9f0; --info:#5eead4;
}
[data-theme="light"]{
  --bg:#f5f7fb; --panel:#ffffff; --panel2:#eef1f7; --border:#dce1ec;
  --text:#1a2030; --muted:#5b6478; --accent:#3b6dff;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
header{padding:28px 32px;border-bottom:1px solid var(--border);background:linear-gradient(180deg,var(--panel),transparent);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px}
.brand{display:flex;align-items:center;gap:14px}
.logo{width:40px;height:40px;border-radius:10px;background:conic-gradient(from 210deg,var(--accent),var(--accent2),var(--crit),var(--accent));box-shadow:0 0 24px rgba(91,140,255,.4)}
h1{font-size:20px;margin:0;letter-spacing:.3px}
h1 small{display:block;color:var(--muted);font-size:12px;font-weight:400;margin-top:2px}
.wrap{max-width:1280px;margin:0 auto;padding:24px 32px 64px}
.grid{display:grid;gap:16px}
.stats{grid-template-columns:repeat(auto-fit,minmax(150px,1fr));margin-bottom:24px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px}
.stat .n{font-size:28px;font-weight:700}
.stat .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.6px;margin-top:4px}
.risk{display:flex;align-items:center;gap:20px}
.gauge{--v:0;width:96px;height:96px;border-radius:50%;background:conic-gradient(var(--accent) calc(var(--v)*1%),var(--panel2) 0);display:grid;place-items:center;position:relative}
.gauge::before{content:"";position:absolute;inset:8px;border-radius:50%;background:var(--panel)}
.gauge span{position:relative;font-size:22px;font-weight:800}
.section{margin-top:28px}
.section h2{font-size:15px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin:0 0 12px;display:flex;align-items:center;gap:10px}
.section h2::after{content:"";flex:1;height:1px;background:var(--border)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.5px}
tr:hover td{background:var(--panel2)}
.badge{display:inline-block;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.4px}
.badge.critical{background:rgba(255,77,109,.15);color:var(--crit)}
.badge.high{background:rgba(255,140,66,.15);color:var(--high)}
.badge.medium{background:rgba(255,209,102,.15);color:var(--med)}
.badge.low{background:rgba(76,201,240,.15);color:var(--low)}
.badge.info{background:rgba(94,234,212,.12);color:var(--info)}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{background:var(--panel2);border:1px solid var(--border);border-radius:10px;padding:8px 12px;font-size:12px}
.chip b{color:var(--accent)}
.controls{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
input[type=search],select{background:var(--panel2);border:1px solid var(--border);color:var(--text);border-radius:9px;padding:8px 12px;font-size:13px;outline:none}
input[type=search]{flex:1;min-width:220px}
.filter-btn{cursor:pointer;background:var(--panel2);border:1px solid var(--border);color:var(--muted);border-radius:20px;padding:5px 12px;font-size:12px}
.filter-btn.active{color:var(--text);border-color:var(--accent)}
.gallery{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px}
.gallery img{width:100%;border-radius:10px;border:1px solid var(--border)}
.muted{color:var(--muted)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
footer{color:var(--muted);text-align:center;padding:32px;font-size:12px}
details{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px 16px;margin-bottom:10px}
summary{cursor:pointer;font-weight:600}
.aibox{white-space:pre-wrap;background:var(--panel2);border:1px solid var(--border);border-radius:12px;padding:16px;font-size:13px}
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="logo"></div>
    <h1>ThreatPrism<small>Attack Surface Intelligence — {{.R.Target.URL}}</small></h1>
  </div>
  <div class="chips">
    <span class="chip">Mode <b>{{.R.Mode}}</b></span>
    <span class="chip">Duration <b>{{duration}}</b></span>
    <span class="chip">Generated <b>{{now}}</b></span>
  </div>
</header>
<div class="wrap">

  <div class="grid stats">
    <div class="card stat"><div class="n">{{len .R.Subdomains}}</div><div class="l">Subdomains</div></div>
    <div class="card stat"><div class="n">{{len .R.Hosts}}</div><div class="l">Alive Hosts</div></div>
    <div class="card stat"><div class="n">{{len .R.JSFiles}}</div><div class="l">JS Files</div></div>
    <div class="card stat"><div class="n">{{len .R.APIEndpoints}}</div><div class="l">APIs</div></div>
    <div class="card stat"><div class="n">{{len .R.LoginPages}}</div><div class="l">Login Pages</div></div>
    <div class="card stat"><div class="n">{{len .R.SensitiveFiles}}</div><div class="l">Sensitive Files</div></div>
    <div class="card stat"><div class="n">{{len .R.Secrets}}</div><div class="l">Secrets</div></div>
    <div class="card stat"><div class="n">{{len .R.Parameters}}</div><div class="l">Parameters</div></div>
  </div>

  <div class="card risk">
    <div class="gauge" style="--v:{{.R.RiskScore}}"><span>{{.R.RiskScore}}</span></div>
    <div>
      <div style="font-size:18px;font-weight:700;text-transform:capitalize">{{.R.RiskLevel}} risk</div>
      <div class="muted">Aggregated from {{len .Findings}} findings across all modules.</div>
    </div>
  </div>

  {{if .Findings}}
  <div class="section">
    <h2>Findings</h2>
    <div class="controls">
      <input type="search" id="q" placeholder="Search findings…" oninput="filterFindings()">
      {{range $s := (severities)}}
      <span class="filter-btn active" data-sev="{{$s}}" onclick="toggleSev(this)">{{$s}}</span>
      {{end}}
    </div>
    <div class="card" style="padding:0;overflow:hidden">
    <table id="findings">
      <thead><tr><th>Severity</th><th>Module</th><th>Title</th><th>URL</th></tr></thead>
      <tbody>
      {{range .Findings}}
        <tr data-sev="{{sev .Severity}}" data-text="{{.Title}} {{.Module}} {{.URL}}">
          <td><span class="badge {{sev .Severity}}">{{.Severity}}</span></td>
          <td class="muted">{{.Module}}</td>
          <td>{{.Title}}{{if .Evidence}}<div class="mono muted">{{.Evidence}}</div>{{end}}</td>
          <td class="mono">{{if .URL}}<a href="{{.URL}}" target="_blank" rel="noopener">{{.URL}}</a>{{end}}</td>
        </tr>
      {{end}}
      </tbody>
    </table>
    </div>
  </div>
  {{end}}

  {{if .R.Technologies}}
  <div class="section">
    <h2>Technologies</h2>
    <div class="chips">
      {{range .R.Technologies}}<span class="chip"><b>{{.Name}}</b>{{if .Version}} {{.Version}}{{end}} <span class="muted">· {{.Category}}</span></span>{{end}}
    </div>
  </div>
  {{end}}

  {{if .R.Subdomains}}
  <div class="section">
    <h2>Subdomains &amp; Hosts</h2>
    <div class="card" style="padding:0;overflow:hidden">
    <table>
      <thead><tr><th>Subdomain</th><th>Alive</th><th>IPs</th><th>Sources</th></tr></thead>
      <tbody>
      {{range .R.Subdomains}}
        <tr><td class="mono">{{.Name}}</td>
        <td>{{if .Alive}}<span class="badge low">yes</span>{{else}}<span class="muted">—</span>{{end}}</td>
        <td class="mono muted">{{range .IPs}}{{.}} {{end}}</td>
        <td class="muted">{{range .Sources}}{{.}} {{end}}</td></tr>
      {{end}}
      </tbody>
    </table>
    </div>
  </div>
  {{end}}

  {{if .R.JSFiles}}
  <div class="section">
    <h2>JavaScript Explorer</h2>
    {{range .R.JSFiles}}
    <details>
      <summary>{{.URL}} <span class="muted">({{len .Endpoints}} endpoints, {{len .Secrets}} secrets)</span></summary>
      {{if .Libraries}}<p class="muted">Libraries: {{range .Libraries}}{{.}} {{end}}</p>{{end}}
      {{if .Endpoints}}<div class="mono muted">{{range .Endpoints}}{{.}}<br>{{end}}</div>{{end}}
    </details>
    {{end}}
  </div>
  {{end}}

  {{if .R.APIEndpoints}}
  <div class="section">
    <h2>API Explorer</h2>
    <div class="card" style="padding:0;overflow:hidden">
    <table>
      <thead><tr><th>Kind</th><th>Method</th><th>URL</th><th>Source</th></tr></thead>
      <tbody>
      {{range .R.APIEndpoints}}
        <tr><td><span class="badge info">{{.Kind}}</span></td><td class="muted">{{if .Method}}{{.Method}}{{else}}—{{end}}</td>
        <td class="mono"><a href="{{.URL}}" target="_blank" rel="noopener">{{.URL}}</a></td><td class="muted">{{.Source}}</td></tr>
      {{end}}
      </tbody>
    </table>
    </div>
  </div>
  {{end}}

  {{if .R.Screenshots}}
  <div class="section">
    <h2>Screenshot Gallery</h2>
    <div class="gallery">
      {{range .R.Screenshots}}<a href="{{.Path}}" target="_blank"><img src="{{.Path}}" alt="{{.URL}}" loading="lazy"></a>{{end}}
    </div>
  </div>
  {{end}}

  {{range .Findings}}{{if eq .Type "ai_summary"}}
  <div class="section">
    <h2>AI Recommendations</h2>
    <div class="aibox">{{.Description}}</div>
  </div>
  {{end}}{{end}}

</div>
<footer>Generated by ThreatPrism · Autonomous Attack Surface Intelligence Platform</footer>
<script>
function filterFindings(){
  var q=document.getElementById('q').value.toLowerCase();
  var active={};document.querySelectorAll('.filter-btn').forEach(function(b){if(b.classList.contains('active'))active[b.dataset.sev]=1;});
  document.querySelectorAll('#findings tbody tr').forEach(function(tr){
    var okSev=active[tr.dataset.sev];
    var okText=tr.dataset.text.toLowerCase().indexOf(q)>=0;
    tr.style.display=(okSev&&okText)?'':'none';
  });
}
function toggleSev(el){el.classList.toggle('active');filterFindings();}
</script>
</body>
</html>`
