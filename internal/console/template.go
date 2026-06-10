package console

// pageHTML is the single self-contained dashboard page (inline CSS, no JS, no build
// step). It renders the view model from console.go. The risk-rating banner answers
// "am I okay?" at a glance; the rest is the evidence behind it.
const pageHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Tenant}} — Security Posture</title>
<style>
  :root{--bg:#0b0e14;--card:#151a23;--ink:#e6e9ef;--muted:#8b94a7;--line:#232a37;
        --critical:#ff4d4f;--high:#ff7a45;--medium:#faad14;--low:#52c41a;--clear:#52c41a}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  .wrap{max-width:980px;margin:0 auto;padding:28px 20px}
  h1{font-size:20px;margin:0 0 2px} .sub{color:var(--muted);font-size:13px;margin-bottom:22px}
  .banner{border-radius:12px;padding:18px 22px;margin-bottom:22px;display:flex;align-items:center;gap:16px;border:1px solid var(--line)}
  .banner .rr{font-size:26px;font-weight:700} .banner .lbl{color:var(--muted);font-size:13px}
  .rr-Critical{color:var(--critical)} .rr-High{color:var(--high)} .rr-Medium{color:var(--medium)}
  .rr-Low{color:var(--low)} .rr-Clear{color:var(--clear)}
  .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:22px}
  .pill{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;text-align:center}
  .pill .n{font-size:24px;font-weight:700} .pill .s{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
  .n.critical{color:var(--critical)} .n.high{color:var(--high)} .n.medium{color:var(--medium)} .n.low{color:var(--low)}
  section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:18px}
  section h2{font-size:14px;margin:0 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
  table{width:100%;border-collapse:collapse} td,th{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}
  th{color:var(--muted);font-weight:500} tr:last-child td{border-bottom:0}
  .sev{font-weight:600;text-transform:capitalize} .sev.critical{color:var(--critical)} .sev.high{color:var(--high)}
  .sev.medium{color:var(--medium)} .sev.low{color:var(--low)} .sev.info{color:var(--muted)}
  .tag{display:inline-block;background:#1d2530;border:1px solid var(--line);border-radius:6px;padding:1px 7px;font-size:11px;color:var(--muted)}
  .empty{color:var(--muted);font-size:13px;padding:6px 0}
  .btn{display:inline-block;border:1px solid var(--line);border-radius:6px;padding:3px 11px;font-size:12px;cursor:pointer;background:#1d2530;color:var(--ink)}
  .btn.ok{border-color:#2a6b1f;color:var(--low)} .btn.no{border-color:#6b2a2a;color:var(--high)}
  form.inline{display:inline;margin:0}
  .topbar{display:flex;align-items:center;gap:12px;margin-bottom:2px}
  .topbar .who{margin-left:auto;color:var(--muted);font-size:12px}
  .fw{display:flex;gap:8px;flex-wrap:wrap}
  .fwcard{flex:1;min-width:120px;background:#11161f;border:1px solid var(--line);border-radius:9px;padding:12px}
  a.fwcard{text-decoration:none;color:inherit;display:block} a.fwcard:hover{border-color:#3a4658}
  .fwcard .name{font-size:12px;color:var(--muted)} .fwcard .met{color:var(--low);font-weight:600} .fwcard .gap{color:var(--high);font-weight:600}
  code{background:#11161f;border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:12px}
  .foot{color:var(--muted);font-size:12px;margin-top:16px}
</style></head><body><div class="wrap">
  <div class="topbar">
    <h1>{{.Tenant}}</h1>
    <div class="who">{{if .Operator}}{{.Operator}} · {{end}}<form class="inline" method="post" action="/ui/logout"><button class="btn" type="submit">Sign out</button></form></div>
  </div>
  <div class="sub">Autonomous security posture · tenant <code>{{.TenantID}}</code></div>

  <div class="banner">
    <div><div class="lbl">Risk rating</div><div class="rr rr-{{.RiskRating}}">{{.RiskRating}}</div></div>
    <div style="margin-left:auto;color:var(--muted);font-size:13px">{{len .Pending}} action(s) awaiting approval · {{len .Connections}} connected system(s)</div>
  </div>

  <div class="grid">
    {{range .SevCounts}}<div class="pill"><div class="n {{.Class}}">{{.Count}}</div><div class="s">{{.Severity}}</div></div>{{end}}
  </div>

  {{if .Frameworks}}<section><h2>Compliance posture</h2><div class="fw">
    {{$tid := .TenantID}}{{$rep := .CanReport}}
    {{range .Frameworks}}{{if $rep}}<a class="fwcard" href="/ui/compliance/{{.Key}}?tenant={{$tid}}"><div class="name">{{.Name}} →</div><span class="met">{{.Met}} met</span> · <span class="gap">{{.Gap}} gap</span></a>{{else}}<div class="fwcard"><div class="name">{{.Name}}</div><span class="met">{{.Met}} met</span> · <span class="gap">{{.Gap}} gap</span></div>{{end}}{{end}}
  </div></section>{{end}}

  <section><h2>Awaiting your approval</h2>
    {{if .Pending}}<table><tr><th>Action</th><th>Kind</th><th>Tier</th><th>Finding</th>{{if $.CanApprove}}<th></th>{{end}}</tr>
    {{range .Pending}}<tr><td>{{.Title}}</td><td><span class="tag">{{.Kind}}</span></td><td>{{.Tier}}</td><td><code>{{.FindingID}}</code></td>
    {{if $.CanApprove}}<td>
      <form class="inline" method="post" action="/ui/approvals/{{.ID}}"><input type="hidden" name="tenant" value="{{$.TenantID}}"><input type="hidden" name="decision" value="approve"><button class="btn ok" type="submit">Approve</button></form>
      <form class="inline" method="post" action="/ui/approvals/{{.ID}}"><input type="hidden" name="tenant" value="{{$.TenantID}}"><input type="hidden" name="decision" value="reject"><button class="btn no" type="submit">Reject</button></form>
    </td>{{end}}</tr>{{end}}
    </table>{{else}}<div class="empty">Nothing waiting on you — the agent is auto-handling everything safe.</div>{{end}}
  </section>

  <section><h2>Top findings</h2>
    {{if .Findings}}<table><tr><th>Severity</th><th>Finding</th><th>Where</th><th>Tool</th></tr>
    {{range .Findings}}<tr><td><span class="sev {{.Severity}}">{{.Severity}}</span></td><td>{{.Title}}</td><td><code>{{.Endpoint}}</code></td><td><span class="tag">{{.Tool}}</span></td></tr>{{end}}
    </table>{{else}}<div class="empty">No open findings.</div>{{end}}
  </section>

  <div class="foot">Every decision — approve or reject — is signed into the ledger. Tier 0/1 fixes auto-apply; tier 2+ wait for you here.</div>
</div></body></html>`

// loginHTML is the token gate. A browser can't send a bearer header on navigation, so
// this POSTs the token to /ui/login, which sets the session cookie.
const loginHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in — Security Posture</title>
<style>
  :root{--bg:#0b0e14;--card:#151a23;--ink:#e6e9ef;--muted:#8b94a7;--line:#232a37;--high:#ff7a45}
  body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
       display:flex;min-height:100vh;align-items:center;justify-content:center}
  .box{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:28px;width:320px}
  h1{font-size:17px;margin:0 0 4px} .sub{color:var(--muted);font-size:13px;margin-bottom:18px}
  label{display:block;font-size:12px;color:var(--muted);margin:12px 0 4px}
  input{width:100%;box-sizing:border-box;background:#0b0e14;border:1px solid var(--line);border-radius:7px;padding:9px;color:var(--ink);font-size:14px}
  button{margin-top:18px;width:100%;background:#1d2530;border:1px solid var(--line);border-radius:7px;padding:10px;color:var(--ink);font-size:14px;cursor:pointer}
  .err{color:var(--high);font-size:13px;margin-top:12px}
</style></head><body>
  <form class="box" method="post" action="/ui/login">
    <h1>Autonomous Security Team</h1>
    <div class="sub">Sign in to review posture and approvals.</div>
    <label>Access token</label><input type="password" name="token" autofocus autocomplete="current-password">
    <label>Your name (optional)</label><input type="text" name="operator" placeholder="for the approval audit trail">
    <label>Tenant</label><input type="text" name="tenant" value="{{.Tenant}}" placeholder="tenant id">
    <button type="submit">Sign in</button>
    {{if .Error}}<div class="err">{{.Error}}</div>{{end}}
  </form>
</body></html>`

// pickerHTML lets a signed-in operator choose a tenant when none is in the URL.
const pickerHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Choose tenant</title>
<style>
  :root{--bg:#0b0e14;--card:#151a23;--ink:#e6e9ef;--muted:#8b94a7;--line:#232a37}
  body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  .wrap{max-width:480px;margin:60px auto;padding:0 20px}
  h1{font-size:18px} a{display:block;background:var(--card);border:1px solid var(--line);border-radius:9px;padding:12px 14px;margin:8px 0;color:var(--ink);text-decoration:none}
  a:hover{border-color:#3a4658} .id{color:var(--muted);font-size:12px}
  .empty{color:var(--muted)}
</style></head><body><div class="wrap">
  <h1>Choose a tenant</h1>
  {{if .}}{{range .}}<a href="/ui?tenant={{.ID}}">{{if .Name}}{{.Name}}{{else}}{{.ID}}{{end}}<div class="id">{{.ID}}</div></a>{{end}}
  {{else}}<div class="empty">No tenants yet. Provision one via <code>POST /v1/tenants</code>.</div>{{end}}
</div></body></html>`

// complianceHTML is the per-framework drill-down: every gap backed by its citing
// findings — the auditor-facing view behind a posture card. Renders a *grc.Report.
const complianceHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}} — {{.TenantName}}</title>
<style>
  :root{--bg:#0b0e14;--card:#151a23;--ink:#e6e9ef;--muted:#8b94a7;--line:#232a37;
        --critical:#ff4d4f;--high:#ff7a45;--medium:#faad14;--low:#52c41a}
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);
    font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  .wrap{max-width:880px;margin:0 auto;padding:28px 20px}
  .topbar{display:flex;align-items:center;gap:12px}
  h1{font-size:20px;margin:0} .topbar .who{margin-left:auto}
  .btn{display:inline-block;border:1px solid var(--line);border-radius:6px;padding:4px 11px;font-size:12px;color:var(--ink);text-decoration:none;background:#1d2530}
  .sub{color:var(--muted);font-size:13px;margin:4px 0 18px}
  .banner{display:flex;gap:22px;background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 20px;margin-bottom:18px}
  .banner .n{font-size:24px;font-weight:700} .banner .met{color:var(--low)} .banner .gap{color:var(--high)} .banner .lbl{color:var(--muted);font-size:12px}
  section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin-bottom:18px}
  section h2{font-size:14px;margin:0 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
  .ctl{border-bottom:1px solid var(--line);padding:10px 0} .ctl:last-child{border-bottom:0}
  .cid{font-weight:600} .gapbadge{color:var(--high);font-size:11px;border:1px solid #6b2a2a;border-radius:5px;padding:0 6px;margin-left:6px}
  ul{margin:8px 0 0;padding-left:18px} li{font-size:13px;margin:2px 0}
  .sev{font-weight:600;text-transform:capitalize;font-size:12px} .sev.critical{color:var(--critical)} .sev.high{color:var(--high)}
  .sev.medium{color:var(--medium)} .sev.low{color:var(--low)} .sev.info{color:var(--muted)}
  .tag{display:inline-block;background:#1d2530;border:1px solid var(--line);border-radius:6px;padding:2px 8px;font-size:12px;color:var(--low);margin:0 4px 6px 0}
  .empty{color:var(--muted);font-size:13px} code{background:#11161f;border:1px solid var(--line);border-radius:5px;padding:1px 5px;font-size:12px}
  .foot{color:var(--muted);font-size:12px;margin-top:8px}
</style></head><body><div class="wrap">
  <div class="topbar"><h1>{{.Title}} Compliance</h1><div class="who"><a class="btn" href="/ui?tenant={{.TenantID}}">← Dashboard</a></div></div>
  <div class="sub">{{.TenantName}} · generated {{rfc3339 .GeneratedAt}}{{if .Signer}} · signed by <code>{{.Signer}}</code> sha256 <code>{{.SHA256}}</code>{{end}}</div>

  <div class="banner">
    <div><div class="n met">{{.MetCount}}</div><div class="lbl">controls met</div></div>
    <div><div class="n gap">{{.GapCount}}</div><div class="lbl">gaps</div></div>
  </div>

  <section><h2>Gaps ({{.GapCount}})</h2>
    {{range .Rows}}{{if .Gap}}<div class="ctl"><div class="cid">{{.ControlID}}<span class="gapbadge">GAP</span></div>
      {{if .Evidence}}<ul>{{range .Evidence}}<li><code>{{.FindingID}}</code> — {{if .Title}}{{.Title}}{{else}}(finding detail unavailable){{end}} <span class="sev {{.Severity}}">{{if .Severity}}{{.Severity}}{{else}}unknown{{end}}</span></li>{{end}}</ul>
      {{else}}<div class="empty">No evidence finding on record.</div>{{end}}
    </div>{{end}}{{end}}
    {{if eq .GapCount 0}}<div class="empty">No open gaps — every tracked control is met.</div>{{end}}
  </section>

  <section><h2>Met ({{.MetCount}})</h2>
    {{range .Rows}}{{if not .Gap}}<span class="tag">{{.ControlID}}</span>{{end}}{{end}}
    {{if eq .MetCount 0}}<div class="empty">No controls currently met.</div>{{end}}
  </section>

  <div class="foot">Attachable Markdown for an auditor: <code>GET /v1/compliance/{{.Framework}}/report</code></div>
</div></body></html>`
