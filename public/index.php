<?php
/**
 * VulnScope Pro — single-URL entry point (behavior preserved from the monolith).
 *
 * Pre-split, index.php served BOTH the JSON API and the dashboard from one
 * URL: any ?action=… request was answered by the router (which always
 * exits), and every other request fell through to the HTML dashboard.
 * This file reproduces that exactly — zero frontend JS changes needed:
 * the UI keeps calling fetch('?action=…') relative to '/'.
 *
 * The dashboard is .php (not .html) because the sidebar's "API Source
 * Status" widget is server-rendered via get_api_status().
 */
require_once __DIR__ . '/../bootstrap.php';

/* ---- API mode: ?action=… is handled by the router and never returns. ---- */
require __DIR__ . '/api_router.php';

/* ---- Dashboard mode: no (recognized) action — render the operator UI. ---- */
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScope Pro &mdash; Enterprise Vulnerability Intelligence</title>
<meta name="description" content="Enterprise vulnerability intelligence platform. Multi-source CVE correlation: NVD, Shodan, Censys, CIRCL.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<style>
:root{
  --bg-root:#020408;--bg-card:rgba(10,18,30,0.92);
  --accent:#06b6d4;--accent2:#3b82f6;
  --accent-glow:rgba(6,182,212,0.12);--accent-border:rgba(6,182,212,0.22);
  --danger:#ef4444;--danger-dim:rgba(239,68,68,0.08);--danger-border:rgba(239,68,68,0.28);
  --warn:#f97316;--warn-dim:rgba(249,115,22,0.08);
  --med:#eab308;--med-dim:rgba(234,179,8,0.08);
  --low:#22d3ee;--low-dim:rgba(34,211,238,0.06);
  --info:#64748b;--info-dim:rgba(100,116,139,0.06);
  --t1:#e2e8f0;--t2:#94a3b8;--t3:#7d8ea3;--t4:#5b6b82;
  --border:rgba(30,41,59,0.8);--border2:rgba(51,65,85,0.9);
  --r8:8px;--r12:12px;--r16:16px;--r24:24px;
  --sidebar:260px;--topbar:60px;
  --ease:all 0.22s cubic-bezier(.4,0,.2,1);
  --font:"Inter",system-ui,sans-serif;
  --mono:"JetBrains Mono","Courier New",monospace;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{background:var(--bg-root);color:var(--t1);font-family:var(--font);overflow-x:hidden;min-height:100vh}
::-webkit-scrollbar{width:4px;height:4px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#1e293b;border-radius:99px}
#bgc{position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.3}
#shell{position:relative;z-index:1;display:flex;min-height:100vh}
#sb{width:var(--sidebar);flex-shrink:0;background:rgba(4,8,18,0.97);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;height:100vh;z-index:200;backdrop-filter:blur(20px);transition:transform .3s ease;overflow:hidden}
.sb-logo{padding:20px 16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.sb-logo-ico{width:36px;height:36px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));display:flex;align-items:center;justify-content:center;font-size:16px;color:#fff;flex-shrink:0;box-shadow:0 0 14px rgba(6,182,212,.35)}
.sb-logo-txt h2{font-size:13px;font-weight:800;letter-spacing:.04em;text-transform:uppercase}
.sb-logo-txt h2 span{color:var(--accent)}
.sb-logo-txt p{font-size:9px;color:var(--t3);font-family:var(--mono);letter-spacing:.1em;margin-top:1px}
.sb-nav{flex:1;padding:12px 10px;overflow-y:auto}
.nav-lbl{font-size:9px;font-weight:700;color:var(--t4);letter-spacing:.15em;text-transform:uppercase;padding:10px 8px 5px}
.nav-a{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:var(--r8);color:var(--t2);font-size:13px;font-weight:500;cursor:pointer;transition:var(--ease);border:1px solid transparent;margin-bottom:2px;text-decoration:none}
.nav-a:hover,.nav-a.active{background:var(--accent-glow);border-color:var(--accent-border);color:var(--accent)}
.nav-a i{width:15px;text-align:center;font-size:12px}
.sb-apis{padding:14px;border-top:1px solid var(--border)}
.sb-api-lbl{font-size:9px;font-weight:700;color:var(--t4);letter-spacing:.14em;text-transform:uppercase;margin-bottom:8px}
.sb-api-row{display:flex;align-items:center;justify-content:space-between;padding:5px 0;border-bottom:1px solid rgba(30,41,59,.4)}
.sb-api-row:last-child{border:none}
.sb-api-name{font-family:var(--mono);font-size:10px;color:var(--t2);text-transform:uppercase;display:flex;align-items:center;gap:6px}
.dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
.dot-on{background:#22c55e;box-shadow:0 0 5px #22c55e;animation:dpulse 2s infinite}
.dot-off{background:#ef4444}
@keyframes dpulse{0%,100%{opacity:1}50%{opacity:.35}}
.api-badge{font-family:var(--mono);font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;text-transform:uppercase;letter-spacing:.04em}
.api-badge.on{background:rgba(34,197,94,.1);color:#22c55e;border:1px solid rgba(34,197,94,.2)}
.api-badge.off{background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
.sb-footer{padding:10px 14px;border-top:1px solid var(--border);font-size:9px;color:var(--t4);text-align:center;font-family:var(--mono);line-height:1.6}
#main{margin-left:var(--sidebar);flex:1;display:flex;flex-direction:column;min-height:100vh}
#topbar{height:var(--topbar);border-bottom:1px solid var(--border);background:rgba(4,8,18,.85);backdrop-filter:blur(20px);display:flex;align-items:center;justify-content:space-between;padding:0 24px;position:sticky;top:0;z-index:100}
.tb-left{display:flex;align-items:center;gap:12px}
.tb-bread{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--t3)}
.tb-bread .cr-active{color:var(--t1);font-weight:600}
.tb-bread i{font-size:8px}
.tb-right{display:flex;align-items:center;gap:10px}
.tb-pill{display:flex;align-items:center;gap:5px;font-size:10px;font-family:var(--mono);color:var(--t3);background:rgba(255,255,255,.03);border:1px solid var(--border);padding:4px 10px;border-radius:var(--r8)}
.ldot{width:5px;height:5px;border-radius:50%;background:#22c55e;animation:dpulse 2s infinite;display:inline-block}
#sbtoggle{display:none;background:none;border:1px solid var(--border);color:var(--t2);padding:7px 10px;border-radius:var(--r8);cursor:pointer;transition:var(--ease);font-size:13px}
#sbtoggle:hover{border-color:var(--accent-border);color:var(--accent)}
#pg{flex:1;padding:24px}
.scan-panel{background:var(--bg-card);border:1px solid var(--border2);border-radius:var(--r24);padding:28px 32px;margin-bottom:24px;position:relative;overflow:hidden;backdrop-filter:blur(16px)}
.scan-panel::before{content:"";position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--accent),var(--accent2),transparent);opacity:.55}
.scan-ph{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:22px;flex-wrap:wrap}
.scan-ph h1{font-size:18px;font-weight:800;letter-spacing:-.01em;margin-bottom:4px}
.scan-ph p{font-size:11px;color:var(--t3);font-family:var(--mono);letter-spacing:.04em}
.eng-badge{display:flex;align-items:center;gap:7px;background:rgba(6,182,212,.05);border:1px solid var(--accent-border);border-radius:var(--r12);padding:7px 13px;font-size:10px;font-family:var(--mono);color:var(--accent);text-transform:uppercase;letter-spacing:.07em;white-space:nowrap;flex-shrink:0}
.scan-row{display:flex;gap:10px;align-items:stretch}
.inp-wrap{position:relative;flex:1}
.inp-ico{position:absolute;left:15px;top:50%;transform:translateY(-50%);color:var(--t3);font-size:13px;pointer-events:none}
#target{width:100%;background:rgba(4,8,18,.9);border:1px solid var(--border2);border-radius:var(--r12);padding:14px 16px 14px 44px;font-family:var(--mono);font-size:13px;color:var(--t1);outline:none;transition:var(--ease);letter-spacing:.02em}
#target::placeholder{color:var(--t4)}
@keyframes inpnudge{0%,100%{box-shadow:0 0 0 0 rgba(6,182,212,0)}20%,60%{box-shadow:0 0 0 4px rgba(6,182,212,.35)}}
.input-nudge{animation:inpnudge .9s ease}
#target:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(6,182,212,.07)}
#btn{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:var(--r12);padding:14px 26px;font-family:var(--font);font-size:13px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;cursor:pointer;transition:var(--ease);display:flex;align-items:center;gap:8px;white-space:nowrap;flex-shrink:0}
#btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(6,182,212,.3)}
#btn:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}
#loader{display:none;margin-top:18px;padding:14px 18px;background:rgba(6,182,212,.04);border:1px solid var(--accent-border);border-radius:var(--r12);align-items:center;gap:14px}
#loader.show{display:flex}
.ld-spin{width:30px;height:30px;border:2px solid var(--accent-border);border-top-color:var(--accent);border-radius:50%;animation:spin .8s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.ld-bar-wrap{flex:1}
.ld-txt{font-size:11px;font-family:var(--mono);color:var(--accent);letter-spacing:.03em;margin-bottom:7px}
.ld-track{height:2px;background:rgba(6,182,212,.1);border-radius:99px;overflow:hidden}
.ld-fill{height:100%;width:0;background:linear-gradient(90deg,var(--accent),var(--accent2));border-radius:99px;animation:ldsweep 2s ease-in-out infinite}
@keyframes ldsweep{0%{width:0;margin-left:0}50%{width:60%;margin-left:15%}100%{width:0;margin-left:100%}}
#results{display:none;animation:fadeup .35s ease}
#results.show{display:block}
@keyframes fadeup{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
.res-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:10px}
.res-hdr-left{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.res-hdr-title{font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t3);display:flex;align-items:center;gap:8px}
.res-hdr-title::before{content:"";width:3px;height:14px;background:linear-gradient(var(--accent),var(--accent2));border-radius:2px;flex-shrink:0;display:inline-block}
.exp-btn{display:flex;align-items:center;gap:6px;padding:7px 13px;background:transparent;border:1px solid var(--border2);border-radius:var(--r8);color:var(--t2);font-size:11px;font-weight:600;cursor:pointer;transition:var(--ease)}
.exp-btn:hover{border-color:var(--accent-border);color:var(--accent);background:var(--accent-glow)}
.risk-badge{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:10px;font-weight:700;padding:4px 10px;border-radius:6px;text-transform:uppercase;letter-spacing:.08em}
.risk-badge.r-critical{background:rgba(239,68,68,.12);color:var(--danger);border:1px solid var(--danger-border)}
.risk-badge.r-high{background:rgba(249,115,22,.1);color:var(--warn);border:1px solid rgba(249,115,22,.25)}
.risk-badge.r-medium{background:rgba(234,179,8,.1);color:var(--med);border:1px solid rgba(234,179,8,.25)}
.risk-badge.r-low{background:rgba(34,211,238,.08);color:var(--low);border:1px solid rgba(34,211,238,.2)}
.risk-badge.r-info{background:rgba(100,116,139,.08);color:var(--info);border:1px solid var(--border)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:18px}
.sc{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);padding:18px 20px;backdrop-filter:blur(12px);position:relative;overflow:hidden;transition:var(--ease)}
.sc::after{content:"";position:absolute;bottom:0;left:0;right:0;height:2px;opacity:0;transition:var(--ease)}
.sc:hover{transform:translateY(-2px);border-color:var(--border2)}
.sc:hover::after{opacity:1}
.sc.risk::after{background:linear-gradient(90deg,var(--danger),var(--warn))}
.sc.finds::after{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.sc.ports::after{background:linear-gradient(90deg,#a855f7,var(--accent2))}
.sc.ip::after{background:linear-gradient(90deg,var(--med),var(--warn))}
.sc-lbl{font-size:9px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:var(--t4);margin-bottom:10px}
.sc-val{font-size:32px;font-weight:900;line-height:1;margin-bottom:8px;font-variant-numeric:tabular-nums}
.sc.risk .sc-val{color:var(--danger)}.sc.finds .sc-val{color:var(--accent)}.sc.ports .sc-val{color:#a855f7}
.sc.ip .sc-val{font-size:13px;padding-top:4px;color:var(--med);font-family:var(--mono)}
.sc-meta{font-size:10px;color:var(--t3);font-family:var(--mono)}
.sc-sub{font-size:9px;font-family:var(--mono);color:var(--t4);margin-top:4px}
.risk-trk{height:4px;background:rgba(255,255,255,.05);border-radius:99px;overflow:hidden;margin:8px 0 6px}
#riskBar{height:100%;background:linear-gradient(90deg,var(--med),var(--warn),var(--danger));border-radius:99px;width:0%;transition:width 1.4s cubic-bezier(.4,0,.2,1)}
.res-body{display:grid;grid-template-columns:300px 1fr;gap:16px;margin-bottom:16px}
.panel{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r16);backdrop-filter:blur(12px);overflow:hidden}
.panel-hdr{padding:14px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px}
.panel-title{font-size:10px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--t2);display:flex;align-items:center;gap:7px}
.panel-title i{color:var(--accent);font-size:11px}
.panel-body{padding:18px}
#severityBars{display:flex;flex-direction:column;gap:12px}
.sev-row .sev-hdr{display:flex;justify-content:space-between;align-items:center;margin-bottom:5px}
.sev-name{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.09em}
.sev-right{display:flex;align-items:center;gap:5px}
.sev-pct{font-size:10px;color:var(--t3);font-family:var(--mono)}
.sev-cnt{font-size:9px;font-weight:700;font-family:var(--mono);padding:1px 5px;border-radius:4px}
.sev-trk{height:5px;background:rgba(255,255,255,.04);border-radius:99px;overflow:hidden}
.progress-bar{height:100%;border-radius:99px;width:0;transition:width .9s cubic-bezier(.4,0,.2,1)}
.sev-Critical .sev-name{color:var(--danger)}.sev-Critical .sev-cnt{background:var(--danger-dim);color:var(--danger)}.bar-Critical{background:linear-gradient(90deg,#dc2626,var(--danger))}
.sev-High .sev-name{color:var(--warn)}.sev-High .sev-cnt{background:var(--warn-dim);color:var(--warn)}.bar-High{background:linear-gradient(90deg,#ea580c,var(--warn))}
.sev-Medium .sev-name{color:var(--med)}.sev-Medium .sev-cnt{background:var(--med-dim);color:var(--med)}.bar-Medium{background:linear-gradient(90deg,#ca8a04,var(--med))}
.sev-Low .sev-name{color:var(--low)}.sev-Low .sev-cnt{background:var(--low-dim);color:var(--low)}.bar-Low{background:linear-gradient(90deg,#0891b2,var(--low))}
.sev-Info .sev-name{color:var(--info)}.sev-Info .sev-cnt{background:var(--info-dim);color:var(--info)}.bar-Info{background:#475569}
#apiStatusDisplay{display:flex;flex-direction:column;gap:7px}
.vf-wrap{display:flex;gap:5px;flex-wrap:wrap}
.fb{font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;padding:3px 9px;border-radius:6px;border:1px solid var(--border2);background:transparent;color:var(--t3);cursor:pointer;transition:var(--ease)}
.fb:hover,.fb.active{background:var(--accent-glow);border-color:var(--accent-border);color:var(--accent)}
.fb.fc.active{background:var(--danger-dim);border-color:var(--danger-border);color:var(--danger)}
.fb.fh.active{background:var(--warn-dim);border-color:rgba(249,115,22,.3);color:var(--warn)}
.fb.fm.active{background:var(--med-dim);border-color:rgba(234,179,8,.3);color:var(--med)}
/* ============================================================
   SEARCH / SORT TOOLBAR
   ============================================================ */
.sif-toolbar{display:flex;align-items:center;gap:8px;padding:0 18px 12px;flex-wrap:wrap}
.sif-search-wrap{position:relative;flex:1;min-width:180px}
.sif-search{width:100%;background:rgba(4,8,18,.8);border:1px solid var(--border2);border-radius:var(--r8);padding:7px 10px 7px 30px;font-family:var(--mono);font-size:11px;color:var(--t1);outline:none;transition:var(--ease)}
.sif-search::placeholder{color:var(--t4)}
.sif-search:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(6,182,212,.06)}
.sif-search-ico{position:absolute;left:10px;top:50%;transform:translateY(-50%);font-size:10px;color:var(--t3);pointer-events:none}
.sif-sort{background:rgba(4,8,18,.8);border:1px solid var(--border2);border-radius:var(--r8);padding:7px 10px;font-family:var(--mono);font-size:10px;color:var(--t2);cursor:pointer;transition:var(--ease);-webkit-appearance:none;appearance:none;min-width:130px;outline:none}
.sif-sort:focus{border-color:var(--accent)}
.sif-sort option{background:#0a121e;color:var(--t1)}
.sif-count{font-size:9px;font-family:var(--mono);color:var(--t4);white-space:nowrap;letter-spacing:.06em}
/* ============================================================
   VULN LIST CONTAINER
   ============================================================ */
#vulnList{max-height:680px;overflow-y:auto;display:flex;flex-direction:column;gap:10px;padding:16px 18px}
/* ============================================================
   UNIFIED VULNERABILITY CARD v2.0
   Every severity tab renders this identical component.
   Description always visible. Expand = advanced details only.
   ============================================================ */
.vc{border-radius:var(--r12);padding:0;border:1px solid var(--border);background:rgba(255,255,255,.016);transition:border-color .18s ease,background .18s ease;animation:cin .25s ease both;position:relative;overflow:hidden;flex-shrink:0}
.vc::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;transition:opacity .2s}
.vc.severity-Critical::before{background:var(--danger)}.vc.severity-Critical{border-color:var(--danger-border);background:var(--danger-dim)}
.vc.severity-High::before{background:var(--warn)}.vc.severity-High{border-color:rgba(249,115,22,.2);background:var(--warn-dim)}
.vc.severity-Medium::before{background:var(--med)}.vc.severity-Medium{border-color:rgba(234,179,8,.2);background:var(--med-dim)}
.vc.severity-Low::before{background:var(--low)}.vc.severity-Low{border-color:rgba(34,211,238,.15);background:var(--low-dim)}
.vc.severity-Info::before,.vc.severity-Unknown::before{background:var(--info)}
.vc.severity-Info,.vc.severity-Unknown{border-color:var(--border);background:var(--info-dim)}
.vc:hover{border-color:rgba(255,255,255,.12)}
.vc.expanded{box-shadow:0 4px 24px rgba(0,0,0,.25)}
@keyframes cin{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:translateY(0)}}
/* --- Header row ------------------------------------------ */
.vc-hdr{display:flex;align-items:center;gap:8px;padding:12px 14px 0 16px;flex-wrap:wrap}
.vc-ids{display:flex;align-items:center;gap:8px;flex:1;min-width:0}
.vc-id{font-family:var(--mono);font-size:12.5px;font-weight:700;color:var(--accent);line-height:1;white-space:nowrap;display:flex;align-items:center}
.vc-id a{color:inherit;text-decoration:none;display:inline-flex;align-items:center}
.vc-id a:hover{text-decoration:underline}
.src-badge{display:inline-flex;align-items:center;height:18px;padding:0 6px;border-radius:3px;font-size:7.5px;font-weight:700;font-family:var(--mono);letter-spacing:.09em;text-transform:uppercase;background:rgba(255,255,255,.04);color:var(--t3);border:1px solid var(--border2);flex-shrink:0;box-sizing:border-box;line-height:1}
.sev-tags{display:flex;align-items:center;gap:6px;flex-shrink:0}
.sp{display:inline-flex;align-items:center;height:20px;padding:0 8px;border-radius:5px;font-size:9px;font-weight:700;font-family:var(--mono);letter-spacing:.07em;text-transform:uppercase;line-height:1;box-sizing:border-box;white-space:nowrap}
.sp.Critical{background:rgba(239,68,68,.14);color:var(--danger);border:1px solid var(--danger-border)}
.sp.High{background:rgba(249,115,22,.12);color:var(--warn);border:1px solid rgba(249,115,22,.25)}
.sp.Medium{background:rgba(234,179,8,.12);color:var(--med);border:1px solid rgba(234,179,8,.25)}
.sp.Low{background:rgba(34,211,238,.08);color:var(--low);border:1px solid rgba(34,211,238,.2)}
.sp.Info,.sp.Unknown{background:rgba(100,116,139,.09);color:var(--info);border:1px solid var(--border)}
.cvss-chip{display:inline-flex;align-items:center;height:20px;padding:0 8px;border-radius:4px;font-size:9px;font-weight:700;font-family:var(--mono);color:#e2e8f0;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.14);line-height:1;box-sizing:border-box;white-space:nowrap}
/* --- ALWAYS VISIBLE: product + description + metadata ---- */
.vc-visible{padding:8px 16px 12px}
.vc-prod-line{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap}
.vc-prod-name{font-size:10.5px;font-weight:600;font-family:var(--mono);color:var(--accent);display:flex;align-items:center;gap:5px}
.vc-prod-name i{font-size:9px;opacity:.7}
.vc-prod-detail{font-size:9px;font-family:var(--mono);color:var(--t3)}
.vc-desc{font-size:11px;color:var(--t2);line-height:1.65;margin-bottom:10px;word-break:break-word;display:-webkit-box;-webkit-line-clamp:4;-webkit-box-orient:vertical;overflow:hidden;position:relative}
.vc-desc.vc-desc-full{-webkit-line-clamp:unset;overflow:visible}
.vc-chips{display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin-bottom:8px}
.vc-chip{display:inline-flex;align-items:center;height:18px;padding:0 6px;border-radius:3px;font-size:7.5px;font-weight:700;font-family:var(--mono);letter-spacing:.05em;text-transform:uppercase;background:rgba(255,255,255,.03);border:1px solid var(--border);color:var(--t3);box-sizing:border-box;line-height:1;white-space:nowrap}
.vc-chip.chip-av{color:var(--accent);border-color:var(--accent-border);background:rgba(6,182,212,.06)}
.vc-chip.chip-sev{color:var(--danger);border-color:var(--danger-border);background:var(--danger-dim)}
.vc-bottom{display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.port-chip{display:inline-flex;align-items:center;height:18px;padding:0 7px;font-size:9px;font-weight:700;font-family:var(--mono);color:var(--t3);background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:4px;box-sizing:border-box;line-height:1}
.cwe-chip{display:inline-flex;align-items:center;height:18px;padding:0 6px;font-size:8px;font-family:var(--mono);color:var(--warn);background:rgba(249,115,22,.06);border:1px solid rgba(249,115,22,.18);border-radius:4px;box-sizing:border-box;line-height:1}
.date-chip{display:inline-flex;align-items:center;height:18px;font-size:8px;font-family:var(--mono);color:var(--t4);line-height:1}
.vec-chip{display:inline-flex;align-items:center;height:18px;padding:0 5px;font-size:8px;font-family:var(--mono);color:var(--t4);background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:3px;max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;box-sizing:border-box;line-height:1}
.na-chip{display:inline-flex;align-items:center;height:18px;padding:0 6px;font-size:8px;font-family:var(--mono);color:var(--t4);background:transparent;border:1px solid var(--border);border-radius:3px;opacity:.5;line-height:1}
.kev-chip{display:inline-flex;align-items:center;gap:4px;height:18px;padding:0 7px;font-size:8px;font-weight:700;font-family:var(--mono);letter-spacing:.06em;text-transform:uppercase;color:#fff;background:linear-gradient(90deg,#dc2626,#ef4444);border-radius:4px;box-sizing:border-box;line-height:1;animation:kevpulse 2s infinite}
@keyframes kevpulse{0%,100%{opacity:1}50%{opacity:.72}}
.vc.vc-kev{border-color:var(--danger-border);box-shadow:0 0 0 1px rgba(239,68,68,.15) inset}
.vc.vc-kev::before{background:var(--danger)!important;width:4px}
/* --- Expand toggle --------------------------------------- */
.vc-expand-btn{display:flex;align-items:center;justify-content:center;gap:5px;padding:6px 16px;border-top:1px solid rgba(255,255,255,.04);font-size:8px;font-family:var(--mono);font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--t4);cursor:pointer;user-select:none;transition:var(--ease)}
.vc-expand-btn:hover{color:var(--accent);background:rgba(6,182,212,.03)}
.vc-expand-btn i{font-size:8px;transition:transform .22s ease}
.vc.expanded .vc-expand-btn i{transform:rotate(180deg)}
/* --- Expandable advanced section ------------------------- */
.vc-adv{max-height:0;overflow:hidden;transition:max-height .3s cubic-bezier(.4,0,.2,1)}
.vc.expanded .vc-adv{max-height:1500px}
.vc-adv-inner{padding:10px 16px 14px;border-top:1px solid rgba(255,255,255,.05)}
.vc-adv-title{font-size:8px;font-weight:700;font-family:var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--t4);margin-bottom:8px}
.vc-adv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px}
.vc-adv-item{font-size:9px;color:var(--t3);font-family:var(--mono)}
.vc-adv-item strong{color:var(--t2);display:block;font-size:8px;letter-spacing:.08em;text-transform:uppercase;margin-bottom:2px}
.vc-adv-desc{font-size:10.5px;color:var(--t2);line-height:1.6;word-break:break-word;margin-bottom:10px}
.vc-adv-link{display:inline-flex;align-items:center;gap:4px;font-size:9px;font-family:var(--mono);color:var(--accent);text-decoration:none;padding:3px 8px;border:1px solid var(--accent-border);border-radius:4px;transition:var(--ease)}
.vc-adv-link:hover{background:var(--accent-glow)}
/* ============================================================
   ATTACK PROBABILITY ANALYSIS PANEL
   ============================================================ */
.attack-prob-panel{margin-top:16px;grid-column:1/-1}
.ap-disclaimer{font-size:9px;color:var(--t4);font-family:var(--mono);line-height:1.55;padding:10px 18px;border-bottom:1px solid var(--border);font-style:italic}
.ap-body{padding:18px;display:flex;flex-direction:column;gap:18px}
.ap-summary{font-size:11px;color:var(--t2);line-height:1.65;padding:12px 14px;background:rgba(6,182,212,.04);border:1px solid var(--accent-border);border-radius:var(--r8);word-break:break-word}
.ap-summary strong{color:var(--accent)}
.ap-bars{display:flex;flex-direction:column;gap:8px}
.ap-bar-row{display:flex;align-items:center;gap:10px}
.ap-bar-label{font-size:9px;font-family:var(--mono);color:var(--t2);width:150px;flex-shrink:0;text-transform:uppercase;letter-spacing:.05em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.ap-bar-track{flex:1;height:8px;background:rgba(255,255,255,.04);border-radius:99px;overflow:hidden;min-width:60px}
.ap-bar-fill{height:100%;border-radius:99px;transition:width .8s cubic-bezier(.4,0,.2,1);min-width:0}
.ap-bar-fill.ap-critical{background:linear-gradient(90deg,#dc2626,var(--danger))}
.ap-bar-fill.ap-vhigh{background:linear-gradient(90deg,#ea580c,var(--warn))}
.ap-bar-fill.ap-high{background:linear-gradient(90deg,#ca8a04,var(--med))}
.ap-bar-fill.ap-medium{background:linear-gradient(90deg,var(--accent),var(--accent2))}
.ap-bar-fill.ap-low{background:linear-gradient(90deg,#0891b2,var(--low))}
.ap-bar-fill.ap-minimal{background:#475569}
.ap-bar-pct{font-size:10px;font-weight:700;font-family:var(--mono);color:var(--t1);width:38px;text-align:right;flex-shrink:0}
.ap-bar-class{font-size:7px;font-family:var(--mono);font-weight:700;letter-spacing:.08em;text-transform:uppercase;width:60px;text-align:right;flex-shrink:0}
.ap-bar-class.cls-critical{color:var(--danger)}.ap-bar-class.cls-vhigh{color:var(--warn)}.ap-bar-class.cls-high{color:var(--med)}.ap-bar-class.cls-medium{color:var(--accent)}.ap-bar-class.cls-low{color:var(--low)}.ap-bar-class.cls-minimal{color:var(--info)}
.ap-charts{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:4px}
.ap-chart-wrap{background:rgba(255,255,255,.015);border:1px solid var(--border);border-radius:var(--r12);padding:14px;text-align:center}
.ap-chart-title{font-size:8px;font-weight:700;font-family:var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--t4);margin-bottom:10px}
.ap-chart-svg{max-width:220px;margin:0 auto;display:block}
.ap-legend{display:flex;flex-wrap:wrap;gap:6px;justify-content:center;margin-top:8px}
.ap-legend-item{display:flex;align-items:center;gap:4px;font-size:8px;font-family:var(--mono);color:var(--t3)}
.ap-legend-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0}
/* ============================================================
   SKELETON / SHIMMER LOADERS
   ============================================================ */
@keyframes shimmer{0%{background-position:-200px 0}100%{background-position:200px 0}}
.skel-card{border-radius:var(--r12);border:1px solid var(--border);padding:14px 16px;margin-bottom:10px;animation:cin .25s ease both}
.skel-line{height:10px;border-radius:4px;background:linear-gradient(90deg,rgba(255,255,255,.03) 25%,rgba(255,255,255,.06) 50%,rgba(255,255,255,.03) 75%);background-size:400px 100%;animation:shimmer 1.4s infinite linear;margin-bottom:8px}
.skel-line.w70{width:70%}.skel-line.w50{width:50%}.skel-line.w90{width:90%}.skel-line.w40{width:40%}
.skel-chips{display:flex;gap:6px;margin-top:4px}
.skel-chip{width:50px;height:18px;border-radius:4px;background:linear-gradient(90deg,rgba(255,255,255,.03) 25%,rgba(255,255,255,.06) 50%,rgba(255,255,255,.03) 75%);background-size:400px 100%;animation:shimmer 1.4s infinite linear}
/* ============================================================
   EMPTY STATE (enhanced)
   ============================================================ */
.empty-s{padding:40px 20px;text-align:center;color:var(--t4);font-family:var(--mono);font-size:12px;display:flex;flex-direction:column;align-items:center;gap:10px}
.empty-s i{font-size:26px}
.empty-s .empty-hint{font-size:10px;color:var(--t4);opacity:.6;margin-top:2px}
/* ============================================================
   PORT GRID + SVC CARDS + ERROR TOAST (preserved)
   ============================================================ */
#portGrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:10px;max-height:420px;overflow-y:auto;padding:16px 18px}
.svc-card{background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:var(--r12);padding:14px;display:flex;align-items:flex-start;gap:10px;transition:var(--ease);animation:cin .25s ease both}
.svc-card:hover{transform:translateY(-2px);border-color:var(--accent-border);background:var(--accent-glow);box-shadow:0 6px 20px rgba(6,182,212,.07)}
.svc-ico{width:34px;height:34px;border-radius:8px;background:rgba(6,182,212,.08);border:1px solid var(--accent-border);display:flex;align-items:center;justify-content:center;color:var(--accent);font-size:12px;flex-shrink:0}
.svc-info{flex:1;min-width:0}
.svc-nm{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--t1);margin-bottom:2px;display:flex;align-items:center;justify-content:space-between;gap:4px}
.open-pill{font-size:7px;font-weight:700;font-family:var(--mono);color:#22c55e;background:rgba(34,197,94,.08);border:1px solid rgba(34,197,94,.2);padding:1px 4px;border-radius:3px;letter-spacing:.06em}
.svc-port{font-family:var(--mono);font-size:10px;color:var(--accent);font-weight:600;margin-bottom:2px}
.svc-prod{font-size:9px;color:var(--t4);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
#error-toast{position:fixed;bottom:20px;right:20px;z-index:9999;background:rgba(20,5,5,.97);border:1px solid rgba(239,68,68,.35);color:var(--t1);padding:12px 16px;border-radius:var(--r12);display:flex;align-items:center;gap:10px;max-width:380px;backdrop-filter:blur(16px);box-shadow:0 8px 32px rgba(0,0,0,.5);transform:translateY(120%);opacity:0;pointer-events:none;transition:transform .3s cubic-bezier(.34,1.56,.64,1),opacity .25s ease}
#error-toast.show{transform:translateY(0);opacity:1;pointer-events:auto}
.t-ico{width:30px;height:30px;border-radius:8px;background:rgba(239,68,68,.12);display:flex;align-items:center;justify-content:center;color:var(--danger);font-size:12px;flex-shrink:0}
.t-body{flex:1}
.t-ttl{font-size:10px;font-weight:700;color:var(--danger);margin-bottom:2px;text-transform:uppercase;letter-spacing:.06em}
#error-msg{font-size:12px;color:var(--t2);line-height:1.45}
.t-close{background:none;border:none;color:var(--t3);cursor:pointer;font-size:16px;transition:var(--ease);padding:0;line-height:1}
.t-close:hover{color:var(--t1)}
#sb-ov{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:150;opacity:0;pointer-events:none;transition:opacity .28s ease}
#sb-ov.on{opacity:1;pointer-events:auto}
/* ============================================================
   RESPONSIVE BREAKPOINTS (v2.0)
   ============================================================ */
@media(max-width:1024px){:root{--sidebar:0px}#sb{transform:translateX(-260px);width:260px}#sb.open{transform:translateX(0)}#main{margin-left:0}#sbtoggle{display:flex;align-items:center}.res-body{grid-template-columns:1fr}.stats{grid-template-columns:repeat(2,1fr)}.ap-charts{grid-template-columns:1fr}.ap-bar-label{width:120px}}
@media(max-width:768px){#pg{padding:14px}.scan-panel{padding:20px 18px}.scan-ph h1{font-size:16px}.scan-row{flex-direction:column}#btn{width:100%;justify-content:center}.stats{grid-template-columns:repeat(2,1fr);gap:10px}.sc-val{font-size:28px}#portGrid{grid-template-columns:repeat(auto-fill,minmax(160px,1fr))}.tb-pill:last-child{display:none}.res-hdr{flex-direction:column;align-items:flex-start}.sif-toolbar{flex-direction:column}.sif-search-wrap{min-width:100%}.vc-hdr{flex-wrap:wrap;gap:6px}.vc-chips{gap:4px}.ap-bar-label{width:90px;font-size:8px}.ap-charts{grid-template-columns:1fr}}
@media(max-width:480px){:root{--topbar:54px}#pg{padding:10px}.scan-panel{padding:16px 14px;border-radius:var(--r16)}.eng-badge{display:none}.stats{grid-template-columns:1fr 1fr;gap:8px}.sc{padding:14px 16px}.sc-val{font-size:24px}.sc.ip .sc-val{font-size:12px}#vulnList{padding:10px 12px;max-height:none}#portGrid{grid-template-columns:1fr 1fr;padding:10px 12px}.panel-hdr{padding:12px 14px}.panel-body{padding:14px}.vc-visible{padding:6px 12px 10px}.ap-bar-row{flex-wrap:wrap;gap:4px}.ap-bar-label{width:100%;font-size:9px}.ap-bar-class{display:none}}
@media(max-width:360px){.stats{grid-template-columns:1fr}#portGrid{grid-template-columns:1fr}}
/* ============================================================
   MODULAR PIPELINE UI (Modules 1-4)
   ============================================================ */
.scan-mode{background:rgba(255,255,255,.03);border:1px solid var(--border2);border-radius:var(--r8);color:var(--t1);font-family:var(--mono);font-size:11px;padding:0 10px;height:38px;cursor:pointer;outline:none;transition:var(--ease)}
.auth-row{margin-top:10px;display:flex;gap:10px;align-items:center}
.auth-inp{flex:1;background:rgba(255,255,255,.03);border:1px solid var(--border2);border-radius:var(--r8);color:var(--t1);font-family:var(--mono);font-size:11.5px;padding:0 12px;height:34px;outline:none;transition:var(--ease)}
.auth-inp:focus{border-color:var(--accent-border);box-shadow:0 0 0 2px var(--accent-glow)}
.auth-lbl{font-family:var(--mono);font-size:10px;color:var(--t3);white-space:nowrap;display:flex;align-items:center;gap:6px}
.scan-mode:focus{border-color:var(--accent-border);box-shadow:0 0 0 2px var(--accent-glow)}
.scan-mode option{background:#0a121e;color:var(--t1)}
.vs-panel{display:none}.vs-panel.show{display:block;animation:cin .3s ease both}
.vs-table{width:100%;border-collapse:collapse;font-size:12.5px}
.vs-table th{font-family:var(--mono);font-size:10px;text-transform:uppercase;letter-spacing:.1em;color:#9fd8e8;text-align:left;padding:9px 14px;border-bottom:1px solid var(--border2)}
.vs-table td{padding:8px 14px;border-bottom:1px solid rgba(30,41,59,.4);font-family:var(--mono);font-size:12px;color:var(--t1);vertical-align:top}
.vs-table tr:last-child td{border-bottom:none}
.vs-table tbody tr:hover td{background:rgba(6,182,212,.05)}
.st-pill{font-size:10px;font-weight:700;font-family:var(--mono);padding:2px 8px;border-radius:4px;letter-spacing:.04em;white-space:nowrap}
.st-200{color:#4ade80;background:rgba(34,197,94,.12);border:1px solid rgba(34,197,94,.3)}
.st-3xx{color:#60a5fa;background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.3)}
.st-403{color:#fb923c;background:rgba(249,115,22,.12);border:1px solid rgba(249,115,22,.35)}
.st-404{color:#94a3b8;background:rgba(100,116,139,.12);border:1px solid rgba(100,116,139,.3)}
.st-err{color:#f87171;background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.35)}
.vuln-hit{padding:14px 16px;border:1px solid var(--danger-border);background:var(--danger-dim);border-radius:var(--r12);margin:10px 14px;animation:cin .25s ease both}
.vh-h{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.vh-type{font-size:12px;font-weight:800;font-family:var(--mono);color:#f87171;text-transform:uppercase;letter-spacing:.08em}
.vh-url{font-size:11.5px;font-family:var(--mono);color:#c9d5e3;word-break:break-all;margin-bottom:5px}
.vh-ev{font-size:11.5px;font-family:var(--mono);color:#fbbf24;line-height:1.6}
.recon-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;padding:16px 18px}
.recon-cell{background:rgba(255,255,255,.03);border:1px solid var(--border2);border-radius:var(--r12);padding:14px}
.recon-cell h4{font-size:10.5px;font-weight:700;font-family:var(--mono);color:#67e8f9;text-transform:uppercase;letter-spacing:.1em;margin-bottom:9px}
.recon-cell .rc-v{font-family:var(--mono);font-size:12.5px;color:var(--t1);line-height:1.8;word-break:break-word}
.rc-dim{color:var(--t3);font-size:11px}
.whois-pre{max-height:300px;overflow:auto;padding:16px 18px;margin:0;font-family:var(--mono);font-size:12px;line-height:1.8;color:#c9d5e3;white-space:pre-wrap;word-break:break-word}
@media(max-width:768px){.recon-grid{grid-template-columns:1fr}.scan-mode{width:100%;height:36px}}
/* ============================================================
   V6.0 — ADVANCED SCANNER UI (profiles, stages, new modules)
   ============================================================ */
.scan-opts{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:10px}
.seg{display:inline-flex;background:rgba(255,255,255,.03);border:1px solid var(--border2);border-radius:9px;padding:3px;gap:2px}
.seg-btn{border:none;background:transparent;color:var(--t3);font-family:var(--mono);font-size:10px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:6px 12px;border-radius:6px;cursor:pointer;transition:var(--ease)}
.seg-btn:hover{color:var(--t1)}
.seg-btn.active{background:linear-gradient(135deg,rgba(6,182,212,.18),rgba(59,130,246,.16));color:var(--accent);box-shadow:inset 0 0 0 1px var(--accent-border)}
.opt-lbl{font-family:var(--mono);font-size:9px;color:var(--t4);letter-spacing:.12em;text-transform:uppercase}
.chk{display:inline-flex;align-items:center;gap:6px;font-family:var(--mono);font-size:10px;color:var(--t3);cursor:pointer;user-select:none}
.chk input{accent-color:var(--accent);width:13px;height:13px;cursor:pointer}
#stageTrack{display:none;gap:6px;flex-wrap:wrap;margin-bottom:16px}
#stageTrack.show{display:flex}
.stage{display:flex;align-items:center;gap:7px;padding:7px 11px;background:var(--bg-card);border:1px solid var(--border);border-radius:9px;font-family:var(--mono);font-size:9.5px;color:var(--t3);transition:var(--ease)}
.stage.done{border-color:rgba(34,197,94,.25);color:#86efac;background:rgba(34,197,94,.05)}
.stage i{font-size:9px}
.stage .st-ms{color:var(--t4);font-size:8.5px}
.stage.done .st-ms{color:#4ade80}
.exp-menu{position:relative}
.exp-drop{position:absolute;right:0;top:calc(100% + 6px);min-width:196px;background:#0a1220;border:1px solid var(--border2);border-radius:10px;padding:5px;display:none;z-index:60;box-shadow:0 14px 36px rgba(0,0,0,.55)}
.exp-drop.open{display:block;animation:fadeup .16s ease}
.exp-item{display:flex;align-items:center;gap:8px;width:100%;padding:8px 10px;border:none;background:transparent;color:var(--t2);font-family:var(--mono);font-size:10.5px;text-align:left;border-radius:7px;cursor:pointer;transition:var(--ease)}
.exp-item:hover{background:var(--accent-glow);color:var(--accent)}
.exp-item i{width:13px;font-size:10px;opacity:.85}
/* --- Spider / tech --- */
.spider-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(105px,1fr));gap:9px;padding:16px 18px 4px}
.sp-stat{background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:10px;padding:11px 13px}
.sp-stat .n{font-size:19px;font-weight:800;color:var(--accent);font-variant-numeric:tabular-nums}
.sp-stat .l{font-size:8.5px;font-family:var(--mono);color:var(--t4);letter-spacing:.1em;text-transform:uppercase;margin-top:2px}
.tech-wrap{display:flex;flex-wrap:wrap;gap:6px;padding:12px 18px 16px}
.tech-chip{display:inline-flex;align-items:center;gap:5px;padding:4px 9px;border-radius:6px;background:rgba(6,182,212,.05);border:1px solid var(--accent-border);color:var(--t2);font-family:var(--mono);font-size:9.5px}
.tech-chip b{color:var(--accent);font-weight:700}
.tech-chip .ver{color:var(--warn);font-size:8.5px}
.url-list{max-height:360px;overflow-y:auto;padding:8px 14px 14px}
.url-row{display:flex;align-items:center;gap:9px;padding:6px 4px;border-bottom:1px solid rgba(30,41,59,.4);font-family:var(--mono);font-size:10.5px}
.url-row:last-child{border:none}
.url-row .u{color:var(--t2);word-break:break-all;flex:1;min-width:0}
.url-row .u:hover{color:var(--accent)}
/* --- Passive alerts table --- */
.alert-row{display:grid;grid-template-columns:78px 1fr 74px;gap:10px;padding:11px 16px;border-bottom:1px solid var(--border);align-items:start}
.alert-row:last-child{border:none}
.alert-row:hover{background:rgba(6,182,212,.03)}
.alert-name{font-size:11.5px;font-weight:600;color:var(--t1);margin-bottom:3px}
.alert-ev{font-size:10px;font-family:var(--mono);color:var(--t3);line-height:1.5;word-break:break-word}
.alert-meta{display:flex;gap:6px;flex-wrap:wrap;margin-top:5px}
.conf-chip{display:inline-flex;align-items:center;height:17px;padding:0 6px;border-radius:3px;font-family:var(--mono);font-size:7.5px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;background:rgba(59,130,246,.09);color:#93c5fd;border:1px solid rgba(59,130,246,.22)}
.conf-chip.high{background:rgba(34,197,94,.08);color:#4ade80;border-color:rgba(34,197,94,.22)}
.conf-chip.low{background:rgba(234,179,8,.08);color:#facc15;border-color:rgba(234,179,8,.22)}
.rule-chip{font-family:var(--mono);font-size:7.5px;color:var(--t4);letter-spacing:.05em;padding:2px 5px;border:1px solid var(--border);border-radius:3px}
.sev-bar{display:inline-flex;align-items:center;justify-content:center;min-width:66px;height:20px;padding:0 7px;border-radius:5px;font-family:var(--mono);font-size:8.5px;font-weight:800;text-transform:uppercase;letter-spacing:.07em}
.sev-bar.Critical{background:rgba(239,68,68,.14);color:#f87171;border:1px solid rgba(239,68,68,.3)}
.sev-bar.High{background:rgba(249,115,22,.12);color:#fb923c;border:1px solid rgba(249,115,22,.28)}
.sev-bar.Medium{background:rgba(234,179,8,.1);color:#facc15;border:1px solid rgba(234,179,8,.26)}
.sev-bar.Low{background:rgba(34,211,238,.08);color:#67e8f9;border:1px solid rgba(34,211,238,.22)}
.sev-bar.Info{background:rgba(148,163,184,.09);color:#cbd5e1;border:1px solid var(--border2)}
/* --- Evidence / solution blocks in cards --- */
.ev-grid{display:grid;gap:8px;margin-top:10px}
.ev-block{background:rgba(2,6,16,.55);border:1px solid var(--border);border-radius:8px;padding:9px 11px}
.ev-block .ev-lbl{font-family:var(--mono);font-size:7.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--t4);margin-bottom:4px;display:flex;align-items:center;gap:5px}
.ev-block .ev-val{font-family:var(--mono);font-size:10px;line-height:1.6;color:var(--t2);word-break:break-word}
.ev-block.sol{border-color:rgba(34,197,94,.2);background:rgba(34,197,94,.03)}
.ev-block.sol .ev-val{color:#bbf7d0}
.ref-link{display:inline-flex;align-items:center;gap:5px;font-family:var(--mono);font-size:9px;color:var(--accent);text-decoration:none;margin-top:9px}
.ref-link:hover{text-decoration:underline}
/* --- Intel lookup --- */
.intel-head{display:flex;gap:8px;flex-wrap:wrap;padding:16px 18px 4px}
.intel-inp{flex:1;min-width:220px;background:rgba(4,8,18,.9);border:1px solid var(--border2);border-radius:9px;padding:11px 13px;font-family:var(--mono);font-size:12px;color:var(--t1);outline:none;transition:var(--ease)}
.intel-inp:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(6,182,212,.06)}
.intel-btn{background:linear-gradient(135deg,var(--accent),var(--accent2));border:none;border-radius:9px;color:#fff;font-family:var(--font);font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;padding:0 20px;cursor:pointer;transition:var(--ease);display:flex;align-items:center;gap:6px}
.intel-btn:hover{transform:translateY(-1px);box-shadow:0 8px 22px rgba(6,182,212,.25)}
.intel-btn:disabled{opacity:.45;cursor:not-allowed;transform:none;box-shadow:none}
.intel-hint{font-size:9.5px;font-family:var(--mono);color:var(--t4);padding:8px 18px 0}
.intel-results{padding:14px 18px;display:flex;flex-direction:column;gap:9px;max-height:560px;overflow-y:auto}
.intel-card{border:1px solid var(--border);border-radius:10px;padding:12px 14px;background:rgba(255,255,255,.016);transition:var(--ease)}
.intel-card:hover{border-color:var(--accent-border);background:var(--accent-glow)}
.intel-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.intel-id{font-family:var(--mono);font-size:12.5px;font-weight:700;color:var(--accent)}
.intel-id a{color:inherit;text-decoration:none}.intel-id a:hover{text-decoration:underline}
.intel-sum{font-size:11px;color:var(--t2);line-height:1.6}
.intel-tags{display:flex;gap:5px;flex-wrap:wrap;margin-top:7px}
/* --- History --- */
.hist-row{display:flex;align-items:center;gap:12px;padding:10px 16px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:10.5px}
.hist-row:last-child{border:none}
.hist-row:hover{background:rgba(6,182,212,.03)}
.hist-t{flex:1;min-width:0;color:var(--t1);word-break:break-all}
.hist-sub{color:var(--t4);font-size:9px;margin-top:2px}
.hist-ok{background:transparent;border:1px solid var(--border2);color:var(--t3);border-radius:6px;padding:4px 9px;font-family:var(--mono);font-size:9px;cursor:pointer;transition:var(--ease)}
.hist-ok:hover{border-color:var(--accent-border);color:var(--accent)}
/* --- Polish pass --- */
.scan-panel{background:linear-gradient(180deg,rgba(10,18,30,.95),rgba(6,12,22,.92))}
.panel{box-shadow:0 1px 0 rgba(255,255,255,.02) inset}
.nav-a i{transition:var(--ease)}
.nav-a:hover i{transform:translateX(1px)}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
/* ===== V7.0 — Threat Intelligence Hub & Consoles ===== */
.vs-tabs{display:flex;gap:6px;padding:10px 14px 0;flex-wrap:wrap}
.vs-tab{background:transparent;border:1px solid transparent;color:var(--t3);font-size:11px;font-weight:600;padding:7px 14px;border-radius:20px;cursor:pointer;transition:var(--ease)}
.vs-tab:hover{color:var(--t1)}
.vs-tab.active{background:var(--accent-glow);color:var(--accent);border-color:var(--accent-border)}
.mi-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px;padding:16px 18px}
.mi-inp{width:100%;background:rgba(4,8,18,.9);border:1px solid var(--border2);border-radius:var(--r8);padding:10px 12px;font-family:var(--mono);font-size:11px;color:var(--t1);outline:none;transition:var(--ease)}
.mi-inp:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(6,182,212,.07)}
.mi-inp::placeholder{color:var(--t4)}
select.mi-inp option{background:#0a1220;color:var(--t1)}
.vs-submit{background:linear-gradient(135deg,var(--accent),var(--accent2));color:#fff;border:none;border-radius:var(--r8);padding:10px 18px;font-size:11px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;cursor:pointer;transition:var(--ease);display:inline-flex;align-items:center;gap:7px}
.vs-submit:hover{transform:translateY(-1px);box-shadow:0 6px 18px rgba(6,182,212,.25)}
.vs-submit:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}
.vs-ghost{background:transparent;border:1px solid var(--border2);color:var(--t2);border-radius:var(--r8);padding:9px 14px;font-size:10px;font-weight:600;cursor:pointer;transition:var(--ease);display:inline-flex;align-items:center;gap:6px}
.vs-ghost:hover{border-color:var(--accent-border);color:var(--accent)}
.mi-actions{grid-column:1/-1;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.form-note{grid-column:1/-1;font-size:10px;color:var(--t4);font-family:var(--mono);letter-spacing:.02em}
/* Feed */
.feed-src-wrap{display:flex;gap:10px;align-items:center;padding:14px 18px 4px;flex-wrap:wrap}
.feed-list{display:flex;flex-direction:column;gap:10px;padding:14px 18px 18px;max-height:560px;overflow-y:auto}
.feed-card{border:1px solid var(--border);border-left:3px solid var(--sev,var(--accent));border-radius:var(--r8);padding:12px 14px;background:rgba(4,8,18,.5);transition:var(--ease)}
.feed-card:hover{border-color:var(--border2);background:rgba(4,8,18,.75)}
.feed-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:6px}
.feed-id{font-family:var(--mono);font-size:11.5px;font-weight:700;color:var(--accent)}
.feed-id a{color:inherit;text-decoration:none}.feed-id a:hover{text-decoration:underline}
.feeder-chip{font-family:var(--mono);font-size:8.5px;color:var(--t3);border:1px solid var(--border2);border-radius:4px;padding:2px 6px;text-transform:uppercase;letter-spacing:.06em}
.feed-sum{font-size:11.5px;color:var(--t2);line-height:1.55}
.feed-foot{display:flex;gap:12px;margin-top:7px;font-family:var(--mono);font-size:9px;color:var(--t4);flex-wrap:wrap}
/* Hazard */
.hz-top{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;padding:16px 18px 6px}
.hz-card{border:1px solid var(--border2);border-radius:var(--r12);padding:16px;background:rgba(4,8,18,.55);position:relative;overflow:hidden}
.hz-card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:var(--hzc,var(--accent));box-shadow:0 0 10px var(--hzc,var(--accent))}
.hz-id{font-family:var(--mono);font-size:12px;font-weight:700;color:var(--t1);display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px}
.hz-band{font-family:var(--mono);font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;padding:3px 9px;border-radius:5px;background:color-mix(in srgb,var(--hzc) 14%,transparent);color:var(--hzc);border:1px solid color-mix(in srgb,var(--hzc) 40%,transparent)}
.hz-gauge{display:flex;align-items:center;gap:12px;margin-bottom:10px}
.hz-pct{font-family:var(--mono);font-size:26px;font-weight:800;color:var(--hzc);min-width:64px}
.hz-trk{flex:1;height:5px;background:rgba(148,163,184,.12);border-radius:99px;overflow:hidden}
.hz-fill{height:100%;width:0;border-radius:99px;background:var(--hzc);transition:width 1s cubic-bezier(.4,0,.2,1)}
.hz-meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px;font-family:var(--mono);font-size:9.5px;color:var(--t3)}
.hz-meta b{display:block;color:var(--t2);font-weight:600;font-size:10px;margin-bottom:1px}
.hz-agg{margin:14px 18px 18px;border:1px dashed var(--accent-border);border-radius:var(--r10,12px);padding:13px 16px;background:var(--accent-glow);display:flex;gap:26px;flex-wrap:wrap;font-family:var(--mono)}
.hz-agg .n{font-size:19px;font-weight:800;color:var(--accent)}
.hz-agg .l{font-size:9px;color:var(--t3);text-transform:uppercase;letter-spacing:.08em;margin-top:2px}
/* Watchlists */
.wl-table-wrap{max-height:340px;overflow-y:auto}
.notif-feed{max-height:230px;overflow-y:auto;border-top:1px solid var(--border)}
.notif-row{display:flex;align-items:flex-start;gap:10px;padding:9px 18px;border-bottom:1px solid var(--border);font-size:11px}
.notif-row:last-child{border:none}
.notif-ico{color:var(--accent);font-size:11px;padding-top:2px;width:16px;text-align:center;flex-shrink:0}
.notif-body{flex:1;color:var(--t2);line-height:1.5}
.notif-meta{font-family:var(--mono);font-size:8.5px;color:var(--t4);margin-top:2px}
/* Proxy */
.proxy-hist table{width:100%}
.proxy-pre{background:rgba(2,4,9,.85);border:1px solid var(--border2);border-radius:var(--r8);padding:13px 15px;font-family:var(--mono);font-size:10.5px;line-height:1.6;color:var(--t2);white-space:pre-wrap;word-break:break-word;max-height:340px;overflow:auto}
.proxy-pre .sep{color:var(--t4);margin:8px 0;display:block}
.ctx-row{display:flex;align-items:center;gap:10px;padding:9px 18px;border-bottom:1px solid var(--border);font-size:11.5px}
.ctx-row:last-child{border:none}
.ctx-name{font-weight:600;color:var(--t1);min-width:130px}
.ctx-meta{font-family:var(--mono);font-size:9px;color:var(--t3);flex:1}
.wmark-dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
/* Login indicator on context */
.ind-chip{font-family:var(--mono);font-size:8.5px;border-radius:4px;padding:2px 6px;text-transform:uppercase}
/* deepOpts selects inheritance */
.scan-opts select.opt-sel{background:rgba(4,8,18,.9);border:1px solid var(--border2);border-radius:var(--r8);padding:7px 10px;font-family:var(--mono);font-size:10px;color:var(--t1);outline:none;cursor:pointer}
.scan-opts select.opt-sel:focus{border-color:var(--accent)}
.opt-sep{width:1px;height:20px;background:var(--border2)}
@media(max-width:768px){.mi-grid{grid-template-columns:1fr}.hz-top{grid-template-columns:1fr}.hz-agg{gap:14px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}}
@media(max-width:768px){.alert-row{grid-template-columns:66px 1fr}.alert-row .sev-bar{min-width:60px}.scan-opts{gap:8px}.seg{width:100%;justify-content:space-between}.seg-btn{flex:1;padding:7px 6px;font-size:9px}.intel-head{padding:12px 14px 0}.intel-results{padding:10px 12px}.exp-drop{right:auto;left:0}}
</style>
</head>
<body>
<canvas id="bgc"></canvas>
<div id="error-toast">
  <div class="t-ico"><i class="fas fa-triangle-exclamation"></i></div>
  <div class="t-body"><div class="t-ttl">Scan Error</div><span id="error-msg"></span></div>
  <button class="t-close" onclick="hideError()">&times;</button>
</div>
<div id="shell">
<aside id="sb">
  <div class="sb-logo">
    <img src="logo.png" alt="VulnScope Pro" style="width:38px;height:38px;object-fit:contain;border-radius:8px;flex-shrink:0;filter:drop-shadow(0 0 8px rgba(6,182,212,.5))" onerror="this.style.display='none'">
    <div class="sb-logo-txt"><h2>VulnScope <span>Pro</span></h2><p>Exploit Intelligence v6.1</p></div>
  </div>
  <nav class="sb-nav">
    <div class="nav-lbl">Platform</div>
    <a class="nav-a active" id="navScan" href="#" onclick="setActiveNav(this);closeSB();document.getElementById('pg').scrollIntoView({behavior:'smooth',block:'start'});return false"><i class="fas fa-radar"></i>Scan Console</a>
    <a class="nav-a" id="navFeed" href="#" onclick="setActiveNav(this);toResults();return false"><i class="fas fa-shield-halved"></i>Intelligence Feed</a>
    <a class="nav-a" id="navAttack" href="#" onclick="setActiveNav(this);toAttackProb();return false"><i class="fas fa-chart-simple"></i>Attack Probability</a>
    <a class="nav-a" id="navInfra" href="#" onclick="setActiveNav(this);toInfra();return false"><i class="fas fa-network-wired"></i>Infrastructure Map</a>
    <div class="nav-lbl" style="margin-top:6px">Modules</div>
    <a class="nav-a" id="navRecon" href="#" onclick="setActiveNav(this);toPanel('reconPanel');return false"><i class="fas fa-satellite"></i>M1 Recon</a>
    <a class="nav-a" id="navFuzz" href="#" onclick="setActiveNav(this);toPanel('fuzzPanel');return false"><i class="fas fa-folder-tree"></i>M2 Fuzzer</a>
    <a class="nav-a" id="navPayload" href="#" onclick="setActiveNav(this);toPanel('payloadPanel');return false"><i class="fas fa-syringe"></i>M3 Payloads</a>
    <div class="nav-lbl" style="margin-top:6px">Advanced Scanner</div>
    <a class="nav-a" id="navSpider" href="#" onclick="setActiveNav(this);toPanel('spiderPanel');return false"><i class="fas fa-spider"></i>Spider / Crawler</a>
    <a class="nav-a" id="navPassive" href="#" onclick="setActiveNav(this);toPanel('passivePanel');return false"><i class="fas fa-filter"></i>Passive Scan</a>
    <a class="nav-a" id="navActive" href="#" onclick="setActiveNav(this);toPanel('activePanel');return false"><i class="fas fa-bolt"></i>Active Scan</a>
    <a class="nav-a" id="navIntel" href="#" onclick="setActiveNav(this);toIntel();return false"><i class="fas fa-magnifying-glass-chart"></i>Intel Lookup</a>
    <a class="nav-a" id="navHistory" href="#" onclick="setActiveNav(this);toHistory();return false"><i class="fas fa-clock-rotate-left"></i>Scan History</a>
    <a class="nav-a" id="navHazard" href="#" onclick="setActiveNav(this);openHazard();return false"><i class="fas fa-wave-square"></i>Exploit Hazard</a>
    <div class="nav-lbl" style="margin-top:6px">Threat Intel</div>
    <a class="nav-a" id="navFeedP" href="#" onclick="setActiveNav(this);openFeed();return false"><i class="fas fa-newspaper"></i>Advisory Feed</a>
    <a class="nav-a" id="navSight" href="#" onclick="setActiveNav(this);openSightings();return false"><i class="fas fa-eye"></i>Sightings</a>
    <a class="nav-a" id="navCollab" href="#" onclick="setActiveNav(this);openCollab();return false"><i class="fas fa-notes-medical"></i>Notes &amp; Bundles</a>
    <div class="nav-lbl" style="margin-top:6px">Watch &amp; Respond</div>
    <a class="nav-a" id="navWatch" href="#" onclick="setActiveNav(this);openWatch();return false"><i class="fas fa-bell"></i>Watchlists</a>
    <div class="nav-lbl" style="margin-top:6px">Proxy &amp; Config</div>
    <a class="nav-a" id="navProxy" href="#" onclick="setActiveNav(this);openProxy();return false"><i class="fas fa-shuffle"></i>HTTP Proxy</a>
    <a class="nav-a" id="navCtx" href="#" onclick="setActiveNav(this);openCtx();return false"><i class="fas fa-user-lock"></i>Contexts &amp; Auth</a>
    <a class="nav-a" id="navPolicy" href="#" onclick="setActiveNav(this);openPolicy();return false"><i class="fas fa-sliders"></i>Scan Policies</a>
    <div class="nav-lbl" style="margin-top:6px">Sources</div>
    <a class="nav-a" href="https://vulnerability.circl.lu/" target="_blank" rel="noopener"><i class="fas fa-circle-nodes"></i>Vulnerability-Lookup</a>
    <a class="nav-a" href="https://nvd.nist.gov/" target="_blank" rel="noopener"><i class="fas fa-database"></i>NVD / NIST</a>
    <a class="nav-a" href="https://www.shodan.io/" target="_blank" rel="noopener"><i class="fas fa-eye"></i>Shodan</a>
    <a class="nav-a" href="https://search.censys.io/" target="_blank" rel="noopener"><i class="fas fa-satellite-dish"></i>Censys</a>
    <a class="nav-a" href="https://cve.circl.lu/" target="_blank" rel="noopener"><i class="fas fa-circle-nodes"></i>CIRCL CVE</a>
    <a class="nav-a" href="https://www.opencve.io/" target="_blank" rel="noopener"><i class="fas fa-shield-halved"></i>OpenCVE</a>
  </nav>
  <div class="sb-apis">
    <div class="sb-api-lbl">API Source Status</div>
    <?php
$_alist  = ['nvd' => 'NVD v2', 'shodan' => 'Shodan', 'censys' => 'Censys v2', 'vulnlookup' => 'CIRCL VL', 'opencve' => 'OpenCVE'];
$_astatus = get_api_status();
foreach ($_alist as $_ak => $_al):
    $_aok = $_astatus[$_ak] === 'configured';
?>
<div class="sb-api-row">
  <div class="sb-api-name"><span class="dot <?php echo $_aok ? 'dot-on' : 'dot-off'; ?>"></span><?php echo $_al; ?></div>
  <span class="api-badge <?php echo $_aok ? 'on' : 'off'; ?>"><?php echo $_aok ? 'Active' : 'Offline'; ?></span>
</div>
<?php endforeach; ?>
  </div>
  <div class="sb-footer">VulnScope Pro &bull; Enterprise Security Intelligence<br>Multi-source CVE Correlation Engine</div>
</aside>
<div id="sb-ov" onclick="closeSB()"></div>
<div id="main">
  <header id="topbar">
    <div class="tb-left">
      <button id="sbtoggle" onclick="toggleSB()"><i class="fas fa-bars"></i></button>
      <div class="tb-bread">
        <i class="fas fa-shield-halved" style="color:var(--accent);font-size:13px"></i>
        <span class="cr-active">Vulnerability Intelligence Console</span>
      </div>
    </div>
    <div class="tb-right">
      <div class="tb-pill"><span class="ldot"></span>ENGINE ONLINE</div>
      <div class="tb-pill"><i class="fas fa-microchip" style="font-size:9px"></i>v6.0 Advanced</div>
    </div>
  </header>
  <main id="pg">
    <section class="scan-panel">
      <div class="scan-ph">
        <div>
          <h1>Attack Surface Assessment</h1>
          <p>Recon &middot; Spider &middot; Fuzzer &middot; Passive &amp; Active Rules &middot; NVD / VulnLookup / EPSS / KEV</p>
        </div>
        <div class="eng-badge"><i class="fas fa-circle" style="font-size:7px;color:#22c55e;animation:dpulse 1.5s infinite"></i>Scan Core Active</div>
      </div>
      <form id="scanForm">
        <div class="scan-row">
          <div class="inp-wrap">
            <input type="text" id="target" placeholder="Target IP or domain  e.g. 192.168.1.1 or example.com" autocomplete="off" spellcheck="false">
            <i class="fas fa-crosshairs inp-ico"></i>
          </div>
          <select id="scanMode" class="scan-mode" aria-label="Scan mode">
            <option value="deep" selected>Deep Scan (Full Assessment)</option>
            <option value="full">Pipeline (M1&ndash;M4 + CVE)</option>
            <option value="scan">CVE Intelligence (legacy)</option>
            <option value="spider">Spider / Crawler</option>
            <option value="passive">Passive Scan</option>
            <option value="active">Active Scan</option>
            <option value="recon">M1 &mdash; Recon</option>
            <option value="fuzz">M2 &mdash; Dir Fuzzer</option>
            <option value="payloads">M3 &mdash; Payloads</option>
          </select>
          <button type="submit" id="btn"><i class="fas fa-shield-virus"></i>Launch Assessment</button>
        </div>
        <div class="scan-opts" id="deepOpts">
          <span class="opt-lbl">Scan profile</span>
          <div class="seg" id="profileSeg" role="group" aria-label="Scan profile">
            <button type="button" class="seg-btn" data-profile="quick">Quick</button>
            <button type="button" class="seg-btn active" data-profile="balanced">Balanced</button>
            <button type="button" class="seg-btn" data-profile="deep">Deep</button>
          </div>
          <label class="chk"><input type="checkbox" id="safeMode" checked>Safe mode (no time-based checks)</label>
          <label class="chk"><input type="checkbox" id="skipFuzz">Skip directory fuzzing</label>
          <span class="opt-sep"></span>
          <select id="scanCtx" class="opt-sel" aria-label="Auth context"><option value="">Context: none</option></select>
          <select id="scanPolicy" class="opt-sel" aria-label="Scan policy"><option value="default">Policy: default</option></select>
        </div>
        <div class="auth-row">
          <span class="auth-lbl"><i class="fas fa-key"></i>Session Cookie (optional)</span>
          <input type="text" id="authCookie" class="auth-inp" placeholder="PHPSESSID=abc123; security=low   &mdash; for authenticated scans" autocomplete="off" spellcheck="false">
        </div>
      </form>
      <div id="loader">
        <div class="ld-spin"></div>
        <div class="ld-bar-wrap">
          <div class="ld-txt" id="ldtxt"><i class="fas fa-circle-notch fa-spin" style="margin-right:6px"></i>Initializing scan engine...</div>
          <div class="ld-track"><div class="ld-fill"></div></div>
        </div>
      </div>
    </section>
    <div id="results">
      <div class="res-hdr">
        <div class="res-hdr-left">
          <div class="res-hdr-title">Scan Results</div>
          <span id="riskBadge" class="risk-badge r-info" style="display:none"></span>
        </div>
        <div class="exp-menu" id="expMenu">
          <button class="exp-btn" onclick="toggleExport(event)"><i class="fas fa-file-export"></i>Export Report <i class="fas fa-chevron-down" style="font-size:8px"></i></button>
          <div class="exp-drop" id="expDrop">
            <button class="exp-item" onclick="exportReport()"><i class="fas fa-code"></i>JSON (raw envelope)</button>
            <button class="exp-item" onclick="exportSarif()"><i class="fas fa-brackets-curly"></i>SARIF 2.1.0</button>
            <button class="exp-item" onclick="exportHtml()"><i class="fas fa-file-lines"></i>HTML report</button>
          </div>
        </div>
      </div>
      <div id="stageTrack"></div>
      <div class="stats">
        <div class="sc risk">
          <div class="sc-lbl">Composite Risk Score</div>
          <div class="sc-val" id="riskValue">0</div>
          <div class="risk-trk"><div id="riskBar"></div></div>
          <div class="sc-meta" id="resTarget">HOST: ---</div>
          <div class="sc-sub" id="riskLabel">No data</div>
        </div>
        <div class="sc finds">
          <div class="sc-lbl">Total Findings</div>
          <div class="sc-val" id="findingsCount">0</div>
          <div class="sc-meta">CVEs &amp; Vulnerabilities</div>
        </div>
        <div class="sc ports">
          <div class="sc-lbl">Detected Assets</div>
          <div class="sc-val" id="portsCountVal">0</div>
          <div class="sc-meta" id="portsCount">Open Services</div>
        </div>
        <div class="sc ip">
          <div class="sc-lbl">Resolved IP</div>
          <div class="sc-val" id="resIp">---</div>
          <div class="sc-meta">Target Address</div>
        </div>
      </div>
      <div class="res-body">
        <div style="display:flex;flex-direction:column;gap:14px">
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-chart-bar"></i>Severity Distribution</div></div>
            <div class="panel-body"><div id="severityBars"></div></div>
          </div>
          <div class="panel">
            <div class="panel-hdr"><div class="panel-title"><i class="fas fa-plug-circle-check"></i>Intelligence Sources</div></div>
            <div class="panel-body" style="padding:14px 18px"><div id="apiStatusDisplay"></div></div>
          </div>
        </div>
        <div class="panel">
          <div class="panel-hdr">
            <div class="panel-title"><i class="fas fa-bug"></i>Security Intelligence Findings</div>
            <div class="vf-wrap">
              <button class="fb active" onclick="fvulns('all',this)">All</button>
              <button class="fb fc" onclick="fvulns('Critical',this)">Critical</button>
              <button class="fb fh" onclick="fvulns('High',this)">High</button>
              <button class="fb fm" onclick="fvulns('Medium',this)">Medium</button>
              <button class="fb" onclick="fvulns('Low',this)">Low</button>
            </div>
          </div>
          <!-- Search / Sort Toolbar -->
          <div class="sif-toolbar" id="sifToolbar">
            <div class="sif-search-wrap">
              <i class="fas fa-search sif-search-ico"></i>
              <input type="text" class="sif-search" id="sifSearch" placeholder="Search CVE, CWE, description, service..." autocomplete="off" spellcheck="false" aria-label="Search findings">
            </div>
            <select class="sif-sort" id="sifSort" aria-label="Sort findings">
              <option value="severity">Sort: Severity</option>
              <option value="cvss-desc">Sort: CVSS ↓</option>
              <option value="cvss-asc">Sort: CVSS ↑</option>
              <option value="cve-desc">Sort: CVE ID ↓</option>
              <option value="cve-asc">Sort: CVE ID ↑</option>
            </select>
            <span class="sif-count" id="sifCount"></span>
          </div>
          <div id="vulnList"></div>
        </div>
        <!-- Attack Probability Analysis Panel -->
        <div class="panel attack-prob-panel" id="attackProbPanel" style="display:none">
          <div class="panel-hdr">
            <div class="panel-title"><i class="fas fa-radar"></i>Attack Probability Analysis</div>
          </div>
          <div class="ap-disclaimer">Attack probabilities are heuristic estimates based on CVSS, CWE, attack vector and vulnerability metadata. They should be used for prioritisation and triage, not as predictions of future attacks.</div>
          <div class="ap-body">
            <div class="ap-summary" id="apSummary"></div>
            <div class="ap-bars" id="apBars"></div>
            <div class="ap-charts" id="apCharts"></div>
          </div>
        </div>

      </div>
      <div class="panel" id="infra-section" style="margin-bottom:0">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-microchip"></i>Detected Infrastructure &amp; Services</div>
          <span id="portsCount2" style="font-size:10px;font-family:var(--mono);color:var(--t3);text-transform:uppercase;letter-spacing:.07em">0 Assets</span>
        </div>
        <div id="portGrid"></div>
      </div>
      <!-- MODULE 1: Recon -->
      <div class="panel vs-panel" id="reconPanel" style="margin-bottom:0">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-satellite"></i>Module 1 &mdash; Recon (DNS / NS / Ports / Banners / Whois)</div>
          <span class="tb-pill" style="font-size:9px;font-family:var(--mono)">native sockets &mdash; no external binaries</span>
        </div>
        <div class="recon-grid" id="reconGrid"></div>
        <div class="panel-hdr" style="border-top:1px solid var(--border)"><div class="panel-title" style="font-size:11px"><i class="fas fa-file-lines"></i>Raw Whois (IANA referral chain)</div></div>
        <pre class="whois-pre" id="whoisOut">No data.</pre>
      </div>
      <!-- MODULE 2: Fuzzer -->
      <div class="panel vs-panel" id="fuzzPanel" style="margin-bottom:0">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-folder-tree"></i>Module 2 &mdash; Directory &amp; Sensitive File Fuzzer</div>
          <span id="fuzzMeta" style="font-size:10px;font-family:var(--mono);color:var(--t3)"></span>
        </div>
        <div style="max-height:420px;overflow-y:auto">
          <table class="vs-table">
            <thead><tr><th>Status</th><th>Path</th><th>Content-Length</th><th>Server</th></tr></thead>
            <tbody id="fuzzRows"><tr><td colspan="4" class="rc-dim">No data.</td></tr></tbody>
          </table>
        </div>
      </div>
      <!-- MODULE 3: Payload scanner -->
      <div class="panel vs-panel" id="payloadPanel" style="margin-bottom:0">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-syringe"></i>Module 3 &mdash; Active Payload Scanner (SQLi / XSS / LFI / Open Redirect)</div>
          <span id="payloadMeta" style="font-size:10px;font-family:var(--mono);color:var(--t3)"></span>
        </div>
        <div id="payloadHits"><div class="empty-s" style="padding:20px"><span>No injection validations ran.</span></div></div>
      </div>
      <!-- SPIDER / CRAWLER -->
      <div class="panel vs-panel" id="spiderPanel" style="margin-bottom:16px">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-spider"></i>Spider &mdash; Crawl Map &amp; Technologies</div>
          <span id="spiderMeta" style="font-size:10px;font-family:var(--mono);color:var(--t3)"></span>
        </div>
        <div class="spider-stats" id="spiderStats"></div>
        <div class="tech-wrap" id="techWrap"></div>
        <div class="panel-hdr" style="border-top:1px solid var(--border)"><div class="panel-title" style="font-size:10px"><i class="fas fa-link"></i>Discovered URLs &amp; API Endpoints</div></div>
        <div class="url-list" id="urlList"></div>
        <div class="panel-hdr" style="border-top:1px solid var(--border)"><div class="panel-title" style="font-size:10px"><i class="fas fa-rectangle-list"></i>Forms &amp; Input Surface</div></div>
        <div style="max-height:300px;overflow-y:auto">
          <table class="vs-table">
            <thead><tr><th>Method</th><th>Action</th><th>Fields</th><th>CSRF Token</th></tr></thead>
            <tbody id="formRows"></tbody>
          </table>
        </div>
      </div>
      <!-- PASSIVE SCAN -->
      <div class="panel vs-panel" id="passivePanel" style="margin-bottom:16px">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-filter"></i>Passive Scan Rules</div>
          <span id="passiveMeta" style="font-size:10px;font-family:var(--mono);color:var(--t3)"></span>
        </div>
        <div id="passiveAlerts"></div>
      </div>
      <!-- ACTIVE SCAN -->
      <div class="panel vs-panel" id="activePanel" style="margin-bottom:16px">
        <div class="panel-hdr">
          <div class="panel-title"><i class="fas fa-bolt"></i>Active Scan Results</div>
          <span id="activeMeta" style="font-size:10px;font-family:var(--mono);color:var(--t3)"></span>
        </div>
        <div id="activeAlerts"></div>
      </div>
    </div>
    <!-- INTEL LOOKUP (always available) -->
    <div class="panel" id="intelPanel" style="margin-bottom:16px">
      <div class="panel-hdr">
        <div class="panel-title"><i class="fas fa-magnifying-glass-chart"></i>Vulnerability Intelligence Lookup</div>
        <span class="tb-pill" style="font-size:9px">NVD &middot; VulnLookup &middot; EPSS &middot; KEV</span>
      </div>
      <div class="intel-head">
        <input type="text" class="intel-inp" id="intelQ" placeholder="CVE-2024-3400  |  vendor:product  |  keyword e.g. apache" autocomplete="off" spellcheck="false" aria-label="Intelligence lookup query">
        <button class="intel-btn" id="intelBtn" onclick="intelLookup()"><i class="fas fa-magnifying-glass"></i>Lookup</button>
      </div>
      <div class="intel-hint">CVE IDs return full Vulnerability-Lookup detail with CVSS, CWE, EPSS and KEV status. Use <b>vendor:product</b> (e.g. <b>apache:http_server</b>) for version-aware product search.</div>
      <div class="intel-results" id="intelResults"><div class="empty-s"><i class="fas fa-database"></i>Search the intelligence graph.<div class="empty-hint">No API keys required for Vulnerability-Lookup, EPSS or KEV.</div></div></div>
    </div>
    <!-- SCAN HISTORY -->
    <div class="panel" id="historyPanel" style="display:none;margin-bottom:16px">
      <div class="panel-hdr">
        <div class="panel-title"><i class="fas fa-clock-rotate-left"></i>Recent Scans</div>
        <button class="exp-btn" onclick="loadHistory()" style="font-size:9px;padding:5px 10px"><i class="fas fa-rotate"></i>Refresh</button>
      </div>
      <div id="historyRows"><div class="empty-s">No scans recorded yet.</div></div>
    </div>
    <!-- ADVISORY FEED -->
    <div class="panel" id="feedPanel" style="display:none;margin-bottom:16px">
      <div class="panel-hdr">
        <div class="panel-title"><i class="fas fa-newspaper"></i>Advisory Feed &mdash; Vulnerability-Lookup Corridor</div>
        <button class="exp-btn" onclick="loadFeed()" style="font-size:9px;padding:5px 10px"><i class="fas fa-rotate"></i>Refresh</button>
      </div>
      <div class="feed-src-wrap">
        <select id="feedSrc" class="mi-inp" style="max-width:260px" onchange="loadFeed()" aria-label="Advisory source">
          <option value="">All sources</option>
        </select>
        <span class="tb-pill" id="feedMeta">fresh advisories, newest first</span>
      </div>
      <div class="feed-list" id="feedList"><div class="empty-s"><i class="fas fa-satellite-dish"></i>Opening the feed corridor...</div></div>
    </div>
    <!-- EXPLOIT HAZARD -->
    <div class="panel" id="hazardPanel" style="display:none;margin-bottom:16px">
      <div class="panel-hdr">
        <div class="panel-title"><i class="fas fa-wave-square"></i>Exploit Hazard Model &mdash; Shaffer &amp; Voicu (EPSS &times; KEV &times; Controls)</div>
        <span class="tb-pill">local deterministic model &middot; arXiv:2607.24618</span>
      </div>
      <div class="intel-head">
        <input type="text" class="intel-inp" id="hzQ" placeholder="CVE-2021-44228 or comma list e.g. CVE-2024-3400, CVE-2024-21762" autocomplete="off" spellcheck="false" aria-label="Hazard query">
        <button class="intel-btn" id="hzBtn" onclick="loadHazard()"><i class="fas fa-radiation"></i>Compute</button>
      </div>
      <div class="intel-hint">EPSS (ELM probability) &rarr; KEV weight &amp; floor &rarr; compensating controls &rarr; daily hazard &rarr; horizon probability. Lists run as one batch and return an aggregate exposure.</div>
      <div id="hzOut"><div class="empty-s" style="padding:16px 18px"><i class="fas fa-wave-square"></i>Compute hazard for one or many CVEs.<div class="empty-hint">KEV status and EPSS resolve automatically from live feeds.</div></div></div>
    </div>
    <!-- SIGHTINGS -->
    <div class="panel" id="sightingsPanel" style="display:none;margin-bottom:16px">
      <div class="panel-hdr">
        <div class="panel-title"><i class="fas fa-eye"></i>Advisory Sightings &mdash; local evidence log</div>
        <span class="tb-pill">mirrors to CIRCL when VULNLOOKUP_SIGHTINGS_URL is set</span>
      </div>
      <div class="mi-grid">
        <input class="mi-inp" id="sighVuln" placeholder="CVE ID, e.g. CVE-2024-3400" autocomplete="off" spellcheck="false">
        <select class="mi-inp" id="sighKind" aria-label="Sighting kind"></select>
        <input class="mi-inp" id="sighTarget" placeholder="Where seen (host / asset)" autocomplete="off" spellcheck="false">
        <input class="mi-inp" id="sighAuthor" placeholder="Your name / handle (optional)" autocomplete="off">
        <input class="mi-inp" id="sighNote" placeholder="Note (what was observed)" autocomplete="off" style="grid-column:1/-1">
        <div class="mi-actions"><button class="vs-submit" id="sighBtn" onclick="recordSighting()"><i class="fas fa-plus"></i>Record Sighting</button><span class="form-note" id="sighMsg"></span></div>
      </div>
      <div id="sighList" style="max-height:340px;overflow-y:auto"><div class="empty-s" style="padding:16px 18px">No sightings recorded yet.</div></div>
    </div>
    <!-- NOTES & BUNDLES -->
    <div class="panel" id="collabPanel" style="display:none;margin-bottom:16px">
      <div class="panel-hdr">
        <div class="panel-title"><i class="fas fa-notes-medical"></i>Analyst Comments &amp; Case Bundles</div>
      </div>
      <div class="vs-tabs">
        <button class="vs-tab active" data-ctab="comments" onclick="collabTab('comments',this)"><i class="fas fa-comments"></i>Comments</button>
        <button class="vs-tab" data-ctab="bundles" onclick="collabTab('bundles',this)"><i class="fas fa-box-archive"></i>Bundles</button>
      </div>
      <div id="ctComment">
        <div class="mi-grid">
          <input class="mi-inp" id="cmVuln" placeholder="CVE ID" autocomplete="off" spellcheck="false">
          <input class="mi-inp" id="cmAuthor" placeholder="Analyst (optional)" autocomplete="off">
          <input class="mi-inp" id="cmBody" placeholder="Analysis, patch status, related IDs..." autocomplete="off" style="grid-column:2/-1">
          <div class="mi-actions"><button class="vs-submit" id="cmBtn" onclick="postComment()"><i class="fas fa-comment-medical"></i>Save Comment</button><span class="form-note" id="cmMsg"></span></div>
        </div>
        <div id="cmList"><div class="empty-s" style="padding:16px 18px">No comments yet.</div></div>
      </div>
      <div id="ctBundles" style="display:none">
        <div class="mi-grid">
          <input class="mi-inp" id="bdName" placeholder="Bundle name, e.g. Edge FW Q3 triage" autocomplete="off">
          <input class="mi-inp" id="bdDesc" placeholder="Description (optional)" autocomplete="off">
          <input class="mi-inp" id="bdIds" placeholder="CVE-2024-3400, CVE-2024-21762 ..." autocomplete="off" spellcheck="false">
          <div class="mi-actions"><button class="vs-submit" id="bdBtn" onclick="postBundle()"><i class="fas fa-box-archive"></i>Create Bundle</button><span class="form-note" id="bdMsg"></span></div>
        </div>
        <div id="bdList"><div class="empty-s" style="padding:16px 18px">No bundles yet.</div></div>
      </div>
    </div>
    <!-- WATCHLISTS -->
    <div class="panel" id="watchPanel" style="display:none;margin-bottom:16px">
      <div class="panel-hdr">
        <div class="panel-title"><i class="fas fa-bell"></i>Vendor Watchlists &amp; Webhook Notifications</div>
        <button class="exp-btn" onclick="checkWatch(true)" style="font-size:9px;padding:5px 10px"><i class="fas fa-rotate"></i>Check All Now</button>
      </div>
      <div class="mi-grid">
        <input class="mi-inp" id="wlVendor" placeholder="Vendor e.g. apache" autocomplete="off" spellcheck="false">
        <input class="mi-inp" id="wlProduct" placeholder="Product e.g. http_server" autocomplete="off" spellcheck="false">
        <input class="mi-inp" id="wlCvss" type="number" min="0" max="10" step="0.5" placeholder="Min CVSS (0&ndash;10)">
        <select class="mi-inp" id="wlFreq" aria-label="Frequency"><option value="daily">Check: daily</option><option value="hourly">Check: hourly</option><option value="weekly">Check: weekly</option></select>
        <input class="mi-inp" id="wlHz" type="number" min="0" max="100" step="5" placeholder="Hazard alert &ge; (0&ndash;100)">
        <input class="mi-inp" id="wlHook" placeholder="Webhook URL (https, optional)" autocomplete="off" spellcheck="false" style="grid-column:span 2">
        <div class="mi-actions"><button class="vs-submit" id="wlBtn" onclick="addWatch()"><i class="fas fa-bell"></i>Add Watch</button><span class="form-note">SSRF-safe: only HTTPS, public hosts; alerts pass the hazard threshold before delivery.</span></div>
      </div>
      <div class="wl-table-wrap"><table class="vs-table"><thead><tr><th>Watch</th><th>Thresholds</th><th>Delivery</th><th>Pending</th><th></th></tr></thead><tbody id="wlRows"><tr><td colspan="5" class="rc-dim">No watchlists configured.</td></tr></tbody></table></div>
      <div class="panel-hdr" style="border-top:1px solid var(--border)"><div class="panel-title" style="font-size:10px"><i class="fas fa-paper-plane"></i>Notification Queue</div></div>
      <div class="notif-feed" id="notifFeed"><div class="empty-s" style="padding:14px 18px">Run a check to queue notifications.</div></div>
    </div>
    <!-- HTTP PROXY -->
    <div class="panel" id="proxyPanel" style="display:none;margin-bottom:16px">
      <div class="panel-hdr">
        <div class="panel-title"><i class="fas fa-shuffle"></i>HTTP Proxy &mdash; Site Map &amp; Request Composer</div>
        <button class="exp-btn" onclick="loadProxy()" style="font-size:9px;padding:5px 10px"><i class="fas fa-rotate"></i>Refresh</button>
      </div>
      <div class="vs-tabs">
        <button class="vs-tab active" data-ptab="hist" onclick="proxyTab('hist',this)"><i class="fas fa-list"></i>History</button>
        <button class="vs-tab" data-ptab="replay" onclick="proxyTab('replay',this)"><i class="fas fa-repeat"></i>Replay&nbsp;/&nbsp;Compose</button>
      </div>
      <div id="pxHist">
        <div style="display:flex;gap:10px;padding:14px 18px 8px;flex-wrap:wrap">
          <input class="mi-inp" id="pxQ" placeholder="Filter URL..." style="max-width:220px" onkeydown="if(event.key==='Enter')loadProxy()" autocomplete="off">
          <input class="mi-inp" id="pxHost" placeholder="Host..." style="max-width:180px" onkeydown="if(event.key==='Enter')loadProxy()" autocomplete="off">
          <select class="mi-inp" id="pxType" style="max-width:150px" onchange="loadProxy()" aria-label="Entry type">
            <option value="">All traffic</option><option value="crawl">Spider</option><option value="scan">Scan engine</option><option value="manual">Replays</option>
          </select>
          <button class="vs-ghost" onclick="purgeProxy()"><i class="fas fa-broom"></i>Purge</button>
        </div>
        <div class="proxy-hist" style="max-height:330px;overflow-y:auto"><table class="vs-table"><thead><tr><th>#</th><th>M</th><th>St</th><th>URL</th><th>Size</th><th>ms</th></tr></thead><tbody id="pxRows"><tr><td colspan="6" class="rc-dim">No traffic recorded yet.</td></tr></tbody></table></div>
      </div>
      <div id="pxReplay" style="display:none">
        <div class="mi-grid">
          <select class="mi-inp" id="rpMethod" aria-label="Method"><option>GET</option><option>POST</option><option>PUT</option><option>DELETE</option><option>HEAD</option><option>OPTIONS</option><option>PATCH</option></select>
          <input class="mi-inp" id="rpUrl" placeholder="https://target/path" autocomplete="off" spellcheck="false" style="grid-column:span 2">
          <input class="mi-inp" id="rpHeaders" placeholder="Headers: X-Foo: bar | Cookie: a=b" autocomplete="off" style="grid-column:1/-1">
          <textarea class="mi-inp" id="rpBody" rows="3" placeholder="Request body (optional)" style="grid-column:1/-1;font-family:var(--mono)"></textarea>
          <div class="mi-actions"><button class="vs-submit" id="rpBtn" onclick="replayReq()"><i class="fas fa-paper-plane"></i>Send</button><span class="form-note">Scoped like the scanner: internal RFC1918 hosts need ALLOW_INTERNAL_SCAN.</span></div>
        </div>
        <div style="padding:0 18px 18px"><pre class="proxy-pre" id="rpOut" hidden></pre></div>
      </div>
    </div>
    <!-- CONTEXTS -->
    <div class="panel" id="ctxPanel" style="display:none;margin-bottom:16px">
      <div class="panel-hdr">
        <div class="panel-title"><i class="fas fa-user-lock"></i>Scan Contexts &mdash; Authenticated Sessions</div>
        <span class="tb-pill">form-login session harvesting &middot; basic auth</span>
      </div>
      <div class="mi-grid">
        <input class="mi-inp" id="cxName" placeholder="Context name e.g. admin-portal" autocomplete="off">
        <select class="mi-inp" id="cxAuth" aria-label="Auth type" onchange="cxAuthFields()"><option value="none">Auth: none (cookies only)</option><option value="auto-cookie">Form login (auto cookie)</option><option value="basic">HTTP Basic</option></select>
        <input class="mi-inp" id="cxScope" placeholder="Target scope e.g. https://app.internal" autocomplete="off" spellcheck="false">
        <input class="mi-inp" id="cxUrl" placeholder="Login URL (form mode)" autocomplete="off" spellcheck="false">
        <input class="mi-inp" id="cxUser" placeholder="Username" autocomplete="off">
        <input class="mi-inp" id="cxPass" type="password" placeholder="Password" autocomplete="new-password">
        <input class="mi-inp" id="cxPayload" placeholder="Payload template: u={username}&amp;p={password} (optional)" autocomplete="off" style="grid-column:1/-1">
        <input class="mi-inp" id="cxCookie" placeholder="Extra cookies e.g. PHPSESSID=abc; X-A=1 (optional)" autocomplete="off" style="grid-column:1/-1">
        <div class="mi-actions"><button class="vs-submit" id="cxBtn" onclick="saveCtx()"><i class="fas fa-save"></i>Save Context</button><span class="form-note" id="cxMsg">Passwords are stored server-side and never echoed to the UI.</span></div>
      </div>
      <div id="cxList"></div>
    </div>
    <!-- SCAN POLICIES -->
    <div class="panel" id="policyPanel" style="display:none;margin-bottom:16px">
      <div class="panel-hdr">
        <div class="panel-title"><i class="fas fa-sliders"></i>Scan Policies &mdash; rule-group strength</div>
        <span class="tb-pill">ZAP-style thresholds &amp; budgets</span>
      </div>
      <div class="mi-grid">
        <input class="mi-inp" id="plName" placeholder="Policy name e.g. CI-Lite" autocomplete="off">
        <input class="mi-inp" id="plMult" type="number" min="0.1" max="3" step="0.1" placeholder="Requests multiplier (0.1&ndash;3)" value="1">
        <label class="chk" style="align-self:center;display:flex;align-items:center;gap:6px;font-size:10px;color:var(--t2)"><input type="checkbox" id="plDefault">Set as default</label>
        <div class="mi-actions"><button class="vs-submit" id="plBtn" onclick="savePolicy()"><i class="fas fa-save"></i>Save Policy</button><span class="form-note" id="plMsg">Groups below set each rule family to OFF / LOW / DEFAULT / HIGH.</span></div>
      </div>
      <div class="mi-grid" id="plGroups" style="padding-top:0"></div>
      <div id="plList"></div>
    </div>
  </main>
</div>
</div>
<script>
const SCAN_TOKEN='<?php echo SCAN_TOKEN; ?>';
let _last=null,_all=[];
(function(){
  const c=document.getElementById('bgc'),ctx=c.getContext('2d');
  const RM=window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  let w,h,pts=[];
  function rsz(){w=c.width=window.innerWidth;h=c.height=window.innerHeight}
  function init(){pts=[];if(RM)return;const n=Math.min(40,Math.floor(w*h/30000));for(let i=0;i<n;i++)pts.push({x:Math.random()*w,y:Math.random()*h,r:Math.random()*.9+.3,vx:(Math.random()-.5)*.13,vy:(Math.random()-.5)*.13})}
  function draw(){ctx.clearRect(0,0,w,h);if(RM||!pts.length)return;ctx.fillStyle='rgba(6,182,212,.35)';for(const d of pts){d.x+=d.vx;d.y+=d.vy;if(d.x<0||d.x>w)d.vx*=-1;if(d.y<0||d.y>h)d.vy*=-1;ctx.beginPath();ctx.arc(d.x,d.y,d.r,0,Math.PI*2);ctx.fill()}ctx.strokeStyle='rgba(6,182,212,.05)';ctx.lineWidth=.5;for(let i=0;i<pts.length;i++)for(let j=i+1;j<pts.length;j++){const dx=pts[i].x-pts[j].x,dy=pts[i].y-pts[j].y,dist=Math.sqrt(dx*dx+dy*dy);if(dist<120){ctx.globalAlpha=(1-dist/120)*.55;ctx.beginPath();ctx.moveTo(pts[i].x,pts[i].y);ctx.lineTo(pts[j].x,pts[j].y);ctx.stroke()}}ctx.globalAlpha=1;requestAnimationFrame(draw)}
  window.addEventListener('resize',()=>{rsz();init()});rsz();init();draw();
})();
function toggleSB(){document.getElementById('sb').classList.toggle('open');document.getElementById('sb-ov').classList.toggle('on')}
function closeSB(){document.getElementById('sb').classList.remove('open');document.getElementById('sb-ov').classList.remove('on')}
window.addEventListener('scroll',function(){
  const sb=document.getElementById('sb');
  if(sb&&sb.classList.contains('open'))closeSB();
},{passive:true});
function setActiveNav(el){document.querySelectorAll('#sb .nav-a').forEach(a=>a.classList.remove('active'));el.classList.add('active')}
const SIGHT_KINDS=[['seen','Seen','seen'],['exploited','Exploited','exploited'],['not-exploited','Not exploited','not-exploited'],['confirmed','Confirmed','confirmed'],['not-confirmed','Not confirmed','not-confirmed'],['patched','Patched','patched'],['not-patched','Not patched','not-patched']];
function vsPanel(id){document.getElementById(id).style.display='block'}
function toIntel(){closeSB();const p=document.getElementById('intelPanel');if(p){p.scrollIntoView({behavior:'smooth',block:'center'});document.getElementById('intelQ').focus()}}
function toHistory(){closeSB();const p=document.getElementById('historyPanel');p.style.display='block';loadHistory();p.scrollIntoView({behavior:'smooth',block:'center'})}
function toResults(){closeSB();const e=document.getElementById('results');if(e&&e.style.display!=='none'){setTimeout(()=>e.scrollIntoView({behavior:'smooth'}),260)}else{noScanYet()}}
function toAttackProb(){closeSB();const e=document.getElementById('attackProbPanel');if(e&&e.style.display!=='none'){setTimeout(()=>e.scrollIntoView({behavior:'smooth'}),260)}else{noScanYet()}}
function toInfra(){closeSB();const e=document.getElementById('infra-section');const r=document.getElementById('results');if(e&&r&&r.style.display!=='none'){setTimeout(()=>e.scrollIntoView({behavior:'smooth'}),260)}else{noScanYet()}}
function noScanYet(){
  document.getElementById('navScan').classList.add('active');
  document.getElementById('navFeed').classList.remove('active');
  document.getElementById('navAttack').classList.remove('active');
  document.getElementById('navInfra').classList.remove('active');
  const t=document.getElementById('target');
  if(t){t.focus();t.classList.add('input-nudge');setTimeout(()=>t.classList.remove('input-nudge'),900)}
  document.getElementById('pg').scrollIntoView({behavior:'smooth',block:'start'});
  showError('Run a scan first — this section fills in once results are ready.');
}
function showError(m){document.getElementById('error-msg').innerText=m;document.getElementById('error-toast').classList.add('show');setTimeout(hideError,7000)}
function hideError(){document.getElementById('error-toast').classList.remove('show')}
function ctr(el,to,dur=900){const s=performance.now(),f=parseInt(el.innerText)||0;(function run(n){const p=Math.min((n-s)/dur,1),e=1-Math.pow(1-p,3);el.innerText=Math.round(f+(to-f)*e);if(p<1)requestAnimationFrame(run)})(s)}
const LDR_MSGS=['Resolving target & DNS...','Recon: enumerating ports and services...','Spider: mapping routes, forms and API endpoints...','Fuzzing sensitive paths and backups...','Passive rules: headers, cookies, CORS, disclosure...','Active rules: injection, traversal, redirect, SSRF, XXE, JWT...','Correlating NVD / VulnLookup / EPSS / KEV...','Computing exploit hazard (EPSS × KEV × controls)...','Scoring and compiling findings...'];
const PROFILES={quick:{max_pages:8,max_requests:45},balanced:{max_pages:20,max_requests:100},deep:{max_pages:35,max_requests:180}};
let _profile='balanced';
let _lm=0,_lt=null;
function startLdr(){_lm=0;updLdr();_lt=setInterval(updLdr,2600)}
function updLdr(){const el=document.getElementById('ldtxt');if(el)el.innerHTML='<i class="fas fa-circle-notch fa-spin" style="margin-right:6px"></i>'+LDR_MSGS[_lm%LDR_MSGS.length];_lm++}
function stopLdr(){clearInterval(_lt)}
function riskMeta(s){if(s>=80)return['Critical Risk','r-critical'];if(s>=60)return['High Risk','r-high'];if(s>=40)return['Medium Risk','r-medium'];if(s>=15)return['Low Risk','r-low'];return['Minimal Risk','r-info']}
/* ---- Modular pipeline renderers (Modules 1-4) ---- */
function _vsReset(){
  for(const id of ['reconPanel','fuzzPanel','payloadPanel','spiderPanel','passivePanel','activePanel']){const el=document.getElementById(id);if(el)el.classList.remove('show')}
  document.getElementById('whoisOut').textContent='No data.';
  document.getElementById('fuzzRows').innerHTML='<tr><td colspan="4" class="rc-dim">No data.</td></tr>';
  document.getElementById('fuzzMeta').textContent='';
  document.getElementById('payloadMeta').textContent='';
  document.getElementById('payloadHits').innerHTML='<div class="empty-s" style="padding:20px"><span>No injection validations ran.</span></div>';
  document.getElementById('reconGrid').innerHTML='';
  document.getElementById('spiderStats').innerHTML='';
  document.getElementById('techWrap').innerHTML='';
  document.getElementById('urlList').innerHTML='';
  document.getElementById('formRows').innerHTML='';
  document.getElementById('spiderMeta').textContent='';
  document.getElementById('passiveAlerts').innerHTML='';
  document.getElementById('passiveMeta').textContent='';
  document.getElementById('activeAlerts').innerHTML='';
  document.getElementById('activeMeta').textContent='';
  document.getElementById('stageTrack').classList.remove('show');
  document.getElementById('stageTrack').innerHTML='';
  _all=[];_filtered=[];
  const vl=document.getElementById('vulnList');if(vl)vl.innerHTML='';
}
function toggleExport(ev){if(ev)ev.stopPropagation();document.getElementById('expDrop').classList.toggle('open')}
document.addEventListener('click',()=>document.getElementById('expDrop')?.classList.remove('open'));
document.getElementById('scanMode').addEventListener('change',function(){
  const deep=this.value==='deep';
  document.getElementById('deepOpts').style.display=deep?'flex':'none';
});
if(document.getElementById('scanMode').value!=='deep')document.getElementById('deepOpts').style.display='none';
document.querySelectorAll('#profileSeg .seg-btn').forEach(b=>b.addEventListener('click',()=>{
  document.querySelectorAll('#profileSeg .seg-btn').forEach(x=>x.classList.remove('active'));
  b.classList.add('active');_profile=b.dataset.profile;
}));
function toPanel(id){closeSB();const p=document.getElementById(id),r=document.getElementById('results');if(p&&r&&r.style.display!=='none'&&p.classList.contains('show')){setTimeout(()=>p.scrollIntoView({behavior:'smooth'}),260)}else{noScanYet()}}
function _vsPill(code){const c=parseInt(code)||0;let cls='st-err';if(c>=200&&c<300)cls='st-200';else if(c>=300&&c<400)cls='st-3xx';else if(c===403)cls='st-403';else if(c===404)cls='st-404';return `<span class="st-pill ${cls}">${c||'ERR'}</span>`}
function renderRecon(rc){
  const d=rc.dns||{};
  const cell=(h,v)=>`<div class="recon-cell"><h4>${h}</h4><div class="rc-v">${v||'<span class="rc-dim">none</span>'}</div></div>`;
  let html='';
  html+=cell('A Records',(d.A||[]).join('<br>'));
  html+=cell('AAAA Records',(d.AAAA||[]).join('<br>'));
  html+=cell('MX Records',(d.MX||[]).map(m=>`${m.pri} &middot; ${m.target}`).join('<br>'));
  html+=cell('TXT Records',(d.TXT||[]).map(t=>t.length>90?t.slice(0,90)+'&hellip;':t).join('<br>'));
  html+=cell('Nameservers',(rc.nameservers||[]).join('<br>'));
  html+=cell('Open Ports &amp; Banners',(rc.ports||[]).map(p=>`:${p.port} ${p.service}${p.product?' &mdash; '+p.product:''}${p.version?' '+p.version:''}`).join('<br>'));
  if((rc.errors||[]).length)html+=cell('Module Errors',rc.errors.map(e=>`<span class="vh-ev">${e}</span>`).join('<br>'));
  document.getElementById('reconGrid').innerHTML=html;
  const w=rc.whois;
  let out='No whois data (registry unreachable or TLD unsupported).';
  if(w){out=Object.entries(w).map(([k,v])=>Array.isArray(v)?k.toUpperCase()+':\n  '+v.join('\n  '):k.toUpperCase()+': '+v).join('\n')}
  document.getElementById('whoisOut').textContent=out;
  document.getElementById('reconPanel').classList.add('show');
}
function renderFuzz(fz){
  const hits=fz.hits||[];
  document.getElementById('fuzzRows').innerHTML=hits.length?hits.map(h=>`<tr><td>${_vsPill(h.status)}</td><td>${h.path}</td><td>${h.length}</td><td>${h.server_header||'&mdash;'}</td></tr>`).join(''):'<tr><td colspan="4" class="rc-dim">No interesting paths found.</td></tr>';
  document.getElementById('fuzzMeta').textContent=`${hits.length} hits / ${fz.paths_tested||0} probed · ${fz.base_url||''}`;
  document.getElementById('fuzzPanel').classList.add('show');
}
function renderPayloads(ps){
  const all=ps.vulnerabilities||[],hits=all.filter(v=>v.vulnerable);
  const LBL={sqli:'SQL Injection',sqli2:'SQL Injection',xss:'Cross-Site Scripting',lfi:'Local File Inclusion',redirect:'Open Redirect',idor:'IDOR',csrf:'CSRF'};
  document.getElementById('payloadHits').innerHTML=hits.length?hits.map(v=>`<div class="vuln-hit"><div class="vh-h"><span class="vh-type">${LBL[v.type]||v.type}</span><span class="st-pill st-200">VULNERABLE</span><span class="st-pill st-403">${v.severity||''}</span><span class="st-pill st-404">${v.cwe||''}</span></div><div class="vh-url">${v.url}</div><div class="vh-ev"><i class="fas fa-vial" style="margin-right:6px"></i>${v.evidence||'&mdash;'}</div></div>`).join(''):'<div class="empty-s" style="padding:20px"><span>No confirmed injection points (heuristic scan).</span></div>';
  document.getElementById('payloadMeta').textContent=`${all.length} tests · ${hits.length} confirmed · ${ps.base_url||''}`;
  document.getElementById('payloadPanel').classList.add('show');
}
function renderDashboardShell(resp){
  const s=resp.summary||{};
  const re=document.getElementById('results');re.style.display='block';re.classList.add('show');
  const rs=s.risk_score||0;
  ctr(document.getElementById('riskValue'),rs,1100);
  setTimeout(()=>document.getElementById('riskBar').style.width=rs+'%',90);
  document.getElementById('resTarget').innerText='HOST: '+(s.target||'---');
  document.getElementById('resIp').innerText=s.ip||'---';
  const[rl,rc]=riskMeta(rs);
  document.getElementById('riskLabel').innerText=rl+' — Score: '+rs+'/100';
  const rb=document.getElementById('riskBadge');rb.className='risk-badge '+rc;rb.innerHTML='<i class="fas fa-triangle-exclamation"></i> '+rl;rb.style.display='inline-flex';
  _all=(resp.findings||[]);_filtered=_all;_curSev='all';
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  document.querySelector('.vf-wrap .fb')?.classList.add('active');
  ctr(document.getElementById('findingsCount'),_all.length);
  if(_all.length){document.getElementById('sifToolbar').style.display='flex';applyFilters()}else{document.getElementById('sifToolbar').style.display='none'}
  const dist={critical:0,high:0,medium:0,low:0,info:0};
  _all.forEach(v=>{const k=(v.severity||'info').toLowerCase();if(k in dist)dist[k]++});
  renderSevBars(dist,_all.length);
  const pc=((resp.modules?.recon?.ports)||(resp.recon?.ports)||[]).length;
  ctr(document.getElementById('portsCountVal'),pc);
  document.getElementById('portsCount').innerText=pc+' Open Services';
  document.getElementById('portsCount2').innerText=pc+' Assets';
  if(resp.api_status)renderApiStatus(resp.api_status);
  if(_all.length)renderAttackProbPanel(_all);
  document.getElementById('pg').scrollIntoView({behavior:'smooth',block:'start'});
}
function renderApiStatus(as){
  const lbl={nvd:'NVD v2',shodan:'Shodan',censys:'Censys v2',opencve:'OpenCVE',vulnlookup:'VulnLookup',epss:'EPSS',kev:'CISA KEV'};
  const html=Object.entries(as).map(([k,v])=>{const ok=v==='configured'||v==='enabled'||v==='public API'||String(v).startsWith('configured');return '<div class="sb-api-row"><div class="sb-api-name"><span class="dot '+(ok?'dot-on':'dot-off')+'"></span>'+esc(lbl[k]||k.toUpperCase())+'</div><span class="api-badge '+(ok?'on':'off')+'">'+(ok?'Active':'Offline')+'</span></div>'}).join('');
  document.getElementById('apiStatusDisplay').innerHTML=html;
}
document.getElementById('scanForm').onsubmit=async(e)=>{
  e.preventDefault();
  const t=document.getElementById('target').value.trim(),btn=document.getElementById('btn'),ldr=document.getElementById('loader');
  if(!t)return showError('No target specified.');
  const mode=document.getElementById('scanMode').value;
  btn.disabled=true;ldr.classList.add('show');startLdr();
  document.getElementById('results').classList.remove('show');document.getElementById('results').style.display='none';
  document.getElementById('riskBadge').style.display='none';
  _vsReset();
  const fd=new FormData();fd.append('target',t);
  const ck=document.getElementById('authCookie').value.trim();if(ck)fd.append('cookie',ck);
  if(mode==='deep'){
    fd.append('profile',_profile);
    fd.append('safe',document.getElementById('safeMode').checked?'1':'0');
    if(document.getElementById('skipFuzz').checked)fd.append('skip_fuzz','1');
    const cx=document.getElementById('scanCtx').value;if(cx)fd.append('context_id',cx);
    const pl=document.getElementById('scanPolicy').value;if(pl&&pl!=='default')fd.append('policy',pl);
  }
  if(mode==='passive'||mode==='active'){
    fd.append('safe',document.getElementById('safeMode').checked?'1':'0');
  }
  try{
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 420000);

    const r=await fetch('?action='+mode,{
      method:'POST',
      body:fd,
      headers:{'X-VulnScope-Token':SCAN_TOKEN},
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if(!r.ok){const tx=await r.text();showError('Server error '+r.status+': '+tx.substring(0,180));return}
    const j=await r.json();
    if(j.success){_last=j;renderScanResult(j,mode)}
    else showError(j.message||'Unknown scan error.')
  }catch(err){
    if (err.name === 'AbortError') {
      showError('Scan timed out. The target may be unroutable or heavily firewalled.');
    } else {
      showError('Connection failure: '+err.message);
    }
  }
  finally{btn.disabled=false;ldr.classList.remove('show');stopLdr()}
};
function renderScanResult(j,mode){
  if(mode==='scan'){renderDashboard(j);return}
  renderDashboardShell(j);
  const m=j.modules||{};
  const recon=m.recon||j.recon;
  const fuzz=m.fuzz||j.fuzz;
  const payloads=m.payloads||j.payload_scan;
  const spider=m.spider||j.spider;
  const passive=m.passive||j.passive;
  const active=m.active||j.active;
  if(recon)renderRecon(recon);
  if(fuzz)renderFuzz(fuzz);
  if(payloads)renderPayloads(payloads);
  if(spider)renderSpider(spider);
  if(passive)renderPassive(passive.alerts||[]);
  if(active)renderActive(active.alerts||[]);
  if(j.scan_stages)renderStages(j.scan_stages,j.summary||{});
  applyFilters();
}
function renderDashboard(resp){
  const{summary:s,severity_distribution:sd,findings:f,debug_info:di,api_status:as}=resp;
  const re=document.getElementById('results');re.style.display='block';re.classList.add('show');
  ctr(document.getElementById('riskValue'),s.risk_score,1100);
  setTimeout(()=>document.getElementById('riskBar').style.width=s.risk_score+'%',90);
  document.getElementById('resTarget').innerText='HOST: '+s.target;
  document.getElementById('resIp').innerText=s.ip;
  const[rl,rc]=riskMeta(s.risk_score);
  document.getElementById('riskLabel').innerText=rl+' — Score: '+s.risk_score+'/100';
  const rb=document.getElementById('riskBadge');rb.className='risk-badge '+rc;rb.innerHTML='<i class="fas fa-triangle-exclamation"></i> '+rl;rb.style.display='inline-flex';
  ctr(document.getElementById('findingsCount'),s.total_findings);
  ctr(document.getElementById('portsCountVal'),s.open_ports_count);
  document.getElementById('portsCount').innerText=s.open_ports_count+' Open Services';
  document.getElementById('portsCount2').innerText=s.open_ports_count+' Assets';
  if(as)document.getElementById('apiStatusDisplay').innerHTML=Object.entries(as).map(([k,v])=>{const ok=v==='configured';const lbl={'nvd':'NVD v2','shodan':'Shodan','censys':'Censys v2','opencve':'OpenCVE'};return `<div class="sb-api-row"><div class="sb-api-name"><span class="dot ${ok?'dot-on':'dot-off'}"></span>${lbl[k]||k.toUpperCase()}</div><span class="api-badge ${ok?'on':'off'}">${ok?'Active':'Offline'}</span></div>`}).join('');
  renderSevBars(sd,s.total_findings);renderPorts(di.ports||[]);_all=f;_filtered=f;_curSev='all';
  document.getElementById('sifSearch').value='';
  document.getElementById('sifSort').value='severity';
  initSearchSort();
  applyFilters();
  renderAttackProbPanel(f);
  setTimeout(()=>re.scrollIntoView({behavior:'smooth',block:'start'}),160);
}
function renderSevBars(d,tot){
  const sevs=['Critical','High','Medium','Low','Info'];
  document.getElementById('severityBars').innerHTML=sevs.map(s=>{const cnt=d[s.toLowerCase()]||0,pct=tot>0?Math.round(cnt/tot*100):0;return `<div class="sev-row sev-${s}"><div class="sev-hdr"><span class="sev-name">${s}</span><div class="sev-right"><span class="sev-pct">${pct}%</span><span class="sev-cnt">${cnt}</span></div></div><div class="sev-trk"><div class="progress-bar bar-${s}" data-p="${pct}"></div></div></div>`}).join('');
  setTimeout(()=>document.querySelectorAll('.progress-bar[data-p]').forEach(b=>b.style.width=b.dataset.p+'%'),110);
}
function svcIco(s){if(!s)return'fa-server';s=s.toLowerCase();if(s.includes('http')||s.includes('www')||s.includes('nginx')||s.includes('apache'))return'fa-globe';if(s.includes('ssh'))return'fa-terminal';if(s.includes('sql')||s.includes('mysql')||s.includes('postgres')||s.includes('mongo'))return'fa-database';if(s.includes('ftp'))return'fa-upload';if(s.includes('smtp')||s.includes('mail')||s.includes('pop')||s.includes('imap'))return'fa-envelope';if(s.includes('dns')||s.includes('domain'))return'fa-sitemap';if(s.includes('rdp')||s.includes('vnc')||s.includes('wbt'))return'fa-desktop';if(s.includes('redis'))return'fa-memory';if(s.includes('docker'))return'fa-docker';if(s.includes('ldap'))return'fa-users';return'fa-server'}
function renderPorts(ports){document.getElementById('portGrid').innerHTML=ports.length?ports.map((p,i)=>`<div class="svc-card" style="animation-delay:${i*28}ms"><div class="svc-ico"><i class="fas ${svcIco(p.service+' '+(p.product||''))}"></i></div><div class="svc-info"><div class="svc-nm"><span>${(p.service||'unknown').toUpperCase()}</span><span class="open-pill">OPEN</span></div><div class="svc-port">${p.port}/TCP</div><div class="svc-prod">${[p.product,p.version].filter(Boolean).join(' ')||'&mdash;'}</div></div></div>`).join(''):`<div class="empty-s" style="grid-column:1/-1"><i class="fas fa-network-wired"></i>No open services detected.</div>`}
/* ============================================================
   V2.0 MODULE: XSS-safe text escape
   ============================================================ */
function esc(s){if(!s)return '';const d=document.createElement('div');d.textContent=String(s);return d.innerHTML}

/* ============================================================
   V2.0 MODULE: CVSS Vector Parser
   Parses CVSS v2/v3 vector strings into readable metadata chips.
   Only derives values that can be reliably extracted from the vector.
   ============================================================ */
function parseCvssVector(vec){
  if(!vec)return[];
  const chips=[];
  const labels={
    AV:{N:'Network',A:'Adjacent',L:'Local',P:'Physical'},
    AC:{L:'Low',H:'High'},
    PR:{N:'None',L:'Low',H:'High'},
    UI:{N:'None',R:'Required'},
    S:{U:'Unchanged',C:'Changed'},
    C:{N:'None',L:'Low',H:'High'},I:{N:'None',L:'Low',H:'High'},A:{N:'None',L:'Low',H:'High'}
  };
  const parts=vec.split('/');
  for(const p of parts){
    const[k,val]=p.split(':');
    if(labels[k]&&labels[k][val]){
      chips.push({key:k,label:labels[k][val],cls:k==='AV'?'chip-av':''})
    }
  }
  return chips;
}

/* ============================================================
   V2.0 MODULE: Attack Probability Engine
   Heuristic model — NOT an AI prediction model.
   Estimates likelihood based on available CVE metadata only.
   ============================================================ */
let _filtered=[],_curSev='all',_searchBound=false;

function buildAttackProbabilities(findings){
  const cats=[
    {name:'Remote Code Execution',cwes:['CWE-94','CWE-78','CWE-77','CWE-502','CWE-434'],avBoost:'N',base:0},
    {name:'SQL Injection',cwes:['CWE-89','CWE-564'],avBoost:'N',base:0},
    {name:'Command Injection',cwes:['CWE-77','CWE-78','CWE-88'],avBoost:'N',base:0},
    {name:'Cross-Site Scripting',cwes:['CWE-79','CWE-80'],avBoost:'N',base:0},
    {name:'Cross-Site Request Forgery',cwes:['CWE-352'],avBoost:'N',base:0},
    {name:'Authentication Bypass',cwes:['CWE-287','CWE-306','CWE-862','CWE-863'],avBoost:'N',base:0},
    {name:'Broken Access Control',cwes:['CWE-284','CWE-285','CWE-639','CWE-441'],avBoost:'N',base:0},
    {name:'Path Traversal',cwes:['CWE-22','CWE-23','CWE-36'],avBoost:'N',base:0},
    {name:'Denial of Service',cwes:['CWE-400','CWE-770','CWE-399'],avBoost:'N',base:0},
    {name:'Information Disclosure',cwes:['CWE-200','CWE-209','CWE-532'],avBoost:'N',base:0},
    {name:'Privilege Escalation',cwes:['CWE-269','CWE-250'],avBoost:'L',base:0},
    {name:'Buffer Overflow',cwes:['CWE-119','CWE-120','CWE-122','CWE-787'],avBoost:'N',base:0},
    {name:'Memory Corruption',cwes:['CWE-416','CWE-415','CWE-476','CWE-825'],avBoost:'N',base:0},
    {name:'Cryptographic Weakness',cwes:['CWE-327','CWE-326','CWE-295','CWE-310'],avBoost:'N',base:0},
    {name:'Server-Side Request Forgery',cwes:['CWE-918'],avBoost:'N',base:0},
    {name:'XML External Entity',cwes:['CWE-611','CWE-827'],avBoost:'N',base:0},
    {name:'Insecure Deserialization',cwes:['CWE-502'],avBoost:'N',base:0},
    {name:'Security Misconfiguration',cwes:['CWE-16','CWE-2','CWE-1188','CWE-1391'],avBoost:'N',base:0},
    {name:'Hardcoded / Default Credentials',cwes:['CWE-798','CWE-259'],avBoost:'N',base:0},
    {name:'Session Management Flaw',cwes:['CWE-384','CWE-613'],avBoost:'N',base:0},
    {name:'Race Condition',cwes:['CWE-362','CWE-367'],avBoost:'L',base:0},
    {name:'Insufficient Logging & Monitoring',cwes:['CWE-778','CWE-223'],avBoost:'L',base:0}
  ];
  const sevW={Critical:1,High:.75,Medium:.45,Low:.2,Info:.05,Unknown:.05};
  for(const f of findings){
    const w=sevW[f.severity]||.05;
    const cvss=parseFloat(f.cvss)||0;
    const cvssW=cvss/10;
    for(const cat of cats){
      let score=0;
      if(f.cwe&&cat.cwes.some(c=>f.cwe.includes(c)))score+=40*w;
      score+=cvssW*15*w;
      if(f.vector){
        if(f.vector.includes('AV:N'))score+=10*w;
        if(f.vector.includes('AC:L'))score+=5*w;
        if(f.vector.includes('PR:N'))score+=5*w;
      }
      if(f.summary){
        const sl=f.summary.toLowerCase();
        if(cat.name.toLowerCase().split(' ').some(kw=>sl.includes(kw)))score+=8*w;
      }
      cat.base+=score;
    }
  }
  const maxVal=Math.max(...cats.map(c=>c.base),1);
  return cats.map(c=>({
    name:c.name,
    pct:Math.min(Math.round(c.base/maxVal*100),100),
    raw:c.base
  })).sort((a,b)=>b.pct-a.pct);
}

function probClass(pct){
  if(pct>=80)return{cls:'ap-critical',label:'CRITICAL',lcls:'cls-critical'};
  if(pct>=60)return{cls:'ap-vhigh',label:'V.HIGH',lcls:'cls-vhigh'};
  if(pct>=40)return{cls:'ap-high',label:'HIGH',lcls:'cls-high'};
  if(pct>=20)return{cls:'ap-medium',label:'MEDIUM',lcls:'cls-medium'};
  if(pct>=5)return{cls:'ap-low',label:'LOW',lcls:'cls-low'};
  return{cls:'ap-minimal',label:'MINIMAL',lcls:'cls-minimal'};
}

/* ============================================================
   V2.0 MODULE: AI Analyst Summary Generator
   Generates text summary from available CVE metadata.
   Does NOT fabricate data — only references parsed metadata.
   ============================================================ */
function generateAiSummary(findings,probs){
  if(!findings.length)return '';
  const total=findings.length;
  const critical=findings.filter(f=>f.severity==='Critical').length;
  const high=findings.filter(f=>f.severity==='High').length;
  const topProb=probs.length?probs[0]:null;
  const networkAV=findings.filter(f=>f.vector&&f.vector.includes('AV:N')).length;
  const kevCount=findings.filter(f=>f.is_kev).length;
  let txt='<strong>'+total+'</strong> vulnerabilities identified across the target infrastructure. ';
  if(kevCount>0)txt+='<strong style="color:var(--danger)">'+kevCount+'</strong> finding'+(kevCount!==1?'s are':' is')+' listed in the CISA Known Exploited Vulnerabilities catalog &mdash; treat as top priority. ';
  if(critical>0)txt+='<strong>'+critical+'</strong> critical-severity findings require immediate attention. ';
  if(high>0)txt+='<strong>'+high+'</strong> high-severity findings should be prioritised for remediation. ';
  if(networkAV>0)txt+='<strong>'+networkAV+'</strong> vulnerabilities are network-exploitable (Attack Vector: Network). ';
  if(topProb&&topProb.pct>0)txt+='The primary attack category is <strong>'+esc(topProb.name)+'</strong> ('+topProb.pct+'% probability). ';
  return txt;
}

/* ============================================================
   V2.0 MODULE: Unified Vulnerability Card Renderer
   Every severity tab renders this identical component.
   Description always visible. Expand = advanced details.
   ============================================================ */
function renderVulns(f){
  const list=document.getElementById('vulnList');
  const countEl=document.getElementById('sifCount');
  if(countEl)countEl.textContent=f.length+' finding'+(f.length!==1?'s':'');
  if(!f.length){
    const sevLabel=_curSev==='all'?'':''+esc(_curSev)+' severity ';
    list.innerHTML='<div class="empty-s"><i class="fas fa-shield-halved"></i>No '+sevLabel+'vulnerabilities found.<div class="empty-hint">Try adjusting filters or running a new scan.</div></div>';
    return;
  }
  // Lazy render: first 50 immediately, rest on scroll
  const BATCH=50;
  const html=f.slice(0,BATCH).map((v,i)=>buildVulnCard(v,i)).join('');
  list.innerHTML=html;
  if(f.length>BATCH){
    let rendered=BATCH;
    const onScroll=()=>{
      if(list.scrollTop+list.clientHeight>=list.scrollHeight-120){
        const next=f.slice(rendered,rendered+BATCH);
        if(!next.length){list.removeEventListener('scroll',onScroll);return;}
        const tmp=document.createElement('div');
        tmp.innerHTML=next.map((v,i)=>buildVulnCard(v,rendered+i)).join('');
        while(tmp.firstChild)list.appendChild(tmp.firstChild);
        rendered+=next.length;
      }
    };
    list.addEventListener('scroll',onScroll);
  }
  // Event delegation for expand toggle
  list.onclick=function(e){
    const btn=e.target.closest('.vc-expand-btn');
    if(btn){
      const card=btn.closest('.vc');
      if(card)card.classList.toggle('expanded');
      return;
    }
    // Don't toggle on link clicks
    if(e.target.tagName==='A')return;
  };
}

function buildVulnCard(v,i){
  const id=esc(v.id||'');
  const sev=esc(v.severity||'Info');
  const src=esc(v.source||'');
  const cvss=v.cvss>0?parseFloat(v.cvss).toFixed(1):'N/A';
  const summary=esc(v.summary||'No description available.');
  const cwe=v.cwe?esc(v.cwe):'';
  const port=v.port?esc(String(v.port)):'—';
  const published=v.published?esc(v.published):'';
  const vector=v.vector?esc(v.vector):'';
  const svcStr=esc(v.affected_service||'');
  const svcIcoClass=svcIco((v.affected_service||'')+' '+(v.source||''));

  // Parse CVSS vector into chips
  const vecChips=parseCvssVector(v.vector||'');
  const chipsHtml=vecChips.map(c=>'<span class="vc-chip '+c.cls+'">'+esc(c.key)+': '+esc(c.label)+'</span>').join('');

  // CVE link (safe — id is already escaped)
  const cveLink=v.id&&v.id.startsWith('CVE-')
    ?'<a href="https://nvd.nist.gov/vuln/detail/'+id+'" target="_blank" rel="noopener noreferrer" onclick="event.stopPropagation()">'+id+'</a>'
    :id;

  // Product/service line
  const prodLine=svcStr?'<div class="vc-prod-line"><span class="vc-prod-name"><i class="fas '+svcIcoClass+'"></i>'+svcStr+'</span><span class="vc-prod-detail">Port '+port+'/TCP</span></div>':'';

  // Bottom chips
  let bottom=v.is_kev?'<span class="kev-chip"><i class="fas fa-triangle-exclamation"></i> KEV: EXPLOITED</span>':'';
  bottom+='<span class="port-chip">PORT '+port+'</span>';
  if(cwe)bottom+='<span class="cwe-chip">'+cwe+'</span>';
  if(published)bottom+='<span class="date-chip">'+published+'</span>';
  if(vector)bottom+='<span class="vec-chip" title="'+vector+'">'+vector.split('/')[0]+'</span>';

  // Advanced details (shown on expand)
  const epssTxt=(v.epss_score!=null)?(v.epss_score*100).toFixed(2)+'% <span style="opacity:.6">(pctl '+Math.round((v.epss_percentile||0)*100)+')</span>':'N/A';
  const kevTxt=v.is_kev?'<span style="color:var(--danger)"><i class="fas fa-triangle-exclamation"></i> Actively Exploited'+(v.kev_date_added?' since '+esc(v.kev_date_added):'')+'</span>':'Not Listed';
  let advHtml='<div class="vc-adv-grid">';
  advHtml+='<div class="vc-adv-item"><strong>EPSS</strong>'+epssTxt+'</div>';
  advHtml+='<div class="vc-adv-item"><strong>CISA KEV</strong>'+kevTxt+'</div>';
  if(v.hazard)advHtml+='<div class="vc-adv-item"><strong>Exploit Hazard</strong>'+v.hazard.score+'/100 ('+esc(v.hazard.band||'')+' &middot; '+esc(v.hazard.model||'exponential')+' &middot; AV '+esc(v.hazard.attack_vector||'?')+(v.hazard.kev?' &middot; KEV-weighted':'')+')</div>';
  advHtml+='<div class="vc-adv-item"><strong>Exploit Status</strong>Unknown</div>';
  advHtml+='<div class="vc-adv-item"><strong>Patch Available</strong>Unknown</div>';
  advHtml+='<div class="vc-adv-item"><strong>Vendor</strong>N/A</div>';
  advHtml+='<div class="vc-adv-item"><strong>Fixed Version</strong>N/A</div>';
  advHtml+='<div class="vc-adv-item"><strong>Source</strong>'+src+'</div>';
  advHtml+='<div class="vc-adv-item"><strong>CVSS Vector</strong>'+(vector||'N/A')+'</div>';
  if(v.confidence)advHtml+='<div class="vc-adv-item"><strong>Confidence</strong>'+esc(v.confidence)+'</div>';
  if(v.param)advHtml+='<div class="vc-adv-item"><strong>Parameter</strong>'+esc(v.param)+'</div>';
  if(v.payload)advHtml+='<div class="vc-adv-item"><strong>Payload</strong>'+esc(v.payload)+'</div>';
  if(v.method)advHtml+='<div class="vc-adv-item"><strong>Method</strong>'+esc(v.method)+'</div>';
  advHtml+='</div>';
  if(v.evidence||v.solution){
    advHtml+='<div class="ev-grid">';
    if(v.evidence)advHtml+='<div class="ev-block"><div class="ev-lbl"><i class="fas fa-vial"></i>Evidence</div><div class="ev-val">'+esc(v.evidence)+'</div></div>';
    if(v.solution)advHtml+='<div class="ev-block sol"><div class="ev-lbl"><i class="fas fa-screwdriver-wrench"></i>Recommended fix</div><div class="ev-val">'+esc(v.solution)+'</div></div>';
    advHtml+='</div>';
  }
  if(v.reference||(v.id&&v.id.startsWith('CVE-'))){
    const ref=v.reference||('https://nvd.nist.gov/vuln/detail/'+id);
    const refLabel=v.reference?'Reference':'View on NVD';
    advHtml+='<a href="'+esc(ref)+'" target="_blank" rel="noopener noreferrer" class="ref-link"><i class="fas fa-arrow-up-right-from-square"></i>'+refLabel+'</a>';
  }

  return '<div class="vc severity-'+sev+(v.is_kev?' vc-kev':'')+'" style="animation-delay:'+Math.min(i,25)*28+'ms">'
    +'<div class="vc-hdr">'
      +'<div class="vc-ids"><span class="vc-id">'+cveLink+'</span><span class="src-badge">'+src+'</span></div>'
      +'<div class="sev-tags"><span class="sp '+sev+'">'+sev+'</span><span class="cvss-chip">CVSS '+cvss+'</span>'+(v.hazard?'<span class="rule-chip" style="color:'+(v.hazard.score>=60?'var(--danger)':'var(--warn)')+'" title="Exploit hazard probability over next 30 days">HAZARD '+v.hazard.score+'</span>':'')+(v.confidence?'<span class="conf-chip '+(String(v.confidence).toLowerCase())+'">'+esc(v.confidence)+'</span>':'')+'</div>'
    +'</div>'
    +'<div class="vc-visible">'
      +prodLine
      +'<div class="vc-desc">'+summary+'</div>'
      +(chipsHtml?'<div class="vc-chips">'+chipsHtml+'</div>':'')
      +'<div class="vc-bottom">'+bottom+'</div>'
    +'</div>'
    +'<div class="vc-adv"><div class="vc-adv-inner"><div class="vc-adv-title">Extended Intelligence</div>'+advHtml+'</div></div>'
    +'<div class="vc-expand-btn"><i class="fas fa-chevron-down"></i>Details</div>'
  +'</div>';
}

/* ============================================================
   V2.0 MODULE: Attack Probability Panel Renderer
   Renders probability bars, SVG radar chart, SVG doughnut chart.
   ============================================================ */
function renderAttackProbPanel(findings){
  const panel=document.getElementById('attackProbPanel');
  if(!findings||!findings.length){panel.style.display='none';return;}
  panel.style.display='block';
  const probs=buildAttackProbabilities(findings);
  // AI Summary
  document.getElementById('apSummary').innerHTML=generateAiSummary(findings,probs);
  // Probability bars
  const barsEl=document.getElementById('apBars');
  barsEl.innerHTML=probs.map(p=>{
    const pc=probClass(p.pct);
    return '<div class="ap-bar-row">'
      +'<span class="ap-bar-label">'+esc(p.name)+'</span>'
      +'<div class="ap-bar-track"><div class="ap-bar-fill '+pc.cls+'" style="width:0%" data-w="'+p.pct+'"></div></div>'
      +'<span class="ap-bar-pct">'+p.pct+'%</span>'
      +'<span class="ap-bar-class '+pc.lcls+'">'+pc.label+'</span>'
    +'</div>';
  }).join('');
  // Animate bars
  setTimeout(()=>barsEl.querySelectorAll('.ap-bar-fill[data-w]').forEach(b=>b.style.width=b.dataset.w+'%'),60);
  // Charts
  const chartsEl=document.getElementById('apCharts');
  chartsEl.innerHTML=renderRadarChart(probs.slice(0,6))+renderDoughnutChart(probs.slice(0,6));
}

function renderRadarChart(probs){
  if(!probs.length)return '';
  const n=probs.length,cx=110,cy=110,maxR=85;
  const colors=['#ef4444','#f97316','#eab308','#06b6d4','#3b82f6','#22d3ee'];
  const pts=probs.map((p,i)=>{
    const angle=(Math.PI*2*i/n)-Math.PI/2;
    const r=maxR*p.pct/100;
    return{x:cx+r*Math.cos(angle),y:cy+r*Math.sin(angle)};
  });
  const polyPoints=pts.map(p=>p.x.toFixed(1)+','+p.y.toFixed(1)).join(' ');
  let rings='';
  [25,50,75,100].forEach(pct=>{
    const r=maxR*pct/100;
    rings+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="rgba(255,255,255,.06)" stroke-width="0.5"/>';
  });
  let axes='';
  probs.forEach((p,i)=>{
    const angle=(Math.PI*2*i/n)-Math.PI/2;
    const ex=cx+maxR*Math.cos(angle),ey=cy+maxR*Math.sin(angle);
    const lx=cx+(maxR+14)*Math.cos(angle),ly=cy+(maxR+14)*Math.sin(angle);
    axes+='<line x1="'+cx+'" y1="'+cy+'" x2="'+ex.toFixed(1)+'" y2="'+ey.toFixed(1)+'" stroke="rgba(255,255,255,.08)" stroke-width="0.5"/>';
    axes+='<text x="'+lx.toFixed(1)+'" y="'+ly.toFixed(1)+'" fill="#64748b" font-size="6" font-family="var(--mono)" text-anchor="middle" dominant-baseline="central">'+esc(p.name.split(' ')[0])+'</text>';
  });
  let svg='<svg viewBox="0 0 220 220" class="ap-chart-svg" role="img" aria-label="Attack probability radar chart">';
  svg+=rings+axes;
  svg+='<polygon points="'+polyPoints+'" fill="rgba(6,182,212,.12)" stroke="var(--accent)" stroke-width="1.5"/>';
  pts.forEach((p,i)=>{svg+='<circle cx="'+p.x.toFixed(1)+'" cy="'+p.y.toFixed(1)+'" r="3" fill="'+colors[i%colors.length]+'"/>';});
  svg+='</svg>';
  return '<div class="ap-chart-wrap"><div class="ap-chart-title">Attack Vector Radar</div>'+svg+'</div>';
}

function renderDoughnutChart(probs){
  if(!probs.length)return '';
  const colors=['#ef4444','#f97316','#eab308','#06b6d4','#3b82f6','#22d3ee'];
  const total=probs.reduce((s,p)=>s+p.pct,0)||1;
  const cx=100,cy=100,r=70,sw=18;
  let offset=0;
  const circ=2*Math.PI*r;
  let arcs='';
  probs.forEach((p,i)=>{
    const pct=p.pct/total;
    const dash=circ*pct;
    const gap=circ-dash;
    arcs+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+colors[i%colors.length]+'" stroke-width="'+sw+'" stroke-dasharray="'+dash.toFixed(2)+' '+gap.toFixed(2)+'" stroke-dashoffset="'+(-offset).toFixed(2)+'" transform="rotate(-90 '+cx+' '+cy+')" opacity=".85"/>';
    offset+=dash;
  });
  let svg='<svg viewBox="0 0 200 200" class="ap-chart-svg" role="img" aria-label="Severity distribution doughnut chart">';
  svg+=arcs;
  svg+='<text x="'+cx+'" y="'+cy+'" fill="var(--t1)" font-size="18" font-weight="700" font-family="var(--mono)" text-anchor="middle" dominant-baseline="central">'+probs.length+'</text>';
  svg+='<text x="'+cx+'" y="'+(cy+14)+'" fill="var(--t4)" font-size="7" font-family="var(--mono)" text-anchor="middle">CATEGORIES</text>';
  svg+='</svg>';
  const legend=probs.map((p,i)=>'<span class="ap-legend-item"><span class="ap-legend-dot" style="background:'+colors[i%colors.length]+'"></span>'+esc(p.name)+'</span>').join('');
  return '<div class="ap-chart-wrap"><div class="ap-chart-title">Category Distribution</div>'+svg+'<div class="ap-legend">'+legend+'</div></div>';
}

/* ============================================================
   V2.0 MODULE: Search & Sort
   Debounced search, memoised filtering.
   ============================================================ */
function initSearchSort(){
  if(_searchBound)return;
  _searchBound=true;
  const searchEl=document.getElementById('sifSearch');
  const sortEl=document.getElementById('sifSort');
  let debounce=null;
  searchEl.addEventListener('input',()=>{
    clearTimeout(debounce);
    debounce=setTimeout(()=>applyFilters(),180);
  });
  sortEl.addEventListener('change',()=>applyFilters());
}

function applyFilters(){
  const q=(document.getElementById('sifSearch').value||'').trim().toLowerCase();
  const sort=document.getElementById('sifSort').value;
  let data=_curSev==='all'?_all:_all.filter(v=>v.severity===_curSev);
  if(q){
    data=data.filter(v=>{
      return(v.id&&v.id.toLowerCase().includes(q))
        ||(v.summary&&v.summary.toLowerCase().includes(q))
        ||(v.cwe&&v.cwe.toLowerCase().includes(q))
        ||(v.affected_service&&v.affected_service.toLowerCase().includes(q))
        ||(v.source&&v.source.toLowerCase().includes(q))
        ||(v.port&&String(v.port).includes(q));
    });
  }
  const sevOrder={Critical:0,High:1,Medium:2,Low:3,Info:4,Unknown:5};
  switch(sort){
    case'severity':data.sort((a,b)=>(sevOrder[a.severity]||5)-(sevOrder[b.severity]||5));break;
    case'cvss-desc':data.sort((a,b)=>(parseFloat(b.cvss)||0)-(parseFloat(a.cvss)||0));break;
    case'cvss-asc':data.sort((a,b)=>(parseFloat(a.cvss)||0)-(parseFloat(b.cvss)||0));break;
    case'cve-desc':data.sort((a,b)=>(b.id||'').localeCompare(a.id||''));break;
    case'cve-asc':data.sort((a,b)=>(a.id||'').localeCompare(b.id||''));break;
  }
  _filtered=data;
  renderVulns(data);
}

function fvulns(sev,btn){
  document.querySelectorAll('.fb').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  _curSev=sev;
  applyFilters();
}

function exportReport(){
  if(!_last)return showError('No scan data available yet.');
  const b=new Blob([JSON.stringify(_last,null,2)],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(b);
  a.download='vulnscope-'+(_last.summary?.target||'report').replace(/[^a-zA-Z0-9.-]/g,'_')+'-'+Date.now()+'.json';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
  document.getElementById('expDrop').classList.remove('open');
}
/* ============================================================
   V6.0 — SPIDER / PASSIVE / ACTIVE RENDERERS
   ============================================================ */
function renderStages(stages,summary){
  const track=document.getElementById('stageTrack');
  const labels={recon:'Recon',spider:'Spider',fuzz:'Fuzzer',passive:'Passive',active:'Active',intel:'Intel',hazard:'Hazard'};
  let html='<div class="stage done"><i class="fas fa-sliders"></i>'+esc(summary.scan_profile||'balanced')+'<span class="st-ms">'+((summary.duration_ms||0)/1000).toFixed(1)+'s</span></div>';
  for(const k of Object.keys(labels)){
    if(!stages[k])continue;
    const ms=stages[k].duration_ms||0;
    html+='<div class="stage done"><i class="fas fa-check"></i>'+labels[k]+'<span class="st-ms">'+(ms/1000).toFixed(1)+'s</span></div>';
  }
  track.innerHTML=html;track.classList.add('show');
}
function renderSpider(sp){
  if(!sp)return;
  const s=sp.stats||{};
  const stat=(n,l)=>'<div class="sp-stat"><div class="n">'+n+'</div><div class="l">'+l+'</div></div>';
  document.getElementById('spiderStats').innerHTML=
    stat(s.pages_fetched||0,'Pages')+stat(s.urls_discovered||0,'URLs')+stat(s.forms_found||0,'Forms')+stat(s.parameters||0,'Parameters')+stat((sp.technologies||[]).length,'Technologies')+stat((sp.endpoints||[]).length,'Endpoints');
  document.getElementById('spiderMeta').textContent=(sp.base_url||'')+' · '+(s.duration_ms||0)+'ms';
  document.getElementById('techWrap').innerHTML=(sp.technologies||[]).length
    ?sp.technologies.map(t=>'<span class="tech-chip" title="'+esc(t.evidence||'')+'"><b>'+esc(t.name)+'</b>'+(t.version?' <span class="ver">'+esc(t.version)+'</span>':'')+'</span>').join('')
    :'<span class="rc-dim" style="font-size:10px">No technology fingerprints.</span>';
  const urls=(sp.urls||[]).slice(0,80);
  const eps=(sp.endpoints||[]).slice(0,40).map(u=>({url:u,status:0}));
  const rows=urls.concat(eps).map(u=>'<div class="url-row">'+(u.status?'<span class="st-pill '+(u.status>=200&&u.status<300?'st-200':u.status>=300&&u.status<400?'st-3xx':u.status===403?'st-403':u.status===404?'st-404':'st-err')+'">'+u.status+'</span>':'<span class="st-pill st-3xx" style="font-size:8px">API</span>')+'<span class="u">'+esc(u.url)+'</span></div>').join('');
  document.getElementById('urlList').innerHTML=rows||'<div class="empty-s" style="padding:20px">No URLs discovered.</div>';
  const forms=(sp.forms||[]).slice(0,40);
  document.getElementById('formRows').innerHTML=forms.length?forms.map(f=>'<tr><td><span class="st-pill '+(f.method==='POST'?'st-3xx':'st-200')+'">'+esc(f.method)+'</span></td><td>'+esc(f.action)+'</td><td>'+esc((f.inputs||[]).map(i=>i.name).join(', ').substring(0,160))+'</td><td>'+(f.has_token?'<span class="st-pill st-200">YES</span>':'<span class="st-pill st-403">NO</span>')+'</td></tr>').join(''):'<tr><td colspan="4" class="rc-dim">No forms found.</td></tr>';
  document.getElementById('spiderPanel').classList.add('show');
}
function renderPassive(alerts){
  const el=document.getElementById('passiveAlerts');
  document.getElementById('passiveMeta').textContent=alerts.length+' alert'+(alerts.length!==1?'s':'');
  el.innerHTML=alerts.length?alerts.map(a=>{
    const sev=esc(a.severity||'Info');
    const conf=String(a.confidence||'Medium');
    return '<div class="alert-row"><div><span class="sev-bar '+sev+'">'+sev+'</span></div><div>'
      +'<div class="alert-name">'+esc(a.name||'Alert')+'</div>'
      +'<div class="alert-ev">'+esc(a.evidence||'')+'</div>'
      +'<div class="alert-meta"><span class="rule-chip">'+esc(a.rule||'')+'</span>'+(a.cwe?'<span class="cwe-chip">'+esc(a.cwe)+'</span>':'')+(a.affected_count>1?'<span class="rule-chip">'+a.affected_count+' pages</span>':'')+'<span class="conf-chip '+conf.toLowerCase()+'">'+esc(conf)+'</span></div>'
      +'</div><div style="text-align:right"><div class="mono" style="font-family:var(--mono);font-size:8.5px;color:var(--t4);word-break:break-all">'+esc((a.url||'').replace(/^https?:\/\//,'').substring(0,42))+'</div><div style="margin-top:5px"><a class="ref-link" style="font-size:8px" href="'+esc(a.reference||'#')+'" target="_blank" rel="noopener noreferrer">fix <i class="fas fa-arrow-up-right-from-square"></i></a></div></div></div>';
  }).join(''):'<div class="empty-s"><i class="fas fa-check-circle"></i>No passive findings.<div class="empty-hint">Security headers, cookies and disclosure checks passed.</div></div>';
  document.getElementById('passivePanel').classList.add('show');
}
function renderActive(alerts){
  const el=document.getElementById('activeAlerts');
  document.getElementById('activeMeta').textContent=alerts.length+' confirmation'+(alerts.length!==1?'s':'');
  el.innerHTML=alerts.length?alerts.map(a=>'<div class="alert-row"><div><span class="sev-bar '+esc(a.severity)+'">'+esc(a.severity)+'</span></div><div>'
    +'<div class="alert-name">'+esc(a.name||'Finding')+(a.confidence?' <span class="conf-chip '+String(a.confidence).toLowerCase()+'">'+esc(a.confidence)+'</span>':'')+'</div>'
    +'<div class="alert-ev">'+esc(a.evidence||'')+'</div>'
    +'<div class="alert-meta">'+(a.cwe?'<span class="cwe-chip">'+esc(a.cwe)+'</span>':'')+(a.param?'<span class="rule-chip">param: '+esc(a.param)+'</span>':'')+(a.payload?'<span class="rule-chip">payload: '+esc(String(a.payload).substring(0,34))+'</span>':'')+'</div>'
    +'<div class="ev-block sol" style="margin-top:8px"><div class="ev-lbl"><i class="fas fa-screwdriver-wrench"></i>Fix</div><div class="ev-val">'+esc(a.solution||'')+'</div></div>'
    +'</div><div style="text-align:right;font-family:var(--mono);font-size:8.5px;color:var(--t4);word-break:break-all">'+esc((a.url||'').replace(/^https?:\/\//,'').substring(0,42))+'</div></div>').join('')
    :'<div class="empty-s"><i class="fas fa-check-circle"></i>No active findings.<div class="empty-hint">Injection, traversal and redirect rules did not confirm a vulnerability.</div></div>';
  document.getElementById('activePanel').classList.add('show');
}
/* ============================================================
   V6.0 — INTEL LOOKUP + HISTORY + SARIF/HTML EXPORT
   ============================================================ */
function ratingChip(sev){
  const s=esc(sev||'Info');
  return '<span class="sev-bar '+s+'">'+s+'</span>';
}
async function intelLookup(){
  const q=document.getElementById('intelQ').value.trim();
  const btn=document.getElementById('intelBtn'),box=document.getElementById('intelResults');
  if(!q)return;
  btn.disabled=true;box.innerHTML='<div class="empty-s"><i class="fas fa-circle-notch fa-spin"></i>Querying intelligence sources...</div>';
  const fd=new FormData();
  if(q.includes(':')){const [v,p]=q.split(':',2);fd.append('vendor',v);fd.append('product',p);}
  else fd.append('q',q);
  try{
    const r=await fetch('?action=cve',{method:'POST',body:fd,headers:{'X-VulnScope-Token':SCAN_TOKEN}});
    const j=await r.json();
    if(!j.success){box.innerHTML='<div class="empty-s"><i class="fas fa-triangle-exclamation"></i>'+esc(j.message||'Lookup failed')+'</div>';return}
    const results=j.results||[];
    if(!results.length){box.innerHTML='<div class="empty-s"><i class="fas fa-database"></i>No records found.<div class="empty-hint">Try a CVE ID, a vendor:product pair, or a shorter keyword.</div></div>';return}
    box.innerHTML=results.map(x=>{
      const id=esc(x.id||'');
      const cveLink=/^CVE-/.test(x.id||'')?'<a href="https://nvd.nist.gov/vuln/detail/'+id+'" target="_blank" rel="noopener noreferrer">'+id+'</a>':id;
      const notes=(x.risk_notes||[]).map(n=>'<div class="alert-ev" style="color:#fbbf24;margin-top:4px"><i class="fas fa-triangle-exclamation" style="margin-right:5px"></i>'+esc(n)+'</div>').join('');
      const cwe=(x.cwe_details||[]).map(c=>'<span class="cwe-chip" title="'+esc(c.description||'')+'">'+esc(c.id)+' '+esc(c.name)+'</span>').join(' ')||(x.cwe?'<span class="cwe-chip">'+esc(Array.isArray(x.cwe)?x.cwe.join(', '):x.cwe)+'</span>':'');
      const refs=(x.references||[]).slice(0,3).map(u=>'<a class="ref-link" style="font-size:8px" href="'+esc(u)+'" target="_blank" rel="noopener noreferrer">reference <i class="fas fa-arrow-up-right-from-square"></i></a>').join('');
      return '<div class="intel-card"><div class="intel-top"><span class="intel-id">'+cveLink+'</span>'+ratingChip(x.severity)+(x.cvss?'<span class="cvss-chip">CVSS '+(parseFloat(x.cvss)||0).toFixed(1)+'</span>':'')+(x.is_kev?'<span class="kev-chip"><i class="fas fa-triangle-exclamation"></i>KEV</span>':'')+(x.epss_score!=null?'<span class="rule-chip">EPSS '+(x.epss_score*100).toFixed(1)+'%</span>':'')+(x.published?'<span class="date-chip">'+esc(x.published)+'</span>':'')+'</div>'
        +'<div class="intel-sum">'+esc(x.summary||x.title||'No description.')+'</div>'
        +notes
        +'<div class="intel-tags">'+(cwe||'')+((x.sources||[]).length?'<span class="rule-chip">sources: '+esc(x.sources.join(', '))+'</span>':'')+'</div>'
        +((refs)?'<div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:6px">'+refs+'</div>':'')+'</div>';
    }).join('');
  }catch(e){box.innerHTML='<div class="empty-s"><i class="fas fa-triangle-exclamation"></i>'+esc(e.message)+'</div>'}
  finally{btn.disabled=false}
}
document.getElementById('intelQ').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();intelLookup()}});
async function loadHistory(){
  const box=document.getElementById('historyRows');
  box.innerHTML='<div class="empty-s"><i class="fas fa-circle-notch fa-spin"></i>Loading history...</div>';
  try{
    const r=await fetch('?action=history',{headers:{'X-VulnScope-Token':SCAN_TOKEN}});
    const j=await r.json();
    const h=j.history||[];
    box.innerHTML=h.length?h.map(x=>'<div class="hist-row"><div class="hist-t">'+esc(x.target)+'<div class="hist-sub">'+esc(x.scan_type)+' · '+esc(x.timestamp)+' · '+x.findings+' findings</div></div>'+ratingChip(x.risk_score>=80?'Critical':x.risk_score>=60?'High':x.risk_score>=40?'Medium':'Low')+'<span class="rule-chip">'+x.risk_score+'/100</span><button class="hist-ok" onclick="openReport(\''+esc(String(x.target)).replace(/'/g,"\\'")+'\')"><i class="fas fa-file-lines"></i> Report</button></div>').join(''):'<div class="empty-s">No scans recorded yet. Run a Deep Scan to populate history.</div>';
  }catch(e){box.innerHTML='<div class="empty-s"><i class="fas fa-triangle-exclamation"></i>'+esc(e.message)+'</div>'}
}
async function openReport(target){
  const r=await fetch('?action=report&format=html&target='+encodeURIComponent(target),{headers:{'X-VulnScope-Token':SCAN_TOKEN}});
  if(!r.ok){showError('No stored report for '+target+'.');return}
  const html=await r.text();
  const w=window.open('','_blank');
  if(w){w.document.write(html);w.document.close()}
}
async function exportSarif(){
  document.getElementById('expDrop').classList.remove('open');
  if(!_last)return showError('Run a scan first.');
  const target=_last.target||_last.summary?.target;
  const r=await fetch('?action=report&format=sarif&target='+encodeURIComponent(target),{headers:{'X-VulnScope-Token':SCAN_TOKEN}});
  if(!r.ok){showError('Report export needs a stored scan (run Deep or Pipeline mode).');return}
  const blob=await r.blob();
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='vulnscope-'+String(target).replace(/[^a-zA-Z0-9.-]/g,'_')+'.sarif.json';
  document.body.appendChild(a);a.click();document.body.removeChild(a);
}
async function exportHtml(){
  document.getElementById('expDrop').classList.remove('open');
  if(!_last)return showError('Run a scan first.');
  await openReport(_last.target||_last.summary?.target);
}

/* ============================================================
   V7.0 — THREAT INTELLIGENCE HUB & OPERATOR CONSOLES
   Advisory feed · sightings · comments/bundles · watchlists ·
   exploit hazard · HTTP proxy · contexts · scan policies.
   ============================================================ */
async function vsApi(action,opts={}){
  const o=Object.assign({headers:{'X-VulnScope-Token':SCAN_TOKEN}},opts);
  if(o.json!==undefined){o.method=o.method||'POST';o.body=JSON.stringify(o.json);o.headers['Content-Type']='application/json';delete o.json}
  const r=await fetch('?action='+action,o);
  let j=null;
  try{j=await r.json()}catch(e){throw new Error('HTTP '+r.status+' — non-JSON response')}
  if(!r.ok||j.success===false)throw new Error(j.message||('HTTP '+r.status));
  return j;
}
function _spin(el,msg){if(el)el.innerHTML='<div class="empty-s" style="padding:14px 18px"><i class="fas fa-circle-notch fa-spin"></i>'+esc(msg||'Loading...')+'</div>'}
function _fail(el,m){if(el)el.innerHTML='<div class="empty-s" style="padding:14px 18px"><i class="fas fa-triangle-exclamation"></i>'+esc(m||'Request failed')+'</div>'}

/* ---- ADVISORY FEED ---- */
const HZC={critical:'#ef4444',high:'#f97316',elevated:'#eab308',moderate:'#22d3ee',low:'#64748b'};
let _feedLoaded=false;
function openFeed(){const p=document.getElementById('feedPanel');p.style.display='block';p.scrollIntoView({behavior:'smooth',block:'start'});if(!_feedLoaded)loadFeed()}
async function loadFeed(){
  _feedLoaded=true;
  const src=document.getElementById('feedSrc').value,list=document.getElementById('feedList'),meta=document.getElementById('feedMeta');
  _spin(list,'Pulling the advisory corridor...');
  try{
    const j=await vsApi('recent&limit=24&source='+encodeURIComponent(src));
    if(j.sources&&document.getElementById('feedSrc').options.length<=1){
      const sel=document.getElementById('feedSrc');
      Object.entries(j.sources).forEach(([k,v])=>{const o=document.createElement('option');o.value=k;o.textContent=v;sel.appendChild(o)});
      sel.value=src;
    }
    const items=j.recent||[],top=j.most_sighted||[];
    meta.textContent=(items.length||0)+' fresh advisories · '+(src?'feeder '+src:'all feeders');
    list.innerHTML=items.length?items.map(x=>{
      const id=esc(x.id||''),link=/^(CVE|GHSA|GCVE)-/.test(id)?'<a href="https://nvd.nist.gov/vuln/detail/'+id+'" target="_blank" rel="noopener noreferrer">'+id+'</a>':id;
      const sev=(x.severity||'Info');
      return '<div class="feed-card" style="--sev:'+(sev==='Critical'?'#ef4444':sev==='High'?'#f97316':sev==='Medium'?'#eab308':'#22d3ee')+'">'
        +'<div class="feed-top"><span class="feed-id">'+link+'</span>'+ratingChip(sev)
        +(x.cvss>0?'<span class="cvss-chip">CVSS '+(parseFloat(x.cvss)||0).toFixed(1)+'</span>':'')
        +(x.is_kev?'<span class="kev-chip"><i class="fas fa-triangle-exclamation"></i>KEV</span>':'')
        +(x.epss_score!=null?'<span class="rule-chip">EPSS '+((x.epss_score||0)*100).toFixed(1)+'%</span>':'')
        +'<span class="feeder-chip">'+esc(x.feeder||'recent')+'</span></div>'
        +'<div class="feed-sum">'+esc(x.summary||'No summary available.')+'</div>'
        +'<div class="feed-foot">'+(x.published?'<span><i class="fas fa-calendar"></i> '+esc(x.published)+'</span>':'')+(x.vector?'<span>'+esc(x.vector)+'</span>':'')+'</div></div>';
    }).join(''):'<div class="empty-s"><i class="fas fa-satellite-dish"></i>No advisories returned.<div class="empty-hint">The upstream Vulnerability-Lookup corridor may be unreachable.</div></div>';
    if(top.length)list.innerHTML+='<div class="hz-agg" style="margin:6px 0 0"><span><span class="n">'+top.length+'</span><span class="l">most-sighted this week</span></span><span style="flex:1;line-height:1.7;font-size:9.5px;color:var(--t2)">'+top.map(t=>esc(t.id)+' <span style="color:var(--accent)">'+t.sightings+'</span>').join(' · ')+'</span></div>';
  }catch(e){_fail(list,e.message)}
}
document.getElementById('hzQ').addEventListener('keydown',e=>{if(e.key==='Enter'){e.preventDefault();loadHazard()}});

/* ---- EXPLOIT HAZARD ---- */
function hzCard(h){
  const band=esc(h.band||'low'),c=HZC[h.band]||'#64748b';
  return '<div class="hz-card" style="--hzc:'+c+'">'
    +'<div class="hz-id"><span>'+esc(h.vulnerability_id||'—')+'</span><span class="hz-band">'+band+'</span></div>'
    +'<div class="hz-gauge"><span class="hz-pct">'+(h.score||0)+'%</span><div class="hz-trk"><div class="hz-fill" data-w="'+(h.score||0)+'" style="background:'+c+'"></div></div></div>'
    +'<div class="hz-meta">'
    +'<span><b>EPSS / likelihood</b>'+((h.epss||0)*100).toFixed(2)+'%'+(h.kev?' <span style="color:var(--danger)">(KEV-weighted)</span>':'')+'</span>'
    +'<span><b>Adjusted likelihood</b>'+((h.adjusted_likelihood||0)*100).toFixed(2)+'%</span>'
    +'<span><b>Daily hazard</b>'+(h.daily_hazard!=null?h.daily_hazard:'—')+'</span>'
    +'<span><b>Horizon</b>'+(h.horizon_days||30)+' days · '+esc(h.model||'exponential')+'</span>'
    +(h.age_days!=null?'<span><b>Advisory age</b>'+h.age_days+'d</span>':'')
    +(h.best_control?'<span><b>Best control gain</b>'+esc(h.best_control)+' −'+(h.best_reduction||0)+'pts</span>':'')
    +'</div></div>';
}
async function loadHazard(){
  const q=document.getElementById('hzQ').value.trim(),btn=document.getElementById('hzBtn'),out=document.getElementById('hzOut');
  if(!q){showError('Enter a CVE ID or a comma-separated list.');return}
  btn.disabled=true;_spin(out,'Solving the hazard equation...');
  try{
    const ids=q.split(/[,\s;]+/).map(s=>s.trim().toUpperCase()).filter(Boolean);
    let j;
    if(ids.length===1&&/^CVE-\d{4}-\d+$/i.test(ids[0])){
      j=await vsApi('hazard&vuln_id='+encodeURIComponent(ids[0]));
      out.innerHTML='<div class="hz-top">'+hzCard(j.instance)+'</div>';
    }else{
      j=await vsApi('hazard',{json:{instances:ids,horizon_days:30}});
      const inst=(j.instances||[]).filter(x=>!x.error);
      out.innerHTML='<div class="hz-top">'+inst.map(hzCard).join('')+'</div>'
        +'<div class="hz-agg">'
        +'<span><span class="n">'+((j.probability_at_least_one_event||0)*100).toFixed(1)+'%</span><span class="l">P(&ge;1 event / '+j.horizon_days+'d)</span></span>'
        +'<span><span class="n">'+(j.expected_events||0).toFixed(2)+'</span><span class="l">Expected events</span></span>'
        +'<span><span class="n">'+(j.aggregate_daily_hazard||0).toFixed(4)+'</span><span class="l">Aggregate hazard</span></span>'
        +'<span><span class="n">'+j.computed+'</span><span class="l">Computed</span></span>'
        +'</div>';
    }
    setTimeout(()=>out.querySelectorAll('.hz-fill[data-w]').forEach(b=>b.style.width=b.dataset.w+'%'),60);
  }catch(e){_fail(out,e.message)}
  finally{btn.disabled=false}
}

/* ---- SIGHTINGS ---- */
let _sighLoaded=false;
function openSightings(){
  const p=document.getElementById('sightingsPanel');p.style.display='block';p.scrollIntoView({behavior:'smooth',block:'start'});
  if(document.getElementById('sighKind').options.length<=1){
    const sel=document.getElementById('sighKind');
    SIGHT_KINDS.forEach(([v,l])=>{const o=document.createElement('option');o.value=v;o.textContent='Sighting: '+l;sel.appendChild(o)});
  }
  if(!_sighLoaded)loadSightings();
}
async function loadSightings(){
  _sighLoaded=true;
  const box=document.getElementById('sighList');_spin(box,'Loading sighting log...');
  try{
    const j=await vsApi('sightings');
    const rows=j.sightings||[];
    box.innerHTML=rows.length?rows.map(s=>'<div class="notif-row"><div class="notif-ico"><i class="fas fa-eye"></i></div><div class="notif-body"><b style="color:var(--t1)">'+esc(s.vuln_id)+'</b> <span class="rule-chip">'+esc(s.kind)+'</span>'+(_mkSev(s.kind))+'<div>'+esc(s.note||'')+'</div><div class="notif-meta">'+esc(s.author||'anon')+' @ '+esc(s.target||'—')+' · '+esc(s.timestamp)+'</div></div></div>').join(''):'<div class="empty-s" style="padding:14px 18px">No sightings recorded yet.</div>';
  }catch(e){_fail(box,e.message)}
}
function _mkSev(kind){
  const c={exploited:'Critical',confirmed:'High',patched:'Info','not-exploited':'Info',seen:'Low','not-confirmed':'Low','not-patched':'High'}[kind];
  return c?'<span class="sev-bar '+c+'">'+c+'</span>':'';
}
async function recordSighting(){
  const btn=document.getElementById('sighBtn'),msg=document.getElementById('sighMsg');
  const vuln=document.getElementById('sighVuln').value.trim().toUpperCase();
  if(!vuln){showError('Vuln ID required.');return}
  btn.disabled=true;msg.textContent='';
  const fd=new FormData();
  fd.append('vuln_id',vuln);fd.append('kind',document.getElementById('sighKind').value);
  fd.append('target',document.getElementById('sighTarget').value.trim());
  fd.append('note',document.getElementById('sighNote').value.trim());
  fd.append('author',document.getElementById('sighAuthor').value.trim());
  try{
    const j=await vsApi('sightings',{method:'POST',body:fd});
    msg.innerHTML='<span style="color:#22c55e">Sighting stored'+(j.mirror?' &amp; mirrored to CIRCL':'')+'.</span>';
    document.getElementById('sighNote').value='';document.getElementById('sighTarget').value='';
    await loadSightings();
  }catch(e){msg.innerHTML='<span style="color:var(--danger)">'+esc(e.message)+'</span>'}
  finally{btn.disabled=false}
}

/* ---- COMMENTS & BUNDLES ---- */
let _collabLoaded=false;
function collabTab(name,btn){
  document.querySelectorAll('#collabPanel .vs-tab').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
  document.getElementById('ctComment').style.display=name==='comments'?'block':'none';
  document.getElementById('ctBundles').style.display=name==='bundles'?'block':'none';
  if(name==='bundles')loadBundles();else loadComments();
}
function openCollab(){
  const p=document.getElementById('collabPanel');p.style.display='block';p.scrollIntoView({behavior:'smooth',block:'start'});
  if(!_collabLoaded){_collabLoaded=true;loadComments()}
}
async function loadComments(){
  const box=document.getElementById('cmList');_spin(box,'Loading comments...');
  try{
    const j=await vsApi('comments');
    const rows=j.comments||[];
    box.innerHTML=rows.length?rows.map(c=>'<div class="notif-row"><div class="notif-ico"><i class="fas fa-comments"></i></div><div class="notif-body"><b style="color:var(--t1)">'+esc(c.vuln_id)+'</b>'+(c.severity_vote?' '+_mkSev(c.severity_vote):'')+'<div>'+esc(c.body)+'</div><div class="notif-meta">'+esc(c.author||'analyst')+' · '+esc(c.timestamp)+'</div></div></div>').join(''):'<div class="empty-s" style="padding:14px 18px">No comments yet.</div>';
  }catch(e){_fail(box,e.message)}
}
async function postComment(){
  const btn=document.getElementById('cmBtn'),msg=document.getElementById('cmMsg');
  const vuln=document.getElementById('cmVuln').value.trim().toUpperCase(),body=document.getElementById('cmBody').value.trim();
  if(!vuln||!body){showError('Vuln ID and comment body are required.');return}
  btn.disabled=true;msg.textContent='';
  const fd=new FormData();
  fd.append('vuln_id',vuln);fd.append('body',body);
  fd.append('author',document.getElementById('cmAuthor').value.trim());
  try{await vsApi('comments',{method:'POST',body:fd});msg.innerHTML='<span style="color:#22c55e">Comment saved.</span>';document.getElementById('cmBody').value='';await loadComments()}
  catch(e){msg.innerHTML='<span style="color:var(--danger)">'+esc(e.message)+'</span>'}
  finally{btn.disabled=false}
}
async function loadBundles(){
  const box=document.getElementById('bdList');_spin(box,'Loading bundles...');
  try{
    const j=await vsApi('bundles');
    const rows=j.bundles||[];
    box.innerHTML=rows.length?rows.map(b=>'<div class="notif-row"><div class="notif-ico"><i class="fas fa-box-archive"></i></div><div class="notif-body"><b style="color:var(--t1)">'+esc(b.name)+'</b> <span class="rule-chip">'+b.count+' CVE(s)</span>'+(b.is_default?'':'')+((b.vuln_ids||[]).slice(0,6).map(id=>'<span class="cwe-chip">'+esc(id)+'</span>').join(' ')+(b.count>6?' <span class="rc-dim">+more</span>':''))+'<div>'+esc(b.description||'')+'</div></div><button class="vs-ghost" style="flex-shrink:0" onclick="delBundle('+b.id+')"><i class="fas fa-trash"></i></button></div>').join(''):'<div class="empty-s" style="padding:14px 18px">No bundles yet.</div>';
  }catch(e){_fail(box,e.message)}
}
async function postBundle(){
  const btn=document.getElementById('bdBtn'),msg=document.getElementById('bdMsg');
  const name=document.getElementById('bdName').value.trim();
  if(!name){showError('Bundle name required.');return}
  btn.disabled=true;msg.textContent='';
  const fd=new FormData();
  fd.append('do','create');fd.append('name',name);
  fd.append('description',document.getElementById('bdDesc').value.trim());
  fd.append('vuln_ids',document.getElementById('bdIds').value.trim());
  try{await vsApi('bundles',{method:'POST',body:fd});msg.innerHTML='<span style="color:#22c55e">Bundle created.</span>';document.getElementById('bdIds').value='';await loadBundles()}
  catch(e){msg.innerHTML='<span style="color:var(--danger)">'+esc(e.message)+'</span>'}
  finally{btn.disabled=false}
}
async function delBundle(id){
  const fd=new FormData();fd.append('do','delete');fd.append('id',id);
  try{await vsApi('bundles',{method:'POST',body:fd});await loadBundles()}catch(e){showError(e.message)}
}

/* ---- WATCHLISTS ---- */
let _wlLoaded=false;
function openWatch(){
  const p=document.getElementById('watchPanel');p.style.display='block';p.scrollIntoView({behavior:'smooth',block:'start'});
  if(!_wlLoaded){_wlLoaded=true;loadWatch()}
}
async function loadWatch(){
  _wlLoaded=true;
  const rows=document.getElementById('wlRows');
  rows.innerHTML='<tr><td colspan="5" class="rc-dim">Loading watchlists...</td></tr>';
  try{
    const j=await vsApi('watchlists');
    const wl=j.watchlists||[];
    rows.innerHTML=wl.length?wl.map(w=>'<tr><td><b style="color:var(--t1)">'+esc(w.vendor)+'</b>:<b>'+esc(w.product)+'</b><div class="notif-meta">every '+esc(w.frequency||'daily')+' · last checked '+esc(w.last_checked||'never')+'</div></td><td>CVSS &ge; '+(parseFloat(w.min_cvss)||0)+( (parseInt(w.hazard_threshold)||0)>0?' · hazard &ge; '+w.hazard_threshold:'')+'</td><td>'+(w.webhook_url?'<i class="fas fa-link" style="color:#22c55e"></i> webhook':'<span class="rc-dim">local only</span>')+'</td><td>'+((parseInt(w.hazard_alerted)?'<span class="st-pill st-403">ALERTED</span> ':''))+(w.pending||0)+' pending<br><span class="notif-meta">'+(w.total||0)+' lifetime</span></td><td><button class="vs-ghost" style="padding:4px 9px" onclick="checkWatch(false,'+w.id+')"><i class="fas fa-rotate"></i></button> <button class="vs-ghost" style="padding:4px 9px" onclick="delWatch('+w.id+')"><i class="fas fa-trash"></i></button></td></tr>').join(''):'<tr><td colspan="5" class="rc-dim">No watchlists configured.</td></tr>';
    const nf=document.getElementById('notifFeed');
    const nt=j.notifications||[];
    nf.innerHTML=nt.length?nt.map(n=>'<div class="notif-row"><div class="notif-ico"><i class="fas fa-paper-plane"></i></div><div class="notif-body">'+(n.payload?.text?esc(String(n.payload.text).substring(0,180)):'')+'<div class="notif-meta">'+esc(n.vuln_id||'')+' · '+(n.delivered?'<span style="color:#22c55e">delivered</span>':'pending')+(n.error?' · '+esc(n.error):'')+'</div></div></div>').join(''):'<div class="empty-s" style="padding:14px 18px">Run a check to queue notifications.</div>';
  }catch(e){rows.innerHTML='<tr><td colspan="5" class="rc-dim">'+esc(e.message)+'</td></tr>'}
}
async function addWatch(){
  const btn=document.getElementById('wlBtn');
  const vendor=document.getElementById('wlVendor').value.trim(),product=document.getElementById('wlProduct').value.trim();
  if(!vendor||!product){showError('Vendor and product are required.');return}
  btn.disabled=true;
  const fd=new FormData();
  fd.append('do','add');fd.append('vendor',vendor);fd.append('product',product);
  fd.append('min_cvss',document.getElementById('wlCvss').value||'0');
  fd.append('frequency',document.getElementById('wlFreq').value);
  fd.append('hazard_threshold',document.getElementById('wlHz').value||'0');
  fd.append('webhook_url',document.getElementById('wlHook').value.trim());
  try{await vsApi('watchlists',{method:'POST',body:fd});document.getElementById('wlVendor').value='';document.getElementById('wlProduct').value='';document.getElementById('wlHook').value='';await loadWatch()}
  catch(e){showError(e.message)}
  finally{btn.disabled=false}
}
async function delWatch(id){
  const fd=new FormData();fd.append('do','delete');fd.append('id',id);
  try{await vsApi('watchlists',{method:'POST',body:fd});await loadWatch()}catch(e){showError(e.message)}
}
async function checkWatch(all,id){
  const fd=new FormData();fd.append('do','check');
  if(id)fd.append('id',id);
  try{
    const j=await vsApi('watchlists',{method:'POST',body:fd});
    showError(all?('Check finished: '+j.new+' new advisories across '+j.checked+' list(s), '+j.notified+' webhook(s) sent.'):'Check finished.');
    await loadWatch();
  }catch(e){showError(e.message)}
}

/* ---- HTTP PROXY ---- */
let _proxyLoaded=false;
function proxyTab(name,btn){
  document.querySelectorAll('#proxyPanel .vs-tab').forEach(b=>b.classList.remove('active'));btn.classList.add('active');
  document.getElementById('pxHist').style.display=name==='hist'?'block':'none';
  document.getElementById('pxReplay').style.display=name==='replay'?'block':'none';
}
function openProxy(){
  const p=document.getElementById('proxyPanel');p.style.display='block';p.scrollIntoView({behavior:'smooth',block:'start'});
  if(!_proxyLoaded){_proxyLoaded=true;loadProxy()}
}
async function loadProxy(){
  _proxyLoaded=true;
  const rows=document.getElementById('pxRows');
  rows.innerHTML='<tr><td colspan="6" class="rc-dim">Loading traffic...</td></tr>';
  try{
    const q=document.getElementById('pxQ').value.trim(),host=document.getElementById('pxHost').value.trim(),type=document.getElementById('pxType').value;
    let a='proxy&limit=150';
    if(q)a+='&q='+encodeURIComponent(q);
    if(host)a+='&host='+encodeURIComponent(host);
    if(type)a+='&type='+encodeURIComponent(type);
    const j=await vsApi(a);
    const entries=j.entries||[];
    rows.innerHTML=entries.length?entries.map(h=>'<tr><td><span class="notif-meta">#'+h.id+'</span></td><td><span class="st-pill '+(h.method==='GET'?'st-200':'st-3xx')+'" style="font-size:8px">'+esc(h.method)+'</span></td><td>'+_vsPill(h.status)+'</td><td style="max-width:380px"><span class="u" style="font-family:var(--mono);font-size:10px">'+esc(h.url)+'</span><div class="notif-meta">'+esc(h.session||'—')+' · '+esc(h.entry_type)+' · '+esc(h.ts||'')+'</div></td><td>'+h.size+'</td><td>'+h.ms+'</td></tr>').join(''):'<tr><td colspan="6" class="rc-dim">No traffic recorded yet — run a scan.</td></tr>';
  }catch(e){rows.innerHTML='<tr><td colspan="6" class="rc-dim">'+esc(e.message)+'</td></tr>'}
}
async function purgeProxy(){
  const fd=new FormData();fd.append('do','purge');
  try{await vsApi('proxy',{method:'POST',body:fd});await loadProxy()}catch(e){showError(e.message)}
}
async function replayReq(){
  const btn=document.getElementById('rpBtn'),out=document.getElementById('rpOut');
  const url=document.getElementById('rpUrl').value.trim();
  if(!url){showError('URL required.');return}
  btn.disabled=true;out.hidden=false;out.textContent='Sending request...';
  const fd=new FormData();
  fd.append('do','replay');fd.append('method',document.getElementById('rpMethod').value);
  fd.append('url',url);fd.append('headers',document.getElementById('rpHeaders').value);
  fd.append('body',document.getElementById('rpBody').value);
  try{
    const j=await vsApi('proxy',{method:'POST',body:fd});
    const r=j.response||{};
    out.innerHTML='<span style="color:var(--accent)">[SENT]</span> '+esc(r.sent||'')+'\n<span class="sep">──────── response ────────</span>'
      +'<span style="color:'+(r.status<400?'#22c55e':'var(--danger)')+'">[HTTP '+r.status+' · '+r.ms+'ms]</span>\n'+esc(r.headers||'')+'\n<span class="sep">──────── body ('+ (r.size||0) +'B) ────────</span>\n'+esc((r.body||'').substring(0,4000));
    await loadProxy();
  }catch(e){out.textContent='Error: '+e.message}
  finally{btn.disabled=false}
}

/* ---- CONTEXTS ---- */
let _ctxLoaded=false;
function cxAuthFields(){
  const a=document.getElementById('cxAuth').value;
  document.getElementById('cxUrl').disabled=(a!=='auto-cookie');
  document.getElementById('cxPayload').disabled=(a!=='auto-cookie');
}
function openCtx(){
  const p=document.getElementById('ctxPanel');p.style.display='block';p.scrollIntoView({behavior:'smooth',block:'start'});
  if(!_ctxLoaded){_ctxLoaded=true;loadCtx()}
}
async function loadCtx(){
  _ctxLoaded=true;
  const box=document.getElementById('cxList');
  try{
    const j=await vsApi('contexts');
    const rows=j.contexts||[];
    box.innerHTML=rows.length?'<div class="wl-table-wrap">'+rows.map(c=>{
      const dots={none:'#64748b','auto-cookie':'#22c55e',basic:'#22d3ee'};
      return '<div class="ctx-row"><span class="wmark-dot" style="background:'+(dots[c.auth_type]||'#64748b')+'"></span><span class="ctx-name">'+esc(c.name)+'</span><span class="ctx-meta">'+esc(c.auth_type)+' · '+esc(c.scope||'no scope')+(c.auth_type==='auto-cookie'?' · '+esc(c.auth_url||''):'')+'</span>'
      +'<button class="vs-ghost" style="padding:4px 9px" onclick="testCtx('+c.id+',this)"><i class="fas fa-vial"></i></button><button class="vs-ghost" style="padding:4px 9px" onclick="delCtx('+c.id+')"><i class="fas fa-trash"></i></button></div>';
    }).join('')+'</div>':'<div class="empty-s" style="padding:14px 18px">No contexts saved yet — sessions fall back to the cookie field in the scan form.</div>';
    refreshCtxSelect(rows);
  }catch(e){box.innerHTML='<div class="empty-s" style="padding:14px 18px">'+esc(e.message)+'</div>'}
}
function refreshCtxSelect(rows){
  const sel=document.getElementById('scanCtx');
  const cur=sel.value;
  while(sel.options.length>1)sel.remove(1);
  (rows||[]).forEach(c=>{const o=document.createElement('option');o.value=c.id;o.textContent='Context: '+c.name+' ('+c.auth_type+')';sel.appendChild(o)});
  if(cur&&rows.some(c=>String(c.id)===cur))sel.value=cur;
}
async function saveCtx(){
  const btn=document.getElementById('cxBtn'),msg=document.getElementById('cxMsg');
  const name=document.getElementById('cxName').value.trim();
  if(!name){showError('Context name required.');return}
  btn.disabled=true;
  const fd=new FormData();fd.append('do','save');
  fd.append('name',name);fd.append('auth_type',document.getElementById('cxAuth').value);
  fd.append('scope',document.getElementById('cxScope').value.trim());
  fd.append('auth_url',document.getElementById('cxUrl').value.trim());
  fd.append('username',document.getElementById('cxUser').value.trim());
  fd.append('password',document.getElementById('cxPass').value);
  fd.append('auth_payload',document.getElementById('cxPayload').value.trim());
  const extra=document.getElementById('cxCookie').value.trim();
  if(extra)fd.append('headers',extra);
  try{await vsApi('contexts',{method:'POST',body:fd});msg.innerHTML='<span style="color:#22c55e">Context saved.</span>';document.getElementById('cxPass').value='';await loadCtx()}
  catch(e){msg.innerHTML='<span style="color:var(--danger)">'+esc(e.message)+'</span>'}
  finally{btn.disabled=false}
}
async function delCtx(id){
  const fd=new FormData();fd.append('do','delete');fd.append('id',id);
  try{await vsApi('contexts',{method:'POST',body:fd});await loadCtx()}catch(e){showError(e.message)}
}
async function testCtx(id,btn){
  const old=btn.innerHTML;btn.innerHTML='<i class="fas fa-circle-notch fa-spin"></i>';btn.disabled=true;
  const fd=new FormData();fd.append('do','test');fd.append('id',id);
  try{
    const j=await vsApi('contexts',{method:'POST',body:fd});
    alert((j.success?'Session OK — ':'Session failed — ')+j.detail+'\nHTTP login status: '+j.login_status);
  }catch(e){showError(e.message)}
  finally{btn.innerHTML=old;btn.disabled=false}
}

/* ---- SCAN POLICIES ---- */
let _plLoaded=false,_groupsRef=null;
const PL_OPTS=['off','low','default','high'];
function openPolicy(){
  const p=document.getElementById('policyPanel');p.style.display='block';p.scrollIntoView({behavior:'smooth',block:'start'});
  if(!_plLoaded){_plLoaded=true;loadPolicies()}
}
async function loadPolicies(){
  _plLoaded=true;
  const wrap=document.getElementById('plGroups'),list=document.getElementById('plList');
  try{
    const j=await vsApi('policies');
    _groupsRef=j.groups||{};
    wrap.innerHTML=Object.entries(j.groups||{}).map(([k,label])=>'<div style="grid-column:span 1"><div style="font-size:9.5px;color:var(--t3);margin-bottom:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(label)+'">'+esc(k)+'</div><select class="mi-inp pg-sel" data-g="'+esc(k)+'" style="padding:7px 8px">'+PL_OPTS.map(o=>'<option value="'+o+'">'+o+'</option>').join('')+'</select></div>').join('');
    list.innerHTML=(j.policies||[]).length?'<div class="wl-table-wrap">'+j.policies.map(p=>{
      const g=(p.config?.groups)||{};
      const chips=Object.entries(g).map(([k,v])=>'<span class="rule-chip" style="'+(v==='off'?'color:var(--danger)':'')+'">'+esc(k)+':'+esc(v)+'</span>').join(' ');
      return '<div class="ctx-row"><span class="ctx-name">'+esc(p.name)+(p.is_default?' <span class="ind-chip" style="color:#22c55e;border:1px solid rgba(34,197,94,.3)">DEFAULT</span>':'')+'</span><span class="ctx-meta">×'+esc(p.config?.requests_mult||1)+' '+chips+'</span><button class="vs-ghost" style="padding:4px 9px" onclick="delPolicy('+p.id+')"><i class="fas fa-trash"></i></button></div>';
    }).join('')+'</div>':'<div class="empty-s" style="padding:14px 18px">No custom policies — deep scans run the built-in default.</div>';
    refreshPolicySelect(j.policies||[]);
  }catch(e){list.innerHTML='<div class="empty-s" style="padding:14px 18px">'+esc(e.message)+'</div>'}
}
function refreshPolicySelect(rows){
  const sel=document.getElementById('scanPolicy');
  const cur=sel.value;
  while(sel.options.length>1)sel.remove(1);
  rows.forEach(p=>{const o=document.createElement('option');o.value=p.id;o.textContent='Policy: '+p.name+(p.is_default?' ★':'');sel.appendChild(o)});
  if(cur&&(cur==='default'||rows.some(p=>String(p.id)===cur)))sel.value=cur;
}
async function savePolicy(){
  const btn=document.getElementById('plBtn'),msg=document.getElementById('plMsg');
  const name=document.getElementById('plName').value.trim();
  if(!name){showError('Policy name required.');return}
  btn.disabled=true;
  const config={requests_mult:document.getElementById('plMult').value||'1'};
  document.querySelectorAll('#plGroups .pg-sel').forEach(s=>{if(s.value!=='default')config[s.dataset.g]=s.value});
  const fd=new FormData();fd.append('do','save');fd.append('name',name);fd.append('default',document.getElementById('plDefault').checked?'1':'0');
  Object.entries(config).forEach(([k,v])=>fd.append('config['+k+']',String(v)));
  try{await vsApi('policies',{method:'POST',body:fd});msg.innerHTML='<span style="color:#22c55e">Policy saved.</span>';await loadPolicies()}
  catch(e){msg.innerHTML='<span style="color:var(--danger)">'+esc(e.message)+'</span>'}
  finally{btn.disabled=false}
}
async function delPolicy(id){
  const fd=new FormData();fd.append('do','delete');fd.append('id',id);
  try{await vsApi('policies',{method:'POST',body:fd});await loadPolicies()}catch(e){showError(e.message)}
}

/* ---- V7 bootstrap: preload contexts + policies + sighting kinds for the scan form ---- */
(function(){
  const sel=document.getElementById('sighKind');
  SIGHT_KINDS.forEach(([v,l])=>{const o=document.createElement('option');o.value=v;o.textContent='Sighting: '+l;sel.appendChild(o)});
})();
(async()=>{try{const j=await vsApi('contexts');refreshCtxSelect(j.contexts||[])}catch(e){/* sidebar still console-first */}})();
(async()=>{try{const j=await vsApi('policies');refreshPolicySelect(j.policies||[])}catch(e){}})();
</script>
</body>
</html>
