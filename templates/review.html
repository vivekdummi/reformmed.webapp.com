{% extends "base.html" %}
{% block title %}AI Review — REFORMMED Monitor{% endblock %}
{% block page_title %}AI Review{% endblock %}

{% block content %}
<div class="page-header">
  <div>
    <h1>AI Infrastructure Review</h1>
    <p>Claude analyzes live DB data and generates a complete health summary</p>
  </div>
  <button class="btn btn-primary" id="run-btn" onclick="runReview()">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg>
    Run Review
  </button>
</div>

<!-- Status bar -->
<div id="status-bar" style="display:none;align-items:center;gap:10px;padding:10px 16px;background:var(--bg2);border:1px solid var(--border);border-radius:10px;margin-bottom:16px;font-size:13px;">
  <span class="pulse" style="background:var(--accent);box-shadow:0 0 6px var(--accent)"></span>
  <span id="status-text">Collecting data from database...</span>
</div>

<!-- Output card -->
<div class="card" style="min-height:300px">
  <!-- Idle state -->
  <div id="idle-state" style="display:flex;flex-direction:column;align-items:center;justify-content:center;padding:60px 20px;gap:16px;color:var(--text-muted)">
    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" opacity=".4">
      <circle cx="12" cy="12" r="10"/>
      <path d="M12 16v-4M12 8h.01"/>
    </svg>
    <div style="text-align:center">
      <div style="font-size:15px;font-weight:600;margin-bottom:6px;color:var(--text)">Ready to analyze</div>
      <div style="font-size:13px">Click <strong>Run Review</strong> to pull live data from PostgreSQL<br>and generate an AI-powered health summary</div>
    </div>
  </div>

  <!-- Output area -->
  <div id="output-area" style="display:none">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
      <div style="display:flex;align-items:center;gap:8px">
        <div style="width:8px;height:8px;border-radius:50%;background:var(--accent)"></div>
        <span style="font-size:11px;font-weight:600;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px">AI Review</span>
        <span id="gen-time" style="font-size:11px;color:var(--text-muted)"></span>
      </div>
      <div style="display:flex;gap:8px">
        <button class="btn btn-ghost btn-sm" onclick="copyOutput()">Copy</button>
        <button class="btn btn-ghost btn-sm" onclick="runReview()">↻ Re-run</button>
      </div>
    </div>
    <div id="md-output" style="
      font-size:14px;line-height:1.75;color:var(--text);
      border-top:1px solid var(--border);padding-top:16px;
      white-space:pre-wrap;font-family:'Space Grotesk',sans-serif;
    "></div>
    <div id="cursor" style="display:inline-block;width:2px;height:16px;background:var(--accent);margin-left:2px;animation:blink 1s step-end infinite;vertical-align:text-bottom"></div>
  </div>
</div>

<!-- Quick stats pulled from DB shown while AI is generating -->
<div id="snapshot-grid" style="display:none;margin-top:14px">
  <div class="card-title" style="margin-bottom:10px">Live Snapshot (from DB)</div>
  <div class="stat-grid" style="grid-template-columns:repeat(auto-fill,minmax(130px,1fr))">
    <div class="stat-card total">
      <div class="stat-value" id="snap-total" style="color:var(--accent);font-size:26px">—</div>
      <div class="stat-label">Machines</div>
    </div>
    <div class="stat-card online">
      <div class="stat-value" id="snap-online" style="color:var(--green);font-size:26px">—</div>
      <div class="stat-label">Online</div>
    </div>
    <div class="stat-card offline">
      <div class="stat-value" id="snap-offline" style="color:var(--red);font-size:26px">—</div>
      <div class="stat-label">Offline</div>
    </div>
    <div class="stat-card warning">
      <div class="stat-value" id="snap-dvr" style="color:var(--yellow);font-size:26px">—</div>
      <div class="stat-label">DVRs Online</div>
    </div>
    <div class="stat-card total">
      <div class="stat-value" id="snap-alerts" style="color:var(--accent2);font-size:26px">—</div>
      <div class="stat-label">Alerts 24h</div>
    </div>
  </div>
</div>

<style>
@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}
#md-output h1,#md-output h2{font-size:15px;font-weight:700;margin:18px 0 6px;color:var(--accent);}
#md-output h3{font-size:14px;font-weight:600;margin:14px 0 5px;}
#md-output strong{font-weight:700;color:var(--text);}
#md-output ul,#md-output ol{padding-left:20px;margin:6px 0;}
#md-output li{margin:4px 0;}
#md-output code{font-family:'JetBrains Mono',monospace;font-size:12px;background:var(--bg3);padding:1px 6px;border-radius:4px;}
#md-output hr{border:none;border-top:1px solid var(--border);margin:14px 0;}
</style>
{% endblock %}

{% block extra_js %}
<script>
var _buffer = '';
var _startTime = null;
var _es = null;

function simpleMarkdown(text){
  return text
    .replace(/^### (.+)$/gm,  '<h3>$1</h3>')
    .replace(/^## (.+)$/gm,   '<h2>$1</h2>')
    .replace(/^# (.+)$/gm,    '<h1>$1</h1>')
    .replace(/\*\*(.+?)\*\*/g,'<strong>$1</strong>')
    .replace(/^- (.+)$/gm,    '<li>$1</li>')
    .replace(/(<li>.*<\/li>\n?)+/g, function(m){ return '<ul>'+m+'</ul>'; })
    .replace(/\n\n/g, '<br><br>')
    .replace(/^---$/gm,       '<hr>');
}

function setStatus(txt){ document.getElementById('status-text').textContent = txt; }

function runReview(){
  // Close any existing stream
  if(_es){ _es.close(); _es = null; }

  _buffer = '';
  _startTime = Date.now();

  // Show UI
  document.getElementById('idle-state').style.display = 'none';
  document.getElementById('output-area').style.display = 'block';
  document.getElementById('status-bar').style.display  = 'flex';
  document.getElementById('snapshot-grid').style.display = 'block';
  document.getElementById('md-output').innerHTML = '';
  document.getElementById('cursor').style.display = 'inline-block';
  document.getElementById('gen-time').textContent = '';
  document.getElementById('run-btn').disabled = true;
  document.getElementById('run-btn').textContent = 'Running…';

  setStatus('Collecting live data from database…');

  // Load quick stats
  fetch('/api/home/data')
    .then(function(r){ return r.json(); })
    .then(function(d){
      document.getElementById('snap-total').textContent   = d.total   || '—';
      document.getElementById('snap-online').textContent  = d.online  || '—';
      document.getElementById('snap-offline').textContent = d.offline || '—';
      document.getElementById('snap-alerts').textContent  = d.alerts_today || '0';
    }).catch(function(){});

  fetch('/api/machines/summary')
    .then(function(r){ return r.json(); })
    .catch(function(){ return {}; });

  setTimeout(function(){ setStatus('Sending to Claude AI…'); }, 800);

  // SSE stream
  _es = new EventSource('/review/stream');

  _es.onmessage = function(e){
    var obj;
    try{ obj = JSON.parse(e.data); } catch(err){ return; }

    if(obj.error){
      setStatus('Error: ' + obj.error);
      document.getElementById('cursor').style.display = 'none';
      document.getElementById('run-btn').disabled = false;
      document.getElementById('run-btn').innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run Review';
      _es.close(); return;
    }

    if(obj.done){
      document.getElementById('cursor').style.display = 'none';
      document.getElementById('status-bar').style.display = 'none';
      document.getElementById('run-btn').disabled = false;
      document.getElementById('run-btn').innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run Review';
      var elapsed = ((Date.now() - _startTime)/1000).toFixed(1);
      document.getElementById('gen-time').textContent = 'Generated in ' + elapsed + 's';
      // Final render with markdown
      document.getElementById('md-output').innerHTML = simpleMarkdown(_buffer);
      _es.close(); return;
    }

    if(obj.text){
      _buffer += obj.text;
      setStatus('Generating summary…');
      // Streaming: show raw text with cursor, do markdown on completion
      document.getElementById('md-output').textContent = _buffer;
    }
  };

  _es.onerror = function(){
    setStatus('Connection lost. Try again.');
    document.getElementById('cursor').style.display = 'none';
    document.getElementById('run-btn').disabled = false;
    document.getElementById('run-btn').innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run Review';
    _es.close();
  };
}

function copyOutput(){
  navigator.clipboard.writeText(_buffer).then(function(){
    var btn = event.target;
    btn.textContent = 'Copied!';
    setTimeout(function(){ btn.textContent = 'Copy'; }, 1500);
  });
}

// DVR snap from dvr ping_all if available
fetch('/dvr/ping-all-ids', {method:'POST'})
  .then(function(r){ return r.json(); })
  .then(function(d){
    var online = Object.values(d).filter(function(v){ return v==='online'; }).length;
    document.getElementById('snap-dvr').textContent = online || '—';
  }).catch(function(){});
</script>
{% endblock %}