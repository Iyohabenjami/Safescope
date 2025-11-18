// script.js - frontend logic for SafeScope

// Helpers
function elt(id) { return document.getElementById(id); }
function show(el){ el.classList.remove('hidden'); }
function hide(el){ el.classList.add('hidden'); }

// Render helpers
function verdictChip(verdict) {
  if (!verdict) return '<span class="chip-unk">Unknown</span>';
  if (verdict.toLowerCase() === 'malicious') return '<span class="chip-mal">Malicious</span>';
  if (verdict.toLowerCase() === 'suspicious') return '<span class="chip-susp">Suspicious</span>';
  if (verdict.toLowerCase() === 'safe') return '<span class="chip-safe">Safe</span>';
  return `<span class="chip-unk">${verdict}</span>`;
}

function renderResultsCard(data, type) {
  // data is an object with keys depending on type
  let html = `<div class="flex justify-between items-start"><div>`;
  if (type === 'domain') {
    html += `<h4 class="text-lg font-semibold mb-2">${data.domain}</h4>`;
    const registrar = (data.whois && data.whois.registrar) || data.registrar || 'N/A';
    const created = (data.whois && Array.isArray(data.whois.creation_date) ? data.whois.creation_date[0] : (data.whois && data.whois.creation_date) || data.creation_date || 'N/A');
    html += `<div class="mb-2"><strong>Registrar:</strong> ${registrar}</div>`;
    html += `<div class="mb-2"><strong>Created:</strong> ${created}</div>`;
    html += `<div class="mb-2"><strong>VT verdict:</strong> ${verdictChip(data.verdict)}</div>`;
  } else if (type === 'ip') {
    html += `<h4 class="text-lg font-semibold mb-2">${data.ip}</h4>`;
    html += `<div class="mb-2"><strong>Reverse DNS:</strong> ${data.rev_dns || 'N/A'}</div>`;
    html += `<div class="mb-2"><strong>IP Info:</strong> ${(data.ipinfo && data.ipinfo.org) || 'N/A'}</div>`;
    html += `<div class="mb-2"><strong>VT verdict:</strong> ${verdictChip(data.verdict)}</div>`;
  } else if (type === 'file') {
    html += `<h4 class="text-lg font-semibold mb-2">${data.filename}</h4>`;
    html += `<div class="mb-2"><strong>Size:</strong> ${data.size ? Math.round(data.size/1024)+' KB' : 'N/A'}</div>`;
    html += `<div class="mb-2"><strong>MD5:</strong> <code>${data.md5 || 'N/A'}</code></div>`;
    html += `<div class="mb-2"><strong>VT verdict:</strong> ${verdictChip(data.verdict)}</div>`;
  } else {
    html += `<pre>${JSON.stringify(data, null, 2)}</pre>`;
  }
  html += `</div></div>`;
  return html;
}

// Show result panel
function showResultPanel(renderHtml, rawData) {
  elt('result-card').innerHTML = renderHtml;
  elt('raw-json').textContent = JSON.stringify(rawData, null, 2);
  show(elt('raw-json'));
  show(elt('result-panel'));
}

// Report modal controls
function openReportModal(type, target, verdict) {
  // auto-fill fields, then show modal
  elt('modal-type').value = type || '';
  elt('modal-target').value = target || '';
  elt('modal-verdict').value = verdict || '';
  elt('modal-notes').value = '';
  elt('report-modal-backdrop').classList.remove('hidden');
}

function closeReportModal() {
  elt('report-modal-backdrop').classList.add('hidden');
}

// Submit report (POST /report)
async function submitReport() {
  const payload = {
    type: elt('modal-type').value || '',
    target: elt('modal-target').value || '',
    verdict: elt('modal-verdict').value || '',
    note: elt('modal-notes').value || ''
  };

  try {
    const r = await fetch('/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify(payload)
    });
    const j = await r.json();
    if (j.status === 'success') {
      alert('Report submitted');
      closeReportModal();
    } else {
      alert('Report failed: ' + (j.message || JSON.stringify(j)));
    }
  } catch (err) {
    alert('Network error submitting report');
  }
}

// Wire the "Actions -> Report" button to open modal for last result (if present)
elt('report-btn').addEventListener('click', () => {
  // grab last displayed raw JSON
  const rawText = elt('raw-json').textContent;
  if (!rawText) {
    alert('No result to report');
    return;
  }
  try {
    const data = JSON.parse(rawText);
    // choose sensible defaults
    const t = data.type || (data.domain ? 'domain' : data.ip ? 'ip' : 'file');
    const target = data.domain || data.ip || data.filename || '';
    openReportModal(t, target, data.verdict || '');
  } catch (e) {
    alert('No structured result available to report');
  }
});

// Fetch + render logic

async function scanFile(){
  const input = elt('file-input');
  const file = input.files?.[0];
  if(!file){ alert('Select a file first'); return; }

  show(elt('file-loading'));
  hide(elt('file-results'));

  const fd = new FormData();
  fd.append('file', file);

  try {
    const resp = await fetch('/scan-file', {
      method: 'POST',
      body: fd,
      headers: { 'Accept': 'application/json' } // request json response
    });

    let data;
    if (resp.ok) {
      try {
        data = await resp.json();
      } catch (e) {
        // fallback minimal
        data = { filename: file.name, size: file.size, verdict: 'Unknown', type: 'file' };
      }
      const html = renderResultsCard(data, 'file');
      elt('file-results').innerHTML = html;
      show(elt('file-results'));
      showResultPanel(html, data);
    } else {
      const txt = await resp.text();
      alert('Server error: ' + txt);
    }
  } catch (err) {
    alert('Network error while scanning file');
  } finally {
    hide(elt('file-loading'));
  }
}

async function checkDomain(){
  const domain = elt('domain-input').value.trim();
  if (!domain) { alert('Enter domain'); return; }
  show(elt('domain-loading'));
  hide(elt('domain-results'));

  try {
    const resp = await fetch('/check-domain', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ domain })
    });

    if (!resp.ok) {
      const txt = await resp.text();
      // If server returned HTML (older behavior), open it
      if (txt && txt.trim().startsWith('<')) {
        document.open(); document.write(txt); document.close();
        return;
      }
      alert('Server error: ' + txt);
      return;
    }

    const data = await resp.json();
    const html = renderResultsCard(data, 'domain');
    elt('domain-results').innerHTML = html;
    show(elt('domain-results'));
    showResultPanel(html, data);
  } catch (err) {
    alert('Network error while checking domain');
  } finally {
    hide(elt('domain-loading'));
  }
}

async function checkIP(){
  const ip = elt('ip-input').value.trim();
  if (!ip) { alert('Enter IP'); return; }
  show(elt('ip-loading'));
  hide(elt('ip-results'));

  try {
    const resp = await fetch('/check-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({ ip })
    });

    if (!resp.ok) {
      const txt = await resp.text();
      if (txt && txt.trim().startsWith('<')) {
        document.open(); document.write(txt); document.close();
        return;
      }
      alert('Server error: ' + txt);
      return;
    }

    const data = await resp.json();
    const html = renderResultsCard(data, 'ip');
    elt('ip-results').innerHTML = html;
    show(elt('ip-results'));
    showResultPanel(html, data);
  } catch (err) {
    alert('Network error while checking IP');
  } finally {
    hide(elt('ip-loading'));
  }
}

// Hook Esc key to close modal
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeReportModal();
});