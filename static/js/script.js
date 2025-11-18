// helpers
function elt(id){return document.getElementById(id)}
function show(el){ if(!el) return; el.classList.remove('hidden') }
function hide(el){ if(!el) return; el.classList.add('hidden') }

function verdictBadge(verdict){
  if(!verdict) return '<span class="chip-unknown">Unknown</span>'
  verdict = verdict.toLowerCase()
  if(verdict==='malicious') return '<span class="chip-mal">Malicious</span>'
  if(verdict==='suspicious') return '<span class="chip-susp">Suspicious</span>'
  if(verdict==='safe') return '<span class="chip-safe">Safe</span>'
  return `<span class="chip-unknown">${verdict}</span>`
}

function renderDomain(data){
  const whois = data.whois || {}
  return `
    <div>
      <h4 class="text-lg font-semibold mb-2">${data.domain}</h4>
      <div class="label">Registrar</div><div>${whois.registrar || 'N/A'}</div>
      <div class="label">Created</div><div>${Array.isArray(whois.creation_date)? whois.creation_date[0] : (whois.creation_date || 'N/A')}</div>
      <div class="label">Expiration</div><div>${whois.expiration_date || 'N/A'}</div>
      <div class="label">Country</div><div>${whois.country || 'N/A'}</div>
      <div class="label mt-3">VT verdict</div><div>${verdictBadge(data.verdict)}</div>
    </div>
  `
}

function renderIP(data){
  const ipinfo = data.ipinfo || {}
  return `
    <div>
      <h4 class="text-lg font-semibold mb-2">${data.ip}</h4>
      <div class="label">Reverse DNS</div><div>${data.rev_dns || 'N/A'}</div>
      <div class="label">ASN / Org</div><div>${ipinfo.org || 'N/A'}</div>
      <div class="label">Country</div><div>${ipinfo.country || 'N/A'}</div>
      <div class="label mt-3">VT verdict</div><div>${verdictBadge(data.verdict)}</div>
    </div>
  `
}

function renderFile(data){
  return `
    <div>
      <h4 class="text-lg font-semibold mb-2">${data.filename}</h4>
      <div class="label">Size</div><div>${data.size ? Math.round(data.size/1024)+' KB' : 'N/A'}</div>
      <div class="label">SHA256</div><div><code>${data.sha256 || 'N/A'}</code></div>
      <div class="label mt-3">VT verdict</div><div>${verdictBadge(data.verdict)}</div>
    </div>
  `
}

function showResultPanel(html, obj){
  elt('result-card').innerHTML = html
  // store last result object for report button
  window.__LAST_SAFE_SCOPE_RESULT = obj
  show(elt('result-panel'))
  // ensure report button exists
  elt('report-btn').removeEventListener?.('click', reportBtnHandler)
  elt('report-btn').addEventListener('click', reportBtnHandler)
}

function reportBtnHandler(){
  const data = window.__LAST_SAFE_SCOPE_RESULT
  if(!data){ alert('No result to report'); return }
  const t = data.type || (data.domain? 'domain' : data.ip? 'ip' : 'file')
  const target = data.domain || data.ip || data.filename || ''
  openReportModal(t, target, data.verdict || '')
}

/* Modal */
function openReportModal(type, target, verdict){
  elt('modal-type').value = type || ''
  elt('modal-target').value = target || ''
  elt('modal-verdict').value = verdict || ''
  elt('modal-notes').value = ''
  elt('report-modal-backdrop').classList.remove('hidden')
}
function closeReportModal(){ elt('report-modal-backdrop').classList.add('hidden') }

async function submitReport(){
  const payload = {
    type: elt('modal-type').value || '',
    target: elt('modal-target').value || '',
    verdict: elt('modal-verdict').value || '',
    note: elt('modal-notes').value || ''
  }
  try {
    const r = await fetch('/report', {
      method: 'POST',
      headers: {'Content-Type':'application/json', 'Accept':'application/json'},
      body: JSON.stringify(payload)
    })
    const j = await r.json()
    if(j.status==='success'){ alert('Report submitted'); closeReportModal() }
    else alert('Report failed: '+(j.message || JSON.stringify(j)))
  } catch(e){
    alert('Network error submitting report')
  }
}

/* API interactions */
async function scanFile(){
  const input = elt('file-input')
  const file = input.files?.[0]
  if(!file){ alert('Select a file first'); return }

  show(elt('file-loading'))
  hide(elt('file-results'))

  const fd = new FormData()
  fd.append('file', file)

  try {
    const resp = await fetch('/scan-file', {
      method:'POST',
      body: fd,
      headers: {'Accept':'application/json'}
    })
    if(!resp.ok){
      const txt = await resp.text()
      alert('Server error: '+txt)
      return
    }
    const data = await resp.json()
    const html = renderFile(data)
    elt('file-results').innerHTML = html
    show(elt('file-results'))
    showResultPanel(html, data)
  } catch(e){
    alert('Network error while scanning file')
  } finally {
    hide(elt('file-loading'))
  }
}

async function checkDomain(){
  const domain = elt('domain-input').value.trim()
  if(!domain){ alert('Enter domain'); return }
  show(elt('domain-loading'))
  hide(elt('domain-results'))

  try {
    const resp = await fetch('/check-domain', {
      method:'POST',
      headers:{'Content-Type':'application/json','Accept':'application/json'},
      body: JSON.stringify({domain})
    })
    if(!resp.ok){
      const txt = await resp.text()
      alert('Server error: '+txt)
      return
    }
    const data = await resp.json()
    const html = renderDomain(data)
    elt('domain-results').innerHTML = html
    show(elt('domain-results'))
    showResultPanel(html, data)
  } catch(e){
    alert('Network error while checking domain')
  } finally {
    hide(elt('domain-loading'))
  }
}

async function checkIP(){
  const ip = elt('ip-input').value.trim()
  if(!ip){ alert('Enter IP'); return }
  show(elt('ip-loading'))
  hide(elt('ip-results'))

  try {
    const resp = await fetch('/check-ip', {
      method:'POST',
      headers:{'Content-Type':'application/json','Accept':'application/json'},
      body: JSON.stringify({ip})
    })
    if(!resp.ok){
      const txt = await resp.text()
      alert('Server error: '+txt)
      return
    }
    const data = await resp.json()
    const html = renderIP(data)
    elt('ip-results').innerHTML = html
    show(elt('ip-results'))
    showResultPanel(html, data)
  } catch(e){
    alert('Network error while checking IP')
  } finally {
    hide(elt('ip-loading'))
  }
}

/* hook escape to close modal */
document.addEventListener('keydown', (e)=>{ if(e.key==='Escape') closeReportModal() })