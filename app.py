<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>SafeScope — Threat Intelligence Dashboard</title>

  <!-- Tailwind CDN (optional for utilities used in markup) -->
  <script src="https://cdn.tailwindcss.com"></script>

  <link href="https://cdn.jsdelivr.net/npm/remixicon@4.2.0/fonts/remixicon.css" rel="stylesheet">
  <link rel="stylesheet" href="/static/css/style.css">
</head>

<body class="min-h-screen flex flex-col">

  <!-- Header -->
  <header class="fixed top-0 left-0 right-0 h-16 glass z-50 flex items-center justify-between px-6">
    <div class="flex items-center gap-3">
      <i class="ri-shield-fill text-2xl" style="color:var(--accent)"></i>
      <div>
        <div class="text-lg font-semibold">SafeScope</div>
        <div class="text-xs text-[var(--muted)]">Threat Intelligence Dashboard</div>
      </div>
    </div>
  </header>

  <!-- Hero -->
  <section class="pt-20 pb-12 relative overflow-hidden">
    <div class="max-w-5xl mx-auto text-center px-4">
      <h1 class="text-4xl md:text-5xl font-extrabold mb-2">Threat Intelligence Dashboard</h1>
      <p class="text-md text-[var(--muted)]">VirusTotal · WHOIS · DNS · IP Intelligence</p>
    </div>
  </section>

  <!-- Main -->
  <main class="flex-1 -mt-6 px-4 md:px-8 lg:px-12">
    <div class="max-w-6xl mx-auto">
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">

        <!-- File Scan -->
        <div class="glass rounded-xl p-6 card-shadow">
          <div class="flex items-center mb-4">
            <i class="ri-file-shield-2-line text-3xl" style="color:var(--accent)"></i>
            <h3 class="ml-3 text-lg font-semibold">File Scan</h3>
          </div>

          <form id="file-form" onsubmit="event.preventDefault(); scanFile();">
            <input type="file" id="file-input" class="mb-3 w-full" />
            <button id="file-scan-btn" class="btn-accent w-full py-2 rounded-md" type="button" onclick="scanFile()">Scan File</button>
          </form>

          <div id="file-loading" class="hidden mt-4 flex items-center gap-3">
            <div class="w-9 h-9 border-4 border-[rgba(108,99,255,0.25)] border-t-[var(--accent)] rounded-full animate-spin"></div>
            <div class="text-sm text-[var(--muted)]">Processing request...</div>
          </div>

          <div id="file-results" class="mt-4 hidden"></div>
        </div>

        <!-- Domain Check -->
        <div class="glass rounded-xl p-6 card-shadow">
          <div class="flex items-center mb-4">
            <i class="ri-global-line text-3xl" style="color:var(--accent)"></i>
            <h3 class="ml-3 text-lg font-semibold">Domain Check</h3>
          </div>

          <div>
            <input id="domain-input" type="text" placeholder="example.com" class="mb-3 w-full p-3 rounded-md" />
            <button id="domain-check-btn" class="btn-accent w-full py-2 rounded-md" onclick="checkDomain()">Check Domain</button>
          </div>

          <div id="domain-loading" class="hidden mt-4 flex items-center gap-3">
            <div class="w-9 h-9 border-4 border-[rgba(108,99,255,0.25)] border-t-[var(--accent)] rounded-full animate-spin"></div>
            <div class="text-sm text-[var(--muted)]">Processing request...</div>
          </div>

          <div id="domain-results" class="mt-4 hidden"></div>
        </div>

        <!-- IP Check -->
        <div class="glass rounded-xl p-6 card-shadow">
          <div class="flex items-center mb-4">
            <i class="ri-map-pin-line text-3xl" style="color:var(--accent)"></i>
            <h3 class="ml-3 text-lg font-semibold">IP Check</h3>
          </div>

          <div>
            <input id="ip-input" type="text" placeholder="8.8.8.8" class="mb-3 w-full p-3 rounded-md" />
            <button id="ip-check-btn" class="btn-accent w-full py-2 rounded-md" onclick="checkIP()">Check IP</button>
          </div>

          <div id="ip-loading" class="hidden mt-4 flex items-center gap-3">
            <div class="w-9 h-9 border-4 border-[rgba(108,99,255,0.25)] border-t-[var(--accent)] rounded-full animate-spin"></div>
            <div class="text-sm text-[var(--muted)]">Processing request...</div>
          </div>

          <div id="ip-results" class="mt-4 hidden"></div>
        </div>

      </div>

      <!-- Result Panel -->
      <div id="result-panel" class="mt-8 hidden">
        <div class="flex justify-between items-start gap-4">
          <div class="flex-1">
            <div id="result-card" class="glass rounded-xl p-5 card-shadow"></div>
          </div>
          <div class="w-64">
            <div class="glass rounded-xl p-4">
              <h4 class="text-sm font-semibold mb-2">Actions</h4>
              <button id="report-btn" class="w-full py-2 rounded-md btn-accent mb-2">Report</button>
              <a href="/" class="block text-center py-2 rounded-md border">Back to Dashboard</a>
            </div>
          </div>
        </div>

        <div class="mt-6">
          <h5 class="text-sm font-semibold mb-2">Raw (for debugging only)</h5>
          <pre id="raw-json" class="json-pre hidden"></pre>
        </div>
      </div>

      <footer class="mt-12 text-center text-sm text-[var(--muted)]">
        <p>© 2025 SafeScope — Security Intelligence Toolkit</p>
      </footer>
    </div>
  </main>

  <!-- REPORT MODAL -->
  <div id="report-modal-backdrop" class="fixed inset-0 hidden items-center justify-center z-60">
    <div class="modal-backdrop absolute inset-0"></div>
    <div class="relative z-70 w-full max-w-lg mx-auto">
      <div class="glass rounded-xl p-6">
        <div class="flex justify-between items-center mb-4">
          <h3 class="text-lg font-semibold">Submit Report</h3>
          <button onclick="closeReportModal()" class="text-xl">✕</button>
        </div>
        <div class="space-y-3">
          <label class="text-sm">Report Type</label>
          <input id="modal-type" class="w-full p-2 rounded-md" />

          <label class="text-sm">Target</label>
          <input id="modal-target" class="w-full p-2 rounded-md" />

          <label class="text-sm">Verdict</label>
          <input id="modal-verdict" class="w-full p-2 rounded-md" />

          <label class="text-sm">Notes (optional)</label>
          <textarea id="modal-notes" class="w-full p-2 rounded-md" rows="3"></textarea>

          <div class="flex gap-2">
            <button class="btn-accent w-full py-2 rounded-md" onclick="submitReport()">Send</button>
            <button class="w-full py-2 rounded-md border" onclick="closeReportModal()">Cancel</button>
          </div>
        </div>
      </div>
    </div>
  </div>

  <script src="/static/js/script.js"></script>
</body>
</html>