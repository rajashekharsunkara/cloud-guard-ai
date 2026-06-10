const API_BASE = window.location.origin + '/api';

const metrics = { scans: 0, vulns: 0, patches: 0, ragRetrievals: 0 };

// Tab navigation

document.querySelectorAll('.nav-item[data-tab]').forEach((item) => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach((n) => n.classList.remove('active'));
    item.classList.add('active');

    const tabId = 'tab-' + item.dataset.tab;
    document.querySelectorAll('.tab-view').forEach((t) => t.classList.remove('active'));
    const target = document.getElementById(tabId);
    if (target) target.classList.add('active');
  });
});

// Health check

async function checkHealth() {
  const apiDot = document.getElementById('status-api');
  const apiText = document.getElementById('status-api-text');
  const dbDot = document.getElementById('status-db');
  const dbText = document.getElementById('status-db-text');
  const s3Dot = document.getElementById('status-s3');
  const s3Text = document.getElementById('status-s3-text');

  try {
    const res = await fetch(`${API_BASE}/health`);
    const data = await res.json();

    apiDot.className = 'status-dot online';
    apiText.textContent = 'Online';

    dbDot.className = data.database === 'connected' ? 'status-dot online' : 'status-dot offline';
    dbText.textContent = data.database === 'connected' ? 'Online' : 'Offline';

    s3Dot.className = data.s3 === 'connected' ? 'status-dot online' : 'status-dot offline';
    s3Text.textContent = data.s3 === 'connected' ? 'Online' : 'Offline';
  } catch (err) {
    apiDot.className = 'status-dot offline';
    apiText.textContent = 'Offline';
    dbDot.className = 'status-dot offline';
    dbText.textContent = 'Unknown';
    s3Dot.className = 'status-dot offline';
    s3Text.textContent = 'Unknown';
  }
}

checkHealth();

// Sample terraform

function loadSampleTerraform() {
  document.getElementById('iac-input').value = `resource "aws_s3_bucket" "data_lake" {
  bucket = "company-data-lake-prod"
  acl    = "public-read-write"
}

resource "aws_db_instance" "production_db" {
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  username             = "admin"
  password             = "SuperSecret123!"
  publicly_accessible  = true
  skip_final_snapshot  = true
  storage_encrypted    = false
}

resource "aws_security_group" "web_sg" {
  name = "web-server-sg"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.large"

  vpc_security_group_ids = [aws_security_group.web_sg.id]

  tags = {
    Name = "production-web"
  }
}`;
}

// Standard audit

async function startScan() {
  const iacContent = document.getElementById('iac-input').value.trim();
  const fileName = document.getElementById('file-name-input').value.trim() || 'main.tf';

  if (!iacContent || iacContent.length < 10) {
    alert('Please paste a valid IaC configuration (at least 10 characters).');
    return;
  }

  const btn = document.getElementById('btn-scan');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin:0;"></span> Scanning...';

  document.getElementById('scan-results').style.display = 'none';
  document.getElementById('sse-timeline-panel').style.display = 'none';

  try {
    const res = await fetch(`${API_BASE}/audit`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iac_content: iacContent, file_name: fileName }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Audit failed');
    }

    const result = await res.json();
    displayResults(result, iacContent);

    metrics.scans++;
    metrics.vulns += result.vulnerabilities.length;
    if (result.patched_code) metrics.patches++;
    if (result.similar_past_audits && result.similar_past_audits.length > 0) metrics.ragRetrievals++;
    updateMetrics();
  } catch (err) {
    alert('Error: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Run Audit';
  }
}

// SSE streaming audit

async function startStreamScan() {
  const iacContent = document.getElementById('iac-input').value.trim();
  const fileName = document.getElementById('file-name-input').value.trim() || 'main.tf';

  if (!iacContent || iacContent.length < 10) {
    alert('Please paste a valid IaC configuration (at least 10 characters).');
    return;
  }

  const btn = document.getElementById('btn-scan-stream');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin:0;"></span> Streaming...';

  const timelinePanel = document.getElementById('sse-timeline-panel');
  const timeline = document.getElementById('sse-timeline');
  timelinePanel.style.display = 'block';
  timeline.innerHTML = '';
  document.getElementById('scan-results').style.display = 'none';

  try {
    const res = await fetch(`${API_BASE}/audit/stream`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ iac_content: iacContent, file_name: fileName }),
    });

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const event = JSON.parse(line.slice(6));
            addTimelineItem(timeline, event);

            if (event.step === 'done' && event.data) {
              displayResults(event.data, iacContent);
              metrics.scans++;
              metrics.vulns += (event.data.vulnerabilities || []).length;
              if (event.data.patched_code) metrics.patches++;
              updateMetrics();
            }
          } catch (e) {
            // skip malformed events
          }
        }
      }
    }
  } catch (err) {
    addTimelineItem(timeline, {
      step: 'error',
      status: 'error',
      message: 'Connection error: ' + err.message,
    });
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Stream (SSE)';
  }
}

function addTimelineItem(container, event) {
  const item = document.createElement('div');
  item.className = `timeline-item ${event.status === 'complete' ? 'complete' : 'running'}`;

  const time = new Date().toLocaleTimeString();
  item.innerHTML = `
    <div class="timeline-message">${event.message || event.step}</div>
    <div class="timeline-time">${time}</div>
  `;

  container.appendChild(item);
  container.scrollTop = container.scrollHeight;
}

// Display results

function displayResults(result, originalCode) {
  const resultsDiv = document.getElementById('scan-results');
  resultsDiv.style.display = 'block';

  const score = result.security_score || 0;
  const circle = document.getElementById('score-circle');
  const circumference = 2 * Math.PI * 52;
  const offset = circumference - (score / 100) * circumference;
  circle.style.strokeDashoffset = offset;

  let color;
  if (score >= 80) color = 'var(--green)';
  else if (score >= 50) color = 'var(--amber)';
  else color = 'var(--red)';
  circle.style.stroke = color;

  document.getElementById('score-display').textContent = score;
  document.getElementById('score-display').style.color = color;

  const vulnList = document.getElementById('vuln-list');
  const vulns = result.vulnerabilities || [];
  document.getElementById('vuln-count').textContent = `${vulns.length} found`;

  if (vulns.length === 0) {
    vulnList.innerHTML = `
      <div class="empty-state" style="padding: 28px;">
        <h3>No vulnerabilities detected</h3>
        <p>Your configuration looks secure.</p>
      </div>`;
  } else {
    vulnList.innerHTML = vulns
      .map(
        (v) => `
      <div class="vuln-item">
        <span class="severity-badge ${(v.severity || 'low').toLowerCase()}">${v.severity || 'LOW'}</span>
        <div class="vuln-details">
          <h4>${escapeHtml(v.title || 'Unnamed')}</h4>
          <p>${escapeHtml(v.description || '')}</p>
          ${v.resource ? `<div class="vuln-resource">${escapeHtml(v.resource)}</div>` : ''}
          ${v.remediation ? `<p style="color: var(--green); margin-top: 5px; font-size: 0.75rem;">${escapeHtml(v.remediation)}</p>` : ''}
        </div>
      </div>`
      )
      .join('');
  }

  document.getElementById('code-original').textContent = originalCode || '';
  document.getElementById('code-patched').textContent = result.patched_code || '// No patches generated';

  resultsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Diagram audit

let selectedDiagramFile = null;

const diagramInput = document.getElementById('diagram-file-input');
const diagramZone = document.getElementById('diagram-upload-zone');

if (diagramInput) {
  diagramInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      selectedDiagramFile = file;
      showDiagramPreview(file);
      document.getElementById('btn-diagram-audit').disabled = false;
    }
  });
}

if (diagramZone) {
  diagramZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    diagramZone.classList.add('dragover');
  });

  diagramZone.addEventListener('dragleave', () => {
    diagramZone.classList.remove('dragover');
  });

  diagramZone.addEventListener('drop', (e) => {
    e.preventDefault();
    diagramZone.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file && file.type.startsWith('image/')) {
      selectedDiagramFile = file;
      showDiagramPreview(file);
      document.getElementById('btn-diagram-audit').disabled = false;
    }
  });
}

function showDiagramPreview(file) {
  const preview = document.getElementById('diagram-preview');
  const img = document.getElementById('diagram-preview-img');
  const reader = new FileReader();
  reader.onload = (e) => {
    img.src = e.target.result;
    preview.style.display = 'block';
  };
  reader.readAsDataURL(file);
}

async function startDiagramAudit() {
  const iacContent = document.getElementById('diagram-iac-input').value.trim();
  if (!iacContent) {
    alert('Please paste your Terraform configuration.');
    return;
  }
  if (!selectedDiagramFile) {
    alert('Please upload an architecture diagram.');
    return;
  }

  const btn = document.getElementById('btn-diagram-audit');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner" style="width:14px;height:14px;border-width:2px;margin:0;"></span> Analyzing...';

  const formData = new FormData();
  formData.append('iac_content', iacContent);
  formData.append('file_name', 'main.tf');
  formData.append('diagram', selectedDiagramFile);

  try {
    const res = await fetch(`${API_BASE}/audit/diagram`, {
      method: 'POST',
      body: formData,
    });

    if (!res.ok) throw new Error('Diagram audit failed');

    const result = await res.json();
    const resultsDiv = document.getElementById('diagram-results');
    document.getElementById('diagram-analysis-content').textContent =
      result.diagram_analysis || 'No analysis available.';
    resultsDiv.style.display = 'block';

    metrics.scans++;
    updateMetrics();
  } catch (err) {
    alert('Error: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Validate Diagram';
  }
}

// Semantic search

async function semanticSearch() {
  const query = document.getElementById('search-input').value.trim();
  if (!query) return;

  const container = document.getElementById('search-results-container');
  container.innerHTML = '<div class="spinner"></div><p class="loading-text">Searching...</p>';

  try {
    const res = await fetch(`${API_BASE}/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, limit: 10 }),
    });

    if (!res.ok) throw new Error('Search failed');

    const data = await res.json();

    if (data.results.length === 0) {
      container.innerHTML = `
        <div class="empty-state" style="padding: 28px;">
          <h3>No matching results</h3>
          <p>Try a different query or run more scans first.</p>
        </div>`;
      return;
    }

    container.innerHTML = `
      <div class="search-results">
        ${data.results
          .map(
            (r) => `
          <div class="search-result-item">
            <div class="result-header">
              <span class="result-type">${escapeHtml(r.vulnerability_type)}</span>
              <span class="similarity-badge">${(r.similarity_score * 100).toFixed(1)}% match</span>
            </div>
            <p class="result-desc">${escapeHtml(r.description)}</p>
            <div style="margin-top: 6px; font-size: 0.68rem; color: var(--text-muted);">
              ${escapeHtml(r.file_name)} · ${r.audit_id}
            </div>
          </div>`
          )
          .join('')}
      </div>`;
  } catch (err) {
    container.innerHTML = `
      <div class="empty-state" style="padding: 28px;">
        <h3>Search error</h3>
        <p>${escapeHtml(err.message)}</p>
      </div>`;
  }
}

const searchInput = document.getElementById('search-input');
if (searchInput) {
  searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') semanticSearch();
  });
}

// Audit history

async function loadHistory() {
  const container = document.getElementById('history-list');
  container.innerHTML = '<div class="spinner"></div>';

  try {
    const res = await fetch(`${API_BASE}/history`);
    if (!res.ok) throw new Error('Failed to load history');

    const data = await res.json();

    if (data.length === 0) {
      container.innerHTML = `
        <div class="empty-state">
          <h3>No audit history</h3>
          <p>Run your first scan to see results here.</p>
        </div>`;
      return;
    }

    container.innerHTML = `
      <div class="vuln-list">
        ${data
          .map(
            (item) => `
          <div class="vuln-item">
            <span class="severity-badge ${(item.severity || 'low').toLowerCase()}">${item.severity || 'LOW'}</span>
            <div class="vuln-details">
              <h4>${escapeHtml(item.vulnerability_type || 'Unknown')}</h4>
              <p>${escapeHtml(item.description || '')}</p>
              <div style="margin-top: 5px; font-size: 0.68rem; color: var(--text-muted);">
                ${escapeHtml(item.file_name)} · ${item.audit_id}
                ${item.created_at ? ` · ${new Date(item.created_at).toLocaleString()}` : ''}
              </div>
            </div>
          </div>`
          )
          .join('')}
      </div>`;
  } catch (err) {
    container.innerHTML = `
      <div class="empty-state">
        <h3>Connection Error</h3>
        <p>${escapeHtml(err.message)}. Make sure the backend is running.</p>
      </div>`;
  }
}

// Metrics update

function updateMetrics() {
  document.getElementById('metric-scans').textContent = metrics.scans;
  document.getElementById('metric-vulns').textContent = metrics.vulns;
  document.getElementById('metric-patches').textContent = metrics.patches;
  document.getElementById('metric-rag').textContent = metrics.ragRetrievals;
}

// Utilities

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}
