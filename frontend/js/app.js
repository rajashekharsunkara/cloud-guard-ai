"use strict";

const API = window.location.origin + "/api";

const $ = (id) => document.getElementById(id);

const session = { scans: 0, vulns: 0, patches: 0, ragMatches: 0 };

/* ---------- Utilities ---------- */

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = text == null ? "" : String(text);
  return div.innerHTML;
}

function icon(name, cls = "icon") {
  return `<svg class="${cls}"><use href="#i-${name}"/></svg>`;
}

function relativeTime(iso) {
  if (!iso) return "";
  const then = new Date(iso.endsWith("Z") || iso.includes("+") ? iso : iso + "Z");
  const s = Math.round((Date.now() - then.getTime()) / 1000);
  if (Number.isNaN(s)) return "";
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  if (s < 604800) return `${Math.floor(s / 86400)}d ago`;
  return then.toLocaleDateString();
}

function severityClass(sev) {
  const s = (sev || "low").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(s) ? s : "low";
}

/* ---------- Toasts ---------- */

function toast(message, kind = "info", timeout = 4500) {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  const glyph = kind === "ok" ? "check" : kind === "error" ? "alert" : "info";
  el.innerHTML = `${icon(glyph)}<span>${escapeHtml(message)}</span>`;
  $("toasts").appendChild(el);
  setTimeout(() => {
    el.classList.add("leaving");
    el.addEventListener("animationend", () => el.remove(), { once: true });
  }, timeout);
}

/* ---------- Theme ---------- */

function applyTheme(dark) {
  if (dark) document.documentElement.setAttribute("data-theme", "dark");
  else document.documentElement.removeAttribute("data-theme");
  $("theme-label").textContent = dark ? "Light mode" : "Dark mode";
}

$("theme-toggle").addEventListener("click", () => {
  const dark = !document.documentElement.hasAttribute("data-theme");
  localStorage.setItem("cg-theme", dark ? "dark" : "light");
  applyTheme(dark);
});

applyTheme(document.documentElement.getAttribute("data-theme") === "dark");

/* ---------- Navigation ---------- */

const historyState = { loaded: false };

function openTab(name) {
  document.querySelectorAll(".nav-item").forEach((n) => {
    n.classList.toggle("active", n.dataset.tab === name);
    if (n.dataset.tab === name) {
      $("topbar-title").textContent = n.dataset.title;
    }
  });
  document.querySelectorAll(".page").forEach((p) => {
    p.classList.toggle("active", p.id === "page-" + name);
  });
  closeNav();
  if (name === "history" && !historyState.loaded) loadHistory();
}

document.querySelectorAll(".nav-item[data-tab]").forEach((item) => {
  item.title = item.dataset.title;
  item.addEventListener("click", () => openTab(item.dataset.tab));
});

function closeNav() {
  document.body.classList.remove("nav-open");
}

$("menu-btn").addEventListener("click", () => {
  document.body.classList.toggle("nav-open");
});

$("scrim").addEventListener("click", closeNav);

function applySidebar(rail) {
  if (rail) document.documentElement.setAttribute("data-sidebar", "rail");
  else document.documentElement.removeAttribute("data-sidebar");
  $("sidebar-toggle").setAttribute("aria-label", rail ? "Expand sidebar" : "Collapse sidebar");
}

$("sidebar-toggle").addEventListener("click", () => {
  const rail = !document.documentElement.hasAttribute("data-sidebar");
  localStorage.setItem("cg-sidebar", rail ? "rail" : "full");
  applySidebar(rail);
});

applySidebar(document.documentElement.getAttribute("data-sidebar") === "rail");

/* ---------- Health ---------- */

function setStatus(dotId, txtId, ok, label) {
  $(dotId).className = "status-dot " + (ok ? "online" : "offline");
  $(txtId).textContent = label;
}

async function checkHealth() {
  try {
    const res = await fetch(`${API}/health`);
    const data = await res.json();
    setStatus("dot-api", "txt-api", true, "Online");
    setStatus("dot-db", "txt-db", data.database === "connected",
      data.database === "connected" ? "Online" : "Offline");
    setStatus("dot-s3", "txt-s3", data.s3 === "connected",
      data.s3 === "connected" ? "Online" : "Offline");
  } catch {
    setStatus("dot-api", "txt-api", false, "Offline");
    setStatus("dot-db", "txt-db", false, "Unknown");
    setStatus("dot-s3", "txt-s3", false, "Unknown");
  }
}

/* ---------- Dashboard ---------- */

function updateMetrics() {
  $("m-scans").textContent = session.scans;
  $("m-vulns").textContent = session.vulns;
  $("m-patches").textContent = session.patches;
  $("m-rag").textContent = session.ragMatches;
}

async function loadRecentActivity() {
  const container = $("recent-activity");
  try {
    const res = await fetch(`${API}/history`);
    if (!res.ok) throw new Error();
    const rows = await res.json();

    if (rows.length === 0) {
      container.innerHTML = `
        <div class="empty">
          ${icon("inbox")}
          <h3>Nothing here yet</h3>
          <p>Run a scan and its findings will show up here.</p>
        </div>`;
      $("activity-meta").textContent = "";
      return;
    }

    $("activity-meta").textContent = `Last ${Math.min(rows.length, 8)} findings`;
    container.innerHTML = `
      <div class="activity-list">
        ${rows.slice(0, 8).map((r) => `
          <div class="activity">
            <div class="activity-icon">${icon("alert")}</div>
            <div class="activity-body">
              <div class="activity-title">${escapeHtml(r.vulnerability_type)}</div>
              <div class="activity-sub">${escapeHtml(r.file_name)} · <span class="badge ${severityClass(r.severity)}">${escapeHtml(r.severity)}</span></div>
            </div>
            <span class="activity-time">${relativeTime(r.created_at)}</span>
          </div>`).join("")}
      </div>`;
  } catch {
    container.innerHTML = `
      <div class="empty">
        ${icon("alert")}
        <h3>Couldn't load activity</h3>
        <p>The API isn't reachable right now.</p>
      </div>`;
  }
}

$("btn-refresh-dash").addEventListener("click", () => {
  checkHealth();
  loadRecentActivity();
});

/* ---------- Scanner ---------- */

const SAMPLE_TF = `resource "aws_s3_bucket" "data_lake" {
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

$("btn-sample").addEventListener("click", () => {
  $("iac-input").value = SAMPLE_TF;
  $("iac-input").focus();
});

function readScanInput() {
  const iacContent = $("iac-input").value.trim();
  const fileName = $("file-name-input").value.trim() || "main.tf";
  if (iacContent.length < 10) {
    toast("Paste a configuration first — at least 10 characters.", "error");
    return null;
  }
  return { iacContent, fileName };
}

function setBusy(btn, busy, label) {
  btn.disabled = busy;
  btn.innerHTML = busy
    ? `<span class="spinner sm"></span>${escapeHtml(label)}`
    : btn.dataset.idle;
}

// Remember idle button markup so setBusy can restore it.
["btn-scan", "btn-scan-stream", "btn-diagram-audit"].forEach((id) => {
  $(id).dataset.idle = $(id).innerHTML;
});

function recordScan(result) {
  session.scans++;
  session.vulns += (result.vulnerabilities || []).length;
  if (result.patched_code) session.patches++;
  if ((result.similar_past_audits || []).length > 0) session.ragMatches++;
  updateMetrics();
  loadRecentActivity();
}

$("btn-scan").addEventListener("click", async () => {
  const input = readScanInput();
  if (!input) return;

  const btn = $("btn-scan");
  setBusy(btn, true, "Scanning…");
  $("scan-results").hidden = true;
  $("pipeline-panel").hidden = true;

  try {
    const res = await fetch(`${API}/audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ iac_content: input.iacContent, file_name: input.fileName }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(typeof err.detail === "string" ? err.detail : "Audit failed");
    }

    const result = await res.json();
    displayResults(result, input.iacContent);
    recordScan(result);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    setBusy(btn, false);
  }
});

/* ---------- Streaming scan ---------- */

const STEP_LABELS = {
  security_scan: "Security scan",
  rag_retrieval: "Historical patch lookup",
  patch_generation: "Patch generation",
  scoring: "Scoring",
  storage: "Persistence",
};

function renderStep(stepId, status, note) {
  const container = $("pipeline-steps");
  let row = container.querySelector(`[data-step="${stepId}"]`);
  if (!row) {
    row = document.createElement("div");
    row.dataset.step = stepId;
    row.innerHTML = `
      <div class="step-dot">${icon(status === "error" ? "x" : "check")}</div>
      <div>
        <div class="step-msg">${escapeHtml(STEP_LABELS[stepId] || stepId)}</div>
        <div class="step-note"></div>
      </div>`;
    container.appendChild(row);
  }
  row.className = `step ${status}`;
  if (note) row.querySelector(".step-note").textContent = note;
}

$("btn-scan-stream").addEventListener("click", async () => {
  const input = readScanInput();
  if (!input) return;

  const btn = $("btn-scan-stream");
  setBusy(btn, true, "Running…");
  $("pipeline-panel").hidden = false;
  $("pipeline-steps").innerHTML = "";
  $("scan-results").hidden = true;

  try {
    const res = await fetch(`${API}/audit/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ iac_content: input.iacContent, file_name: input.fileName }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(typeof err.detail === "string" ? err.detail : "Audit failed");
    }

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split("\n");
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.startsWith("data: ")) continue;
        let event;
        try {
          event = JSON.parse(line.slice(6));
        } catch {
          continue;
        }

        if (event.step === "error") {
          renderStep("error", "error", event.message);
          toast(event.message || "The audit failed.", "error");
        } else if (event.step === "done" && event.data) {
          displayResults(event.data, input.iacContent);
          recordScan(event.data);
        } else if (STEP_LABELS[event.step]) {
          renderStep(event.step, event.status === "complete" ? "complete" : "running",
            event.message);
        }
      }
    }
  } catch (err) {
    toast("Connection lost: " + err.message, "error");
  } finally {
    setBusy(btn, false);
  }
});

/* ---------- Results ---------- */

function displayResults(result, originalCode) {
  $("scan-results").hidden = false;

  const score = result.security_score || 0;
  const circumference = 2 * Math.PI * 52;
  const circle = $("score-circle");
  circle.style.strokeDashoffset = circumference - (score / 100) * circumference;

  const tone = score >= 80 ? "var(--ok)" : score >= 50 ? "var(--warn)" : "var(--danger)";
  circle.style.stroke = tone;
  $("score-display").textContent = score;
  $("score-display").style.color = tone;

  const vulns = result.vulnerabilities || [];
  $("score-headline").textContent =
    score >= 80 ? "Looking solid" : score >= 50 ? "Needs attention" : "High risk";
  $("score-note").textContent =
    vulns.length === 0
      ? "No issues were identified in this configuration."
      : `${vulns.length} issue${vulns.length === 1 ? "" : "s"} found. Review the findings below and apply the suggested patch.`;

  const tally = {};
  vulns.forEach((v) => {
    const s = severityClass(v.severity);
    tally[s] = (tally[s] || 0) + 1;
  });
  $("severity-tally").innerHTML = ["critical", "high", "medium", "low"]
    .filter((s) => tally[s])
    .map((s) => `<span class="badge ${s}">${tally[s]} ${s}</span>`)
    .join("");

  $("vuln-count").textContent = vulns.length ? `${vulns.length} found` : "";

  $("vuln-list").innerHTML = vulns.length === 0
    ? `<div class="empty">
        ${icon("check")}
        <h3>No findings</h3>
        <p>This configuration passed all checks.</p>
      </div>`
    : vulns.map((v) => `
      <div class="finding">
        <span class="badge ${severityClass(v.severity)}">${escapeHtml(v.severity || "LOW")}</span>
        <div class="finding-body">
          <h4>${escapeHtml(v.title || "Untitled finding")}</h4>
          <p>${escapeHtml(v.description || "")}</p>
          ${v.resource ? `<div class="finding-resource">${escapeHtml(v.resource)}</div>` : ""}
          ${v.remediation ? `<div class="finding-fix">${icon("check")}<span>${escapeHtml(v.remediation)}</span></div>` : ""}
        </div>
      </div>`).join("");

  $("code-original").textContent = originalCode || "";
  $("code-patched").textContent = result.patched_code || "No patch was needed.";

  $("scan-results").scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ---------- Diagram check ---------- */

let diagramFile = null;
const MAX_DIAGRAM_BYTES = 8 * 1024 * 1024;

function acceptDiagram(file) {
  if (!file) return;
  if (!file.type.startsWith("image/")) {
    toast("That file isn't an image.", "error");
    return;
  }
  if (file.size > MAX_DIAGRAM_BYTES) {
    toast("Diagrams are limited to 8 MB.", "error");
    return;
  }
  diagramFile = file;
  const reader = new FileReader();
  reader.onload = (e) => {
    $("diagram-preview-img").src = e.target.result;
    $("diagram-preview").hidden = false;
  };
  reader.readAsDataURL(file);
  $("btn-diagram-audit").disabled = false;
}

$("diagram-file-input").addEventListener("change", (e) => acceptDiagram(e.target.files[0]));

const dropzone = $("diagram-dropzone");

dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("dragover");
});

dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));

dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  acceptDiagram(e.dataTransfer.files[0]);
});

$("btn-diagram-audit").addEventListener("click", async () => {
  const iacContent = $("diagram-iac-input").value.trim();
  if (iacContent.length < 10) {
    toast("Paste the Terraform configuration first.", "error");
    return;
  }
  if (!diagramFile) {
    toast("Choose an architecture diagram to compare against.", "error");
    return;
  }

  const btn = $("btn-diagram-audit");
  setBusy(btn, true, "Comparing…");

  const formData = new FormData();
  formData.append("iac_content", iacContent);
  formData.append("file_name", "main.tf");
  formData.append("diagram", diagramFile);

  try {
    const res = await fetch(`${API}/audit/diagram`, { method: "POST", body: formData });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(typeof err.detail === "string" ? err.detail : "Comparison failed");
    }

    const result = await res.json();
    $("diagram-analysis-content").textContent =
      result.diagram_analysis || "No analysis was returned.";
    $("diagram-results").hidden = false;
    $("diagram-results").scrollIntoView({ behavior: "smooth", block: "start" });

    recordScan(result);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    setBusy(btn, false);
  }
});

/* ---------- Search ---------- */

async function runSearch() {
  const query = $("search-input").value.trim();
  if (query.length < 3) {
    toast("Type at least three characters to search.", "info");
    return;
  }

  const container = $("search-results");
  container.innerHTML = `<div class="loading"><div class="spinner"></div>Searching…</div>`;

  try {
    const res = await fetch(`${API}/search`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, limit: 10 }),
    });

    if (!res.ok) throw new Error("Search failed");
    const data = await res.json();

    if (data.results.length === 0) {
      container.innerHTML = `
        <div class="empty">
          ${icon("search")}
          <h3>No matches</h3>
          <p>Try different wording, or run more scans to build up history.</p>
        </div>`;
      return;
    }

    container.innerHTML = `
      <div class="result-list">
        ${data.results.map((r) => `
          <div class="result">
            <div class="result-head">
              <span class="result-title">${escapeHtml(r.vulnerability_type)}</span>
              <span class="badge neutral">${(r.similarity_score * 100).toFixed(0)}% match</span>
            </div>
            <p>${escapeHtml(r.description)}</p>
            <div class="result-meta">${escapeHtml(r.file_name)} · ${escapeHtml(r.audit_id)}</div>
          </div>`).join("")}
      </div>`;
  } catch (err) {
    container.innerHTML = `
      <div class="empty">
        ${icon("alert")}
        <h3>Search unavailable</h3>
        <p>${escapeHtml(err.message)}</p>
      </div>`;
  }
}

$("btn-search").addEventListener("click", runSearch);
$("search-input").addEventListener("keydown", (e) => {
  if (e.key === "Enter") runSearch();
});

/* ---------- History ---------- */

async function loadHistory() {
  const container = $("history-list");
  container.innerHTML = `<div class="loading"><div class="spinner"></div></div>`;

  try {
    const res = await fetch(`${API}/history`);
    if (!res.ok) throw new Error("Failed to load history");
    const rows = await res.json();
    historyState.loaded = true;

    if (rows.length === 0) {
      container.innerHTML = `
        <div class="empty">
          ${icon("inbox")}
          <h3>No history yet</h3>
          <p>Findings from your scans will accumulate here.</p>
        </div>`;
      return;
    }

    container.innerHTML = `
      <div class="finding-list">
        ${rows.map((item) => `
          <div class="finding">
            <span class="badge ${severityClass(item.severity)}">${escapeHtml(item.severity || "LOW")}</span>
            <div class="finding-body">
              <h4>${escapeHtml(item.vulnerability_type || "Unknown")}</h4>
              <p>${escapeHtml(item.description || "")}</p>
              <div class="finding-when">
                ${escapeHtml(item.file_name)} · ${escapeHtml(item.audit_id)}
                ${item.created_at ? ` · ${relativeTime(item.created_at)}` : ""}
              </div>
            </div>
          </div>`).join("")}
      </div>`;
  } catch (err) {
    container.innerHTML = `
      <div class="empty">
        ${icon("alert")}
        <h3>Couldn't reach the API</h3>
        <p>${escapeHtml(err.message)}</p>
      </div>`;
  }
}

$("btn-refresh-history").addEventListener("click", loadHistory);

/* ---------- Init ---------- */

checkHealth();
loadRecentActivity();
setInterval(checkHealth, 60000);
