"use strict";

const API = "/api";
const $ = (id) => document.getElementById(id);

const SEVERITIES = ["critical", "high", "medium", "low"];

function store(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(key);
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // Storage can be unavailable (private windows, blocked site data).
  }
  return null;
}

function escapeHtml(text) {
  return String(text == null ? "" : text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function icon(name) {
  return `<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

function severityOf(value) {
  const s = String(value || "low").toLowerCase();
  return SEVERITIES.includes(s) ? s : "low";
}

function scoreTone(score) {
  return score >= 80 ? "good" : score >= 50 ? "fair" : "poor";
}

function plural(n, word, many = word + "s") {
  return `${n} ${n === 1 ? word : many}`;
}

function severityLabel(sev) {
  return sev[0].toUpperCase() + sev.slice(1);
}

function parseDate(iso) {
  if (!iso) return null;
  // The API stores naive UTC timestamps.
  const d = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + "Z");
  return Number.isNaN(d.getTime()) ? null : d;
}

function formatDate(iso) {
  const d = parseDate(iso);
  if (!d) return "";
  const seconds = (Date.now() - d.getTime()) / 1000;
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400 && d.getDate() === new Date().getDate()) {
    return `Today, ${d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}`;
  }
  return d.toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

async function apiError(res, fallback) {
  const body = await res.json().catch(() => ({}));
  if (typeof body.detail === "string") return new Error(body.detail);
  if (res.status === 422) return new Error("The request wasn't valid. Check the file and try again.");
  return new Error(fallback);
}

function toast(message, kind = "info") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = `${icon(kind === "error" ? "x" : "check")}<span>${escapeHtml(message)}</span>`;
  $("toasts").appendChild(el);
  setTimeout(() => {
    el.classList.add("leaving");
    el.addEventListener("animationend", () => el.remove(), { once: true });
  }, kind === "error" ? 6000 : 3500);
}

/* Theme */

function syncThemeButton() {
  const dark = document.documentElement.dataset.theme === "dark";
  $("theme-toggle").setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
}

$("theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  store("cg-theme", next);
  syncThemeButton();
});

syncThemeButton();

/* Service status */

async function checkHealth() {
  const el = $("status");
  const text = el.querySelector(".status-text");
  try {
    const res = await fetch(`${API}/health`);
    const data = await res.json();
    const healthy = data.status === "healthy";
    el.dataset.state = healthy ? "ok" : "degraded";
    text.textContent = healthy ? "Operational" : "Degraded";
    el.title = `Database: ${data.database}, storage: ${data.s3}`;
  } catch {
    el.dataset.state = "down";
    text.textContent = "Offline";
    el.title = "The API isn't responding";
  }
}

/* Routing */

const views = ["scan", "diagram", "history", "how"];

function route() {
  const [name, param] = location.hash.replace(/^#/, "").split("/");
  const view = views.includes(name) ? name : "scan";

  views.forEach((v) => { $(`view-${v}`).hidden = v !== view; });
  document.querySelectorAll(".site-nav a").forEach((a) => {
    if (a.dataset.route === view) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });

  const title = $(`view-${view}`).dataset.title;
  document.title = view === "scan" ? "CloudGuard" : `${title} · CloudGuard`;

  if (view === "history") {
    if (param) openHistoryItem(param);
    else showHistoryIndex();
  }
}

window.addEventListener("hashchange", () => {
  route();
  window.scrollTo(0, 0);
});

/* Editor */

const EXAMPLE = `resource "aws_s3_bucket" "data_lake" {
  bucket = "company-data-lake-prod"
  acl    = "public-read-write"
}

resource "aws_db_instance" "production_db" {
  engine              = "mysql"
  engine_version      = "8.0"
  instance_class      = "db.t3.medium"
  allocated_storage   = 100
  username            = "admin"
  password            = "SuperSecret123!"
  publicly_accessible = true
  skip_final_snapshot = true
  storage_encrypted   = false
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
}
`;

const input = $("iac-input");
const gutter = $("gutter");
let gutterLines = 0;

function refreshEditor() {
  const lines = input.value.split("\n").length;
  if (lines !== gutterLines) {
    gutterLines = lines;
    gutter.textContent = Array.from({ length: lines }, (_, i) => i + 1).join("\n");
  }
  gutter.scrollTop = input.scrollTop;
  const chars = input.value.length;
  $("editor-meta").textContent = chars ? `${plural(lines, "line")} · ${chars.toLocaleString()} chars` : "";
}

let draftTimer;
input.addEventListener("input", () => {
  refreshEditor();
  clearTimeout(draftTimer);
  draftTimer = setTimeout(() => store("cg-draft", input.value || null), 400);
});
input.addEventListener("scroll", () => { gutter.scrollTop = input.scrollTop; });
input.addEventListener("keydown", (e) => {
  if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    runScan();
  }
});

$("btn-example").addEventListener("click", () => {
  input.value = EXAMPLE;
  $("file-name").value = "main.tf";
  store("cg-draft", EXAMPLE);
  refreshEditor();
  input.focus();
  input.setSelectionRange(0, 0);
  input.scrollTop = 0;
});

$("btn-clear").addEventListener("click", () => {
  input.value = "";
  store("cg-draft", null);
  refreshEditor();
  input.focus();
});

input.value = store("cg-draft") || "";
refreshEditor();

/* Scan with streamed progress */

const STEPS = [
  { id: "static_checks", label: "Running Checkov" },
  { id: "review", label: "Explaining findings" },
  { id: "rag_retrieval", label: "Checking your earlier fixes" },
  { id: "patch_generation", label: "Writing a patch" },
  { id: "storage", label: "Saving to history" },
];

const progress = {
  started: {},
  timer: null,

  reset() {
    this.started = {};
    $("steps").innerHTML = STEPS.map((s) => `
      <li class="step" data-step="${s.id}" data-state="pending">
        <span class="step-marker"><span class="step-pending"></span></span>
        <div><div class="step-label">${s.label}</div><div class="step-note"></div></div>
        <span class="step-time"></span>
      </li>`).join("");
    $("side-idle").hidden = true;
    $("side-progress").hidden = false;
    clearInterval(this.timer);
    this.timer = setInterval(() => this.tick(), 200);
  },

  set(stepId, state, note) {
    const row = document.querySelector(`.step[data-step="${stepId}"]`);
    if (!row) return;
    row.dataset.state = state;
    const marker = row.querySelector(".step-marker");
    if (state === "running") {
      this.started[stepId] = Date.now();
      marker.innerHTML = `<span class="spinner"></span>`;
    } else if (state === "done") {
      marker.innerHTML = icon("check");
      this.tick();
      delete this.started[stepId];
    } else if (state === "error") {
      marker.innerHTML = icon("x");
      delete this.started[stepId];
    } else if (state === "skipped") {
      marker.innerHTML = `<span class="step-pending"></span>`;
    }
    if (note !== undefined) row.querySelector(".step-note").textContent = note;
  },

  tick() {
    Object.entries(this.started).forEach(([id, t]) => {
      const el = document.querySelector(`.step[data-step="${id}"] .step-time`);
      if (el) el.textContent = `${((Date.now() - t) / 1000).toFixed(1)}s`;
    });
  },

  fail(message) {
    Object.keys(this.started).forEach((id) => this.set(id, "error", message));
    this.stop();
  },

  stop() {
    clearInterval(this.timer);
  },
};

function handleStreamEvent(event, context) {
  if (event.step === "error") {
    throw new Error(event.message || "The scan failed.");
  }
  if (event.step === "done") {
    context.result = event.data;
    return;
  }
  if (event.step === "storage" && event.status === "running") {
    // Steps that never started were skipped: static-only scan, or nothing to fix.
    document.querySelectorAll('.step[data-state="pending"]').forEach((row) => {
      if (row.dataset.step !== "storage") progress.set(row.dataset.step, "skipped", "Skipped");
    });
  }
  if (!STEPS.some((s) => s.id === event.step)) return;
  if (event.status === "running") {
    progress.set(event.step, "running");
  } else if (event.status === "error") {
    progress.set(event.step, "error", event.message);
  } else {
    const quiet = event.step === "storage" || event.step === "patch_generation";
    progress.set(event.step, "done", quiet ? undefined : event.message);
  }
}

async function readEventStream(res, onEvent) {
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    let boundary;
    while ((boundary = buffer.indexOf("\n\n")) !== -1) {
      const chunk = buffer.slice(0, boundary);
      buffer = buffer.slice(boundary + 2);
      const line = chunk.split("\n").find((l) => l.startsWith("data: "));
      if (line) onEvent(JSON.parse(line.slice(6)));
    }
  }
}

function setBusy(btn, busy, label) {
  if (!btn.dataset.idle) btn.dataset.idle = btn.innerHTML;
  btn.disabled = busy;
  btn.innerHTML = busy ? `<span class="spinner"></span>${escapeHtml(label)}` : btn.dataset.idle;
}

let scanning = false;

async function runScan() {
  if (scanning) return;
  const code = input.value;
  const fileName = $("file-name").value.trim() || "main.tf";
  if (code.trim().length < 10) {
    toast("Paste a configuration first.", "error");
    input.focus();
    return;
  }

  scanning = true;
  const btn = $("btn-scan");
  setBusy(btn, true, "Scanning");
  $("scan-report").hidden = true;
  progress.reset();

  const context = { result: null };
  try {
    const res = await fetch(`${API}/audit/stream`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ iac_content: code, file_name: fileName }),
    });
    if (!res.ok) throw await apiError(res, "The scan couldn't start.");

    await readEventStream(res, (event) => handleStreamEvent(event, context));
    if (!context.result) throw new Error("The connection closed before the scan finished.");

    progress.stop();
    historyCache.stale = true;
    showUsage(context.result.analysis);
    renderReport($("scan-report"), { ...context.result, original_code: code });
    $("scan-report").hidden = false;
    $("scan-report").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    progress.fail("Stopped");
    toast(err.message, "error");
  } finally {
    scanning = false;
    setBusy(btn, false);
  }
}

$("btn-scan").addEventListener("click", runScan);

/* Free explained scans */

function usageText(explanationsAvailable, left, perDay) {
  if (!explanationsAvailable) return "Checkov results only";
  if (left === 0) return "Free explanations used up today · Checkov results still run";
  return `${left} of ${perDay} free explained scans left today`;
}

const usage = { perDay: 0, available: false };

function showUsage(analysis) {
  if (analysis && usage.available) {
    $("usage-hint").textContent = usageText(true, analysis.free_scans_left, usage.perDay);
  }
}

async function loadUsage() {
  try {
    const res = await fetch(`${API}/usage`);
    if (!res.ok) return;
    const data = await res.json();
    usage.perDay = data.free_scans_per_day;
    usage.available = data.explanations_available;
    $("usage-hint").textContent = usageText(data.explanations_available, data.free_scans_left, data.free_scans_per_day);
  } catch {
    // The hint is optional; scans still work without it.
  }
}

/* Report */

function sortFindings(findings) {
  return [...findings].sort((a, b) =>
    SEVERITIES.indexOf(severityOf(a.severity)) - SEVERITIES.indexOf(severityOf(b.severity)));
}

function severityCounts(counts) {
  return SEVERITIES
    .filter((s) => counts[s])
    .map((s) => `<span class="sev-count"><span class="sev sev-${s}">${counts[s]}</span> ${s}</span>`)
    .join("");
}

function summarize(findings) {
  if (findings.length === 0) return "No problems were found in this file.";
  const counts = {};
  findings.forEach((f) => { const s = severityOf(f.severity); counts[s] = (counts[s] || 0) + 1; });
  const worst = SEVERITIES.find((s) => counts[s]);
  const lead = worst === "critical" || worst === "high"
    ? "Fix the critical and high findings before deploying."
    : "Nothing serious, but worth tidying up.";
  return `${plural(findings.length, "finding")}. ${lead}`;
}

function findingLocation(f) {
  const parts = [];
  if (f.check_id) parts.push(`<code>${escapeHtml(f.check_id)}</code>`);
  if (f.file) {
    const lines = f.line_start ? (f.line_end && f.line_end !== f.line_start ? `:${f.line_start}-${f.line_end}` : `:${f.line_start}`) : "";
    parts.push(`<span>${escapeHtml(f.file + lines)}</span>`);
  }
  return parts.length ? `<div class="finding-meta">${parts.join("")}</div>` : "";
}

function renderFindingItem(f, open) {
  const sev = severityOf(f.severity);
  const body = f.description
    ? `<p>${inlineMarkdown(f.description)}</p>${f.remediation ? `<h4>How to fix</h4><p>${inlineMarkdown(f.remediation)}</p>` : ""}`
    : `<p class="muted">No explanation in this scan. The check name above describes what failed.</p>`;
  return `
    <li><details class="finding"${open ? " open" : ""}>
      <summary>
        ${icon("chevron")}
        <span class="sev sev-${sev}">${severityLabel(sev)}</span>
        <span class="finding-title">${escapeHtml(f.title || "Untitled finding")}</span>
        ${f.resource ? `<code class="finding-resource" title="${escapeHtml(f.resource)}">${escapeHtml(f.resource)}</code>` : ""}
      </summary>
      <div class="finding-detail">${findingLocation(f)}${body}</div>
    </details></li>`;
}

function renderFindings(findings, analysis) {
  const checks = sortFindings(findings.filter((f) => f.source !== "review"));
  const review = sortFindings(findings.filter((f) => f.source === "review"));
  const explained = analysis && analysis.mode !== "static";

  if (findings.length === 0) {
    const covered = !analysis || (analysis.covered_files || []).length > 0;
    return covered
      ? `<div class="empty-state"><h3>No findings</h3><p>Every Checkov policy that applies to this file passed. That's a good sign, not proof the file is secure.</p></div>`
      : `<div class="empty-state"><h3>Nothing to report</h3><p>This file type isn't covered by Checkov${explained ? " and the review didn't flag anything" : ""}.</p></div>`;
  }

  const openFirst = explained ? 3 : 0;
  let html = "";
  if (checks.length) {
    html += `<ul class="findings">${checks.map((f, i) => renderFindingItem(f, i < openFirst)).join("")}</ul>`;
  }
  if (review.length) {
    html += `
      <div class="findings-group">
        <h3>Also noticed in review</h3>
        <p>Found by the model review, not by a Checkov policy, so they aren't counted in the score. Double-check them.</p>
      </div>
      <ul class="findings">${review.map((f, i) => renderFindingItem(f, !checks.length && i < 3)).join("")}</ul>`;
  }
  return html;
}

function renderNotices(analysis) {
  const notices = (analysis && analysis.notices) || [];
  if (!notices.length) return "";
  return `<div class="notices">${notices.map((n) => `<p>${escapeHtml(n)}</p>`).join("")}</div>`;
}

function patchedFileName(name) {
  const dot = name.lastIndexOf(".");
  return dot > 0 ? `${name.slice(0, dot)}.patched${name.slice(dot)}` : `${name}.patched`;
}

function renderReport(container, result) {
  const findings = Array.isArray(result.vulnerabilities) ? result.vulnerabilities : [];
  const analysis = result.analysis || null;
  const scored = result.security_score !== null && result.security_score !== undefined;
  const score = Number(result.security_score) || 0;
  const counts = {};
  findings.forEach((f) => { const s = severityOf(f.severity); counts[s] = (counts[s] || 0) + 1; });

  const meta = [];
  if (result.created_at) meta.push(escapeHtml(formatDate(result.created_at)));
  if (result.audit_id) meta.push(`Scan <code>${escapeHtml(result.audit_id)}</code>`);
  if (analysis && analysis.checkov_version) meta.push(`Checkov ${escapeHtml(analysis.checkov_version)}`);

  container.innerHTML = `
    <div class="report-head">
      ${scored
        ? `<div class="score" data-tone="${scoreTone(score)}" aria-label="Score ${score} out of 100">
            <span class="score-num">${score}</span><span class="score-of">/100</span>
          </div>`
        : `<div class="score" data-tone="none" title="No file in this scan is a type Checkov covers">
            <span class="score-num">–</span><span class="score-of">Not scored</span>
          </div>`}
      <div class="report-summary">
        <h2>${escapeHtml(result.file_name || "main.tf")}</h2>
        <p>${escapeHtml(summarize(findings))}</p>
        ${findings.length ? `<div class="sev-counts">${severityCounts(counts)}</div>` : ""}
        ${meta.length ? `<div class="report-meta">${meta.join(" · ")}</div>` : ""}
      </div>
    </div>
    ${renderNotices(analysis)}
    <div class="tabs" role="tablist">
      <button class="tab" role="tab" type="button" data-tab="findings" aria-selected="true">
        Findings <span class="tab-count">${findings.length}</span>
      </button>
      <button class="tab" role="tab" type="button" data-tab="patch" aria-selected="false">Patch</button>
    </div>
    <div class="tab-panel" data-panel="findings">${renderFindings(findings, analysis)}</div>
    <div class="tab-panel" data-panel="patch" hidden></div>`;

  const patchPanel = container.querySelector('[data-panel="patch"]');
  renderPatch(patchPanel, result.original_code || "", result.patched_code || "", result.file_name || "main.tf", analysis);

  container.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      container.querySelectorAll(".tab").forEach((t) => t.setAttribute("aria-selected", String(t === tab)));
      container.querySelectorAll(".tab-panel").forEach((p) => { p.hidden = p.dataset.panel !== tab.dataset.tab; });
    });
  });
}

/* Line diff */

function diffLines(a, b) {
  const ka = a.map((l) => l.trimEnd());
  const kb = b.map((l) => l.trimEnd());

  let head = 0;
  while (head < ka.length && head < kb.length && ka[head] === kb[head]) head++;
  let endA = ka.length;
  let endB = kb.length;
  while (endA > head && endB > head && ka[endA - 1] === kb[endB - 1]) { endA--; endB--; }

  const n = endA - head;
  const m = endB - head;
  if (n * m > 4_000_000) return null;

  const w = m + 1;
  const lcs = new Uint32Array((n + 1) * w);
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      lcs[i * w + j] = ka[head + i] === kb[head + j]
        ? lcs[(i + 1) * w + j + 1] + 1
        : Math.max(lcs[(i + 1) * w + j], lcs[i * w + j + 1]);
    }
  }

  const ops = [];
  for (let k = 0; k < head; k++) ops.push({ type: "same", a: k, b: k });
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (ka[head + i] === kb[head + j]) {
      ops.push({ type: "same", a: head + i, b: head + j }); i++; j++;
    } else if (lcs[(i + 1) * w + j] >= lcs[i * w + j + 1]) {
      ops.push({ type: "del", a: head + i }); i++;
    } else {
      ops.push({ type: "add", b: head + j }); j++;
    }
  }
  while (i < n) { ops.push({ type: "del", a: head + i }); i++; }
  while (j < m) { ops.push({ type: "add", b: head + j }); j++; }
  for (let k = 0; k < ka.length - endA; k++) ops.push({ type: "same", a: endA + k, b: endB + k });
  return ops;
}

const CONTEXT = 3;

function diffRow(op, a, b) {
  const sign = op.type === "add" ? "+" : op.type === "del" ? "−" : "";
  const text = op.type === "add" ? b[op.b] : a[op.a];
  return `<tr class="${op.type}">
    <td class="ln">${op.type === "add" ? "" : op.a + 1}</td>
    <td class="ln">${op.type === "del" ? "" : op.b + 1}</td>
    <td class="sign">${sign}</td>
    <td class="code">${escapeHtml(text)}</td>
  </tr>`;
}

function renderDiffTable(ops, a, b) {
  const parts = [];
  let run = [];

  const flushRun = (atStart, atEnd) => {
    const keepHead = atStart ? 0 : CONTEXT;
    const keepTail = atEnd ? 0 : CONTEXT;
    if (run.length <= keepHead + keepTail + 2) {
      parts.push(`<tbody>${run.map((op) => diffRow(op, a, b)).join("")}</tbody>`);
    } else {
      const hidden = run.slice(keepHead, run.length - keepTail);
      if (keepHead) parts.push(`<tbody>${run.slice(0, keepHead).map((op) => diffRow(op, a, b)).join("")}</tbody>`);
      parts.push(`<tbody class="fold"><tr><td colspan="4"><button class="fold-btn" type="button">Show ${plural(hidden.length, "unchanged line")}</button></td></tr></tbody>`);
      parts.push(`<tbody hidden>${hidden.map((op) => diffRow(op, a, b)).join("")}</tbody>`);
      if (keepTail) parts.push(`<tbody>${run.slice(run.length - keepTail).map((op) => diffRow(op, a, b)).join("")}</tbody>`);
    }
    run = [];
  };

  let sawChange = false;
  ops.forEach((op) => {
    if (op.type === "same") {
      run.push(op);
      return;
    }
    if (run.length) flushRun(!sawChange, false);
    sawChange = true;
    parts.push(`<tbody>${diffRow(op, a, b)}</tbody>`);
  });
  if (run.length) flushRun(!sawChange, true);

  return `<table>${parts.join("")}</table>`;
}

function renderPatch(panel, original, patched, fileName, analysis) {
  if (!patched.trim()) {
    const reason = analysis && analysis.mode === "static"
      ? "Patches are written for explained scans. This one ran Checkov only."
      : "There was nothing to fix, or the patch couldn't be written.";
    panel.innerHTML = `<div class="empty-state"><h3>No patch</h3><p>${reason}</p></div>`;
    return;
  }

  const a = original.replace(/\n$/, "").split("\n");
  const b = patched.replace(/\n$/, "").split("\n");
  const ops = original ? diffLines(a, b) : null;
  const added = ops ? ops.filter((o) => o.type === "add").length : 0;
  const removed = ops ? ops.filter((o) => o.type === "del").length : 0;

  panel.innerHTML = `
    <div class="diff-bar">
      <span class="diff-stats">${ops ? `<span class="plus">+${added}</span> <span class="minus">−${removed}</span> lines` : escapeHtml(patchedFileName(fileName))}</span>
      <div class="diff-actions">
        <button class="btn btn-quiet" type="button" data-action="copy">${icon("copy")}Copy patched file</button>
        <button class="btn btn-quiet" type="button" data-action="download">${icon("download")}Download</button>
      </div>
    </div>
    ${ops ? `<div class="diff">${renderDiffTable(ops, a, b)}</div>` : `<pre class="plain-code">${escapeHtml(patched)}</pre>`}`;

  panel.addEventListener("click", async (e) => {
    const fold = e.target.closest(".fold-btn");
    if (fold) {
      const tbody = fold.closest("tbody");
      tbody.nextElementSibling.hidden = false;
      tbody.remove();
      return;
    }
    const action = e.target.closest("[data-action]")?.dataset.action;
    if (action === "copy") {
      try {
        await navigator.clipboard.writeText(patched);
        toast("Patched file copied");
      } catch {
        toast("Couldn't access the clipboard.", "error");
      }
    } else if (action === "download") {
      const url = URL.createObjectURL(new Blob([patched], { type: "text/plain" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = patchedFileName(fileName);
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    }
  });
}

/* Diagram check */

const MAX_DIAGRAM_BYTES = 8 * 1024 * 1024;
const DIAGRAM_TYPES = ["image/png", "image/jpeg", "image/webp"];
let diagramFile = null;
let previewUrl = null;

function acceptDiagram(file) {
  if (!file) return;
  if (!DIAGRAM_TYPES.includes(file.type)) {
    toast("Use a PNG, JPEG or WebP image.", "error");
    return;
  }
  if (file.size > MAX_DIAGRAM_BYTES) {
    toast("Diagrams can be up to 8 MB.", "error");
    return;
  }
  diagramFile = file;
  if (previewUrl) URL.revokeObjectURL(previewUrl);
  previewUrl = URL.createObjectURL(file);
  $("dropzone-preview").src = previewUrl;
  $("dropzone-preview").hidden = false;
  $("dropzone-empty").hidden = true;
  $("diagram-file-name").textContent = `${file.name} · ${(file.size / 1024 / 1024).toFixed(1)} MB`;
}

const dropzone = $("dropzone");
$("diagram-file").addEventListener("change", (e) => acceptDiagram(e.target.files[0]));
dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("dragover"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
  acceptDiagram(e.dataTransfer.files[0]);
});

function inlineMarkdown(text) {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
}

// Just enough Markdown for the drift report: headings, lists, bold, code.
function renderMarkdown(source) {
  const out = [];
  let list = null;
  const closeList = () => { if (list) { out.push(`</${list}>`); list = null; } };

  source.split("\n").forEach((raw) => {
    const line = raw.trimEnd();
    const heading = line.match(/^#{1,6}\s+(.*)$/);
    const bullet = line.match(/^\s*[-*]\s+(.*)$/);
    const numbered = line.match(/^\s*(\d+)[.)]\s+(.*)$/);

    if (heading) {
      closeList();
      out.push(`<h3>${inlineMarkdown(heading[1])}</h3>`);
    } else if (bullet || numbered) {
      const tag = bullet ? "ul" : "ol";
      if (list !== tag) {
        closeList();
        // Keep the model's numbering when bullets interrupt a numbered list.
        out.push(numbered ? `<ol start="${Number(numbered[1])}">` : "<ul>");
        list = tag;
      }
      out.push(`<li>${inlineMarkdown(bullet ? bullet[1] : numbered[2])}</li>`);
    } else if (line.trim() === "" || /^-{3,}$/.test(line.trim())) {
      closeList();
    } else {
      closeList();
      out.push(`<p>${inlineMarkdown(line)}</p>`);
    }
  });
  closeList();
  return out.join("");
}

$("btn-compare").addEventListener("click", async () => {
  const code = $("diagram-iac").value;
  if (code.trim().length < 10) {
    toast("Paste the Terraform configuration first.", "error");
    $("diagram-iac").focus();
    return;
  }
  if (!diagramFile) {
    toast("Choose a diagram to compare against.", "error");
    return;
  }

  const btn = $("btn-compare");
  setBusy(btn, true, "Comparing");

  const form = new FormData();
  form.append("iac_content", code);
  form.append("file_name", "main.tf");
  form.append("diagram", diagramFile);

  try {
    const res = await fetch(`${API}/audit/diagram`, { method: "POST", body: form });
    if (!res.ok) throw await apiError(res, "The comparison failed.");
    const result = await res.json();
    historyCache.stale = true;

    const container = $("diagram-report");
    container.innerHTML = `
      <section class="drift">
        <h2>Diagram vs. code</h2>
        <div class="md">${renderMarkdown(result.diagram_analysis || "No analysis was returned.")}</div>
      </section>
      <h2 class="section-title">Security scan</h2>
      <div class="scan-part"></div>`;
    renderReport(container.querySelector(".scan-part"), { ...result, original_code: code });
    container.hidden = false;
    container.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    toast(err.message, "error");
  } finally {
    setBusy(btn, false);
  }
});

/* History */

const historyCache = { stale: true, rows: [] };

function loadingRow(label) {
  return `<div class="loading-row"><span class="spinner"></span>${escapeHtml(label)}</div>`;
}

function renderScanList(rows) {
  if (rows.length === 0) {
    return `<div class="empty-state"><h3>No scans yet</h3><p>Scans you run in this browser will be listed here. <a href="#scan">Run a scan</a></p></div>`;
  }
  return `
    <div class="list-head"><span>${plural(rows.length, "scan")}</span><span>Score</span></div>
    <ul class="scan-list">${rows.map((r) => {
      const counts = {};
      Object.entries(r.severity_counts || {}).forEach(([k, v]) => { counts[severityOf(k)] = (counts[severityOf(k)] || 0) + v; });
      return `<li><a class="scan-row" href="#history/${encodeURIComponent(r.audit_id)}">
        <div>
          <div class="scan-file">${escapeHtml(r.file_name)}</div>
          <div class="scan-sub">${r.has_diagram ? "With diagram check · " : ""}${plural(r.finding_count, "finding")}</div>
        </div>
        <div class="scan-counts">${severityCounts(counts)}</div>
        <div class="scan-date">${escapeHtml(formatDate(r.created_at))}</div>
        ${r.security_score === null
          ? `<div class="scan-score" data-tone="none" title="Not scored">–</div>`
          : `<div class="scan-score" data-tone="${scoreTone(r.security_score)}">${r.security_score}</div>`}
      </a></li>`;
    }).join("")}</ul>`;
}

async function showHistoryIndex() {
  $("history-detail").hidden = true;
  $("history-index").hidden = false;
  if ($("search-input").value.trim()) return;

  const body = $("history-body");
  if (!historyCache.stale) {
    body.innerHTML = renderScanList(historyCache.rows);
    return;
  }
  body.innerHTML = loadingRow("Loading scans");
  try {
    const res = await fetch(`${API}/history`);
    if (!res.ok) throw await apiError(res, "History couldn't be loaded.");
    historyCache.rows = await res.json();
    historyCache.stale = false;
    body.innerHTML = renderScanList(historyCache.rows);
  } catch (err) {
    body.innerHTML = `<div class="empty-state"><h3>History isn't available</h3><p>${escapeHtml(err.message)}</p></div>`;
  }
}

async function openHistoryItem(auditId) {
  $("history-index").hidden = true;
  $("history-detail").hidden = false;
  const container = $("history-report");
  container.innerHTML = loadingRow("Loading scan");
  try {
    const res = await fetch(`${API}/history/${encodeURIComponent(auditId)}`);
    if (res.status === 404) {
      container.innerHTML = `<div class="empty-state"><h3>Scan not found</h3><p>It may have been cleared, or it was made in a different browser.</p></div>`;
      return;
    }
    if (!res.ok) throw await apiError(res, "The scan couldn't be loaded.");
    const result = await res.json();
    renderReport(container, result);
    if (result.diagram_analysis) {
      container.insertAdjacentHTML("afterbegin", `
        <section class="drift"><h2>Diagram vs. code</h2><div class="md">${renderMarkdown(result.diagram_analysis)}</div></section>`);
    }
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><h3>Scan unavailable</h3><p>${escapeHtml(err.message)}</p></div>`;
  }
}

$("search-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const query = $("search-input").value.trim();
  const body = $("history-body");
  if (query.length < 3) {
    toast("Type at least three characters.", "error");
    return;
  }

  body.innerHTML = loadingRow("Searching");
  try {
    const res = await fetch(`${API}/search`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, limit: 10 }),
    });
    if (!res.ok) throw await apiError(res, "Search failed.");
    const data = await res.json();

    const head = `<div class="list-head"><span>${plural(data.total, "match", "matches")} for “${escapeHtml(query)}”</span><button class="link-btn" type="button" id="btn-clear-search">Show all scans</button></div>`;
    body.innerHTML = head + (data.results.length === 0
      ? `<div class="empty-state"><h3>No matches</h3><p>Search compares meaning rather than exact words, but it only covers your own scans.</p></div>`
      : data.results.map((r) => `
        <a class="result-row" href="#history/${encodeURIComponent(r.audit_id)}">
          <div class="result-top">
            <span class="sev sev-${severityOf(r.severity)}">${severityLabel(severityOf(r.severity))}</span>
            <span class="result-title">${escapeHtml(r.vulnerability_type)}</span>
            <span class="result-match">${Math.max(0, Math.round(r.similarity_score * 100))}% match</span>
          </div>
          <p>${inlineMarkdown(r.description)}</p>
          <div class="result-file">${escapeHtml(r.file_name)}</div>
        </a>`).join(""));
  } catch (err) {
    body.innerHTML = `<div class="empty-state"><h3>Search isn't available</h3><p>${escapeHtml(err.message)}</p></div>`;
  }
});

$("history-body").addEventListener("click", (e) => {
  if (e.target.id !== "btn-clear-search") return;
  $("search-input").value = "";
  showHistoryIndex();
});

$("search-input").addEventListener("search", () => {
  if (!$("search-input").value) showHistoryIndex();
});

$("btn-clear-history").addEventListener("click", () => $("confirm-clear").showModal());

$("confirm-clear").addEventListener("close", async () => {
  if ($("confirm-clear").returnValue !== "confirm") return;
  try {
    const res = await fetch(`${API}/history`, { method: "DELETE" });
    if (!res.ok) throw await apiError(res, "History couldn't be cleared.");
    historyCache.stale = true;
    $("search-input").value = "";
    toast("History cleared");
    showHistoryIndex();
  } catch (err) {
    toast(err.message, "error");
  }
});

/* Start */

route();
checkHealth();
loadUsage();
setInterval(checkHealth, 60000);
