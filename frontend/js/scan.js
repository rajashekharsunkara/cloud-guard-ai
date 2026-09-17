import { applyAnalysis, llmHeaders } from "./model.js";
import { renderReport } from "./report.js";
import {
  $, API, apiError, escapeHtml, plural, setBusy, store, toast,
} from "./util.js";

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

const STEP_LABELS = {
  fetch: "fetch",
  static_checks: "checkov",
  review: "review",
  rag_retrieval: "history",
  patch_generation: "patch",
  diagram: "diagram",
  storage: "save",
};

let activeSource = "paste";
let zipFile = null;
let scanning = false;
// The most recent scan from this page, so its result page can offer to run
// it again. Results opened any other way are loaded from history.
let lastScan = null;

/* Editor */

const input = () => $("iac-input");
let gutterLines = 0;

function refreshEditor() {
  const text = input().value;
  const lines = text.split("\n").length;
  if (lines !== gutterLines) {
    gutterLines = lines;
    $("gutter").textContent = Array.from({ length: lines }, (_, i) => i + 1).join("\n");
  }
  $("gutter").scrollTop = input().scrollTop;
  $("editor-meta").textContent = text.length ? `${plural(lines, "line")} · ${text.length.toLocaleString()} chars` : "";
}

function initEditor() {
  let draftTimer;
  input().addEventListener("input", () => {
    refreshEditor();
    clearTimeout(draftTimer);
    draftTimer = setTimeout(() => store("cg-draft", input().value || null), 400);
  });
  input().addEventListener("scroll", () => { $("gutter").scrollTop = input().scrollTop; });
  $("btn-example").addEventListener("click", () => {
    input().value = EXAMPLE;
    $("file-name").value = "main.tf";
    store("cg-draft", EXAMPLE);
    refreshEditor();
    input().focus();
    input().setSelectionRange(0, 0);
    input().scrollTop = 0;
  });
  $("btn-clear").addEventListener("click", () => {
    input().value = "";
    store("cg-draft", null);
    refreshEditor();
    input().focus();
  });
  input().value = store("cg-draft") || "";
  refreshEditor();
}

/* Sources */

function selectSource(source) {
  activeSource = source;
  document.querySelectorAll(".source-tab").forEach((tab) => {
    tab.setAttribute("aria-selected", String(tab.dataset.source === source));
  });
  document.querySelectorAll("[data-panel-source]").forEach((panel) => {
    panel.hidden = panel.dataset.panelSource !== source;
  });
}

function acceptZip(file) {
  if (!file) return;
  if (!/\.zip$/i.test(file.name)) {
    toast("Choose a .zip file.", "error");
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    toast("Zip files can be up to 10 MB.", "error");
    return;
  }
  zipFile = file;
  $("zip-title").textContent = file.name;
  $("zip-sub").textContent = `${Math.max(1, Math.round(file.size / 1024))} KB · choose another file to replace it`;
}

function initSources() {
  document.querySelectorAll(".source-tab").forEach((tab) => {
    tab.addEventListener("click", () => selectSource(tab.dataset.source));
  });
  const drop = $("zip-dropzone");
  $("zip-file").addEventListener("change", (e) => acceptZip(e.target.files[0]));
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("dragover"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("dragover"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("dragover");
    acceptZip(e.dataTransfer.files[0]);
  });
  document.querySelectorAll("[data-repo]").forEach((btn) => {
    btn.addEventListener("click", () => { $("repo-url").value = btn.dataset.repo; $("repo-url").focus(); });
  });
  $("repo-url").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); runScan(); }
  });
}

// The request for the chosen source, or null after telling the user what's missing.
function buildRequest() {
  if (activeSource === "zip") {
    if (!zipFile) {
      toast("Choose a zip file first.", "error");
      return null;
    }
    return { url: `${API}/audit/archive`, body: () => { const f = new FormData(); f.append("archive", zipFile); return f; }, original: "" };
  }
  if (activeSource === "github") {
    const url = $("repo-url").value.trim();
    if (!url) {
      toast("Paste a GitHub repository link first.", "error");
      $("repo-url").focus();
      return null;
    }
    return { url: `${API}/audit/repo`, json: { url }, original: "", fetches: true };
  }
  const code = input().value;
  if (code.trim().length < 10) {
    toast("Paste a configuration first.", "error");
    input().focus();
    return null;
  }
  const fileName = $("file-name").value.trim() || "main.tf";
  return { url: `${API}/audit/stream`, json: { iac_content: code, file_name: fileName }, original: code };
}

/* Scan log */

const log = {
  reset() {
    $("log").innerHTML = "";
    $("side-idle").hidden = true;
    $("side-progress").hidden = false;
  },

  line(step, state, message) {
    let row = $("log").querySelector(`[data-step="${step}"]`);
    if (!row) {
      row = document.createElement("li");
      row.dataset.step = step;
      const time = new Date().toLocaleTimeString([], { hour12: false });
      row.innerHTML = `<time>${time}</time><span class="state"></span><span class="msg"></span>`;
      $("log").appendChild(row);
    }
    row.dataset.state = state;
    row.querySelector(".state").textContent = { running: "›", done: "✓", error: "✕", skipped: "–" }[state] || "·";
    const label = STEP_LABELS[step] || step;
    row.querySelector(".msg").textContent = message ? `${label}  ${message}` : label;
  },

  failRunning(message) {
    $("log").querySelectorAll('[data-state="running"]').forEach((row) => this.line(row.dataset.step, "error", message));
  },
};

function handleEvent(event, context) {
  if (event.step === "error") throw new Error(event.message || "The scan failed.");
  if (event.step === "done") {
    context.result = event.data;
    return;
  }
  const message = (event.message || "").replace(/\.\.\.$/, "").toLowerCase();
  if (event.status === "running") log.line(event.step, "running", "…");
  else if (event.status === "error") log.line(event.step, "error", message);
  else log.line(event.step, "done", message);
}

async function readStream(res, onEvent) {
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

/* Running a scan */

export async function runScan(request = null) {
  if (scanning) return;
  const req = request || buildRequest();
  if (!req) return;
  if (location.hash.startsWith("#scan/")) location.hash = "#scan";

  scanning = true;
  const btn = $("btn-scan");
  setBusy(btn, true, "Scanning");
  log.reset();

  const context = { result: null };
  try {
    const headers = { ...llmHeaders() };
    let body;
    if (req.json) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(req.json);
    } else {
      body = req.body();
    }
    const res = await fetch(req.url, { method: "POST", headers, body });
    if (!res.ok) throw await apiError(res, "The scan couldn't start.");
    await readStream(res, (event) => handleEvent(event, context));
    if (!context.result) throw new Error("The connection closed before the scan finished.");

    document.dispatchEvent(new CustomEvent("cloudguard:scanned"));
    applyAnalysis(context.result.analysis);
    const id = context.result.audit_id;
    lastScan = { id, result: { ...context.result, original_code: req.original }, request: req };
    if (!$("view-scan").hidden) location.hash = `#scan/${encodeURIComponent(id)}`;
    else toast("Your scan finished. It's saved in History.");
  } catch (err) {
    log.failRunning("stopped");
    toast(err.message, "error");
  } finally {
    scanning = false;
    setBusy(btn, false);
  }
}

/* Result page */

export function showScanForm() {
  $("scan-result").hidden = true;
  $("scan-form").hidden = false;
}

export async function showScanResult(id) {
  $("scan-form").hidden = true;
  $("scan-result").hidden = false;
  const container = $("scan-report");
  const fresh = lastScan && lastScan.id === id;
  $("btn-rescan").hidden = !fresh;
  if (fresh) {
    renderReport(container, lastScan.result, { onRetry: scanAgain });
    return;
  }
  // Opened from a reload or a link: the scan is in this browser's history.
  container.innerHTML = `<div class="loading-row"><span class="spinner"></span>Loading scan</div>`;
  try {
    const res = await fetch(`${API}/history/${encodeURIComponent(id)}`);
    if (res.status === 404) {
      container.innerHTML = `<div class="empty-state"><h3>Scan not found</h3><p>It may have been cleared, or it was made in another browser.</p></div>`;
      return;
    }
    if (!res.ok) throw await apiError(res, "The scan couldn't be loaded.");
    if (location.hash !== `#scan/${encodeURIComponent(id)}`) return;
    renderReport(container, await res.json());
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><h3>Scan unavailable</h3><p>${escapeHtml(err.message)}</p></div>`;
  }
}

function scanAgain() {
  if (lastScan) runScan(lastScan.request);
}

export function initScan() {
  initEditor();
  initSources();
  $("btn-scan").addEventListener("click", () => runScan());
  $("btn-rescan").addEventListener("click", scanAgain);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey) && !$("view-scan").hidden && !$("scan-form").hidden) {
      e.preventDefault();
      runScan();
    }
  });
}
