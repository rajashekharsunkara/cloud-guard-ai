import { renderMarkdown } from "./markdown.js";
import { renderReport } from "./report.js";
import {
  $, API, apiError, escapeHtml, formatDate, inlineMarkdown, plural,
  riskbar, scoreTone, severityLabel, severityOf, toast,
} from "./util.js";

const cache = { stale: true, rows: [] };
const SOURCE = { github: "GitHub", zip: "Zip upload", paste: "Pasted", cli: "Command line" };

function loading(label) {
  return `<div class="loading-row"><span class="spinner"></span>${escapeHtml(label)}</div>`;
}

function subtitle(row) {
  const parts = [SOURCE[row.source] || "Pasted"];
  if (row.file_count > 1) parts.push(plural(row.file_count, "file"));
  if (row.has_diagram) parts.push("with diagram");
  parts.push(plural(row.finding_count, "finding"));
  return parts.join(" · ");
}

function ledger(rows) {
  if (!rows.length) {
    return `<div class="empty-state"><h3>No scans yet</h3><p>Scans you run in this browser are kept here. <a href="#scan">Run a scan</a></p></div>`;
  }
  const items = rows.map((row) => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    Object.entries(row.severity_counts || {}).forEach(([k, v]) => { counts[severityOf(k)] += v; });
    const scored = row.security_score !== null;
    return `<li><a href="#history/${encodeURIComponent(row.audit_id)}">
      <time>${escapeHtml(formatDate(row.created_at))}</time>
      <div>
        <div class="ledger-label">${escapeHtml(row.file_name)}</div>
        <div class="ledger-sub">${escapeHtml(subtitle(row))}</div>
      </div>
      ${riskbar(counts)}
      <div class="ledger-score" data-tone="${scoreTone(scored ? row.security_score : null)}">${scored ? row.security_score : "–"}</div>
    </a></li>`;
  }).join("");
  return `
    <div class="ledger-head"><span class="eyebrow">When</span><span class="eyebrow">Scan</span><span class="eyebrow">Findings</span><span class="eyebrow">Score</span></div>
    <ul class="ledger">${items}</ul>`;
}

export async function showIndex() {
  $("history-detail").hidden = true;
  $("history-index").hidden = false;
  if ($("search-input").value.trim()) return;
  const body = $("history-body");
  if (!cache.stale) {
    body.innerHTML = ledger(cache.rows);
    return;
  }
  body.innerHTML = loading("Loading scans");
  try {
    const res = await fetch(`${API}/history`);
    if (!res.ok) throw await apiError(res, "History couldn't be loaded.");
    cache.rows = await res.json();
    cache.stale = false;
    body.innerHTML = ledger(cache.rows);
  } catch (err) {
    body.innerHTML = `<div class="empty-state"><h3>History isn't available</h3><p>${escapeHtml(err.message)}</p></div>`;
  }
}

export async function showDetail(auditId) {
  $("history-index").hidden = true;
  $("history-detail").hidden = false;
  const container = $("history-report");
  container.innerHTML = loading("Loading scan");
  try {
    const res = await fetch(`${API}/history/${encodeURIComponent(auditId)}`);
    if (res.status === 404) {
      container.innerHTML = `<div class="empty-state"><h3>Scan not found</h3><p>It may have been cleared, or it was made in another browser.</p></div>`;
      return;
    }
    if (!res.ok) throw await apiError(res, "The scan couldn't be loaded.");
    const result = await res.json();
    if (result.diagram_analysis) {
      container.innerHTML = `
        <section class="drift"><span class="eyebrow">Diagram vs. code</span><h2>What doesn't line up</h2>
        <div class="md">${renderMarkdown(result.diagram_analysis)}</div></section>
        <div data-scan></div>`;
      renderReport(container.querySelector("[data-scan]"), result);
    } else {
      renderReport(container, result);
    }
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><h3>Scan unavailable</h3><p>${escapeHtml(err.message)}</p></div>`;
  }
}

async function search(e) {
  e.preventDefault();
  const query = $("search-input").value.trim();
  if (query.length < 3) {
    toast("Type at least three characters.", "error");
    return;
  }
  const body = $("history-body");
  body.innerHTML = loading("Searching");
  try {
    const res = await fetch(`${API}/search`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ query, limit: 12 }),
    });
    if (!res.ok) throw await apiError(res, "Search failed.");
    const data = await res.json();
    const head = `<div class="list-head"><span class="eyebrow">${plural(data.total, "match", "matches")} for “${escapeHtml(query)}”</span><button class="link-btn" type="button" data-clear-search>Show all scans</button></div>`;
    body.innerHTML = head + (data.results.length
      ? data.results.map((r) => `
        <a class="result-row" href="#history/${encodeURIComponent(r.audit_id)}">
          <div class="result-top">
            <span class="sev sev-${severityOf(r.severity)}">${severityLabel(severityOf(r.severity))}</span>
            <span class="result-title">${inlineMarkdown(r.vulnerability_type)}</span>
            <span class="result-match">${Math.max(0, Math.round(r.similarity_score * 100))}% match</span>
          </div>
          <p>${inlineMarkdown(r.description)}</p>
          <div class="result-file">${escapeHtml(r.file_name)}</div>
        </a>`).join("")
      : `<div class="empty-state"><h3>No matches</h3><p>Search compares meaning rather than exact words, and only covers your own scans.</p></div>`);
  } catch (err) {
    body.innerHTML = `<div class="empty-state"><h3>Search isn't available</h3><p>${escapeHtml(err.message)}</p></div>`;
  }
}

export function markStale() {
  cache.stale = true;
}

export function initHistory() {
  $("search-form").addEventListener("submit", search);
  $("history-body").addEventListener("click", (e) => {
    if (!e.target.closest("[data-clear-search]")) return;
    $("search-input").value = "";
    showIndex();
  });
  $("search-input").addEventListener("search", () => {
    if (!$("search-input").value) showIndex();
  });
  $("btn-clear-history").addEventListener("click", () => $("confirm-clear").showModal());
  $("confirm-clear").addEventListener("close", async () => {
    if ($("confirm-clear").returnValue !== "confirm") return;
    try {
      const res = await fetch(`${API}/history`, { method: "DELETE" });
      if (!res.ok) throw await apiError(res, "History couldn't be cleared.");
      cache.stale = true;
      $("search-input").value = "";
      toast("History cleared");
      showIndex();
    } catch (err) {
      toast(err.message, "error");
    }
  });
  document.addEventListener("cloudguard:scanned", markStale);
}
