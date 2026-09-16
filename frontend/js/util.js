export const API = "/api";
export const SEVERITIES = ["critical", "high", "medium", "low"];

export const $ = (id) => document.getElementById(id);

export function escapeHtml(text) {
  return String(text == null ? "" : text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function inlineMarkdown(text) {
  return escapeHtml(text)
    .replace(/`([^`]+)`/g, "<code>$1</code>")
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
}

export function icon(name, cls = "icon") {
  return `<svg class="${cls}" aria-hidden="true"><use href="#i-${name}"/></svg>`;
}

export function plural(n, word, many = word + "s") {
  return `${n} ${n === 1 ? word : many}`;
}

export function severityOf(value) {
  const s = String(value || "low").toLowerCase();
  return SEVERITIES.includes(s) ? s : "low";
}

export function severityLabel(sev) {
  return sev[0].toUpperCase() + sev.slice(1);
}

export function severityRank(finding) {
  return SEVERITIES.indexOf(severityOf(finding.severity));
}

export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  findings.forEach((f) => { counts[severityOf(f.severity)] += 1; });
  return counts;
}

export function scoreTone(score) {
  if (score === null || score === undefined) return "none";
  return score >= 80 ? "good" : score >= 50 ? "fair" : "poor";
}

export function riskbar(counts) {
  const total = SEVERITIES.reduce((sum, s) => sum + counts[s], 0);
  if (!total) return `<div class="riskbar" aria-hidden="true"></div>`;
  const parts = SEVERITIES.filter((s) => counts[s])
    .map((s) => `<span class="${s}" style="width:${(counts[s] / total) * 100}%"></span>`).join("");
  return `<div class="riskbar" role="img" aria-label="${SEVERITIES.filter((s) => counts[s]).map((s) => `${counts[s]} ${s}`).join(", ")}">${parts}</div>`;
}

export function parseDate(iso) {
  if (!iso) return null;
  // The API stores naive UTC timestamps.
  const d = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + "Z");
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatDate(iso) {
  const d = parseDate(iso);
  if (!d) return "";
  const seconds = (Date.now() - d.getTime()) / 1000;
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  const sameDay = d.toDateString() === new Date().toDateString();
  const time = d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" });
  if (sameDay) return `Today ${time}`;
  return d.toLocaleDateString([], { month: "short", day: "numeric" }) + ` ${time}`;
}

export function formatWait(seconds) {
  const s = Math.max(0, Math.round(seconds));
  if (s < 60) return `${s}s`;
  const minutes = Math.round(s / 60);
  if (minutes < 5) {
    const rest = s % 60;
    return rest ? `${Math.floor(s / 60)}m ${rest}s` : `${minutes} min`;
  }
  if (minutes < 60) return `${minutes} min`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return m ? `${h}h ${m}m` : `${h}h`;
}

export function formatLocalTime(iso) {
  const d = parseDate(iso);
  return d ? d.toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) : "";
}

export async function apiError(res, fallback) {
  const body = await res.json().catch(() => ({}));
  if (typeof body.detail === "string") return new Error(body.detail);
  if (res.status === 422) return new Error("The request wasn't valid. Check what you entered and try again.");
  return new Error(fallback);
}

export function toast(message, kind = "info") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.innerHTML = `${icon(kind === "error" ? "x" : "check")}<span>${escapeHtml(message)}</span>`;
  $("toasts").appendChild(el);
  setTimeout(() => {
    el.classList.add("leaving");
    el.addEventListener("animationend", () => el.remove(), { once: true });
  }, kind === "error" ? 6000 : 3500);
}

export function store(key, value) {
  try {
    if (value === undefined) return localStorage.getItem(key);
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch {
    // Storage can be unavailable (private windows, blocked site data).
  }
  return null;
}

export function setBusy(btn, busy, label) {
  if (!btn.dataset.idle) btn.dataset.idle = btn.innerHTML;
  btn.disabled = busy;
  btn.innerHTML = busy ? `<span class="spinner"></span>${escapeHtml(label)}` : btn.dataset.idle;
}

export function isTyping(event) {
  const el = event.target;
  return el instanceof HTMLElement && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
}
