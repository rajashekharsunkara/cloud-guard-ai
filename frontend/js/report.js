import { handleFold, renderDiff } from "./diff.js";
import {
  SEVERITIES, countBySeverity, escapeHtml, formatDate, formatWait, icon, inlineMarkdown, isTyping,
  plural, riskbar, scoreTone, severityLabel, severityOf, severityRank, toast,
} from "./util.js";

const LIMIT_TITLES = {
  busy: "Free explanations are busy right now",
  patch_busy: "Findings are explained, but the patch wasn't written",
  site_daily: "Free explanations are out for today",
  visitor_daily: "You've used today's free explained scans",
  too_large: "Too much code for the free model",
  unavailable: "Explanations aren't offered on this server",
};

const SOURCE_LABELS = { paste: "Pasted file", zip: "Zip upload", github: "GitHub repository", cli: "Command line" };

export function renderReport(container, result, options = {}) {
  const report = new Report(container, result, options);
  container.__report = report;
  report.render();
  return report;
}

class Report {
  constructor(el, result, options) {
    this.el = el;
    this.result = result;
    this.options = options;
    this.analysis = result.analysis || {};
    this.findings = (result.vulnerabilities || []).map((f, i) => ({ ...f, _id: i, sev: severityOf(f.severity) }));
    this.sources = this.collectSources();
    this.patches = this.collectPatches();

    const placeable = (f) => this.sources[f.file] !== undefined && Number(f.line_start) > 0;
    this.placed = this.findings.filter(placeable);
    this.unplaced = this.findings.filter((f) => !placeable(f)).sort((a, b) => severityRank(a) - severityRank(b));
    this.files = this.orderFiles();
    this.order = this.files.flatMap((file) => this.findingsIn(file));

    this.file = this.files[0] || null;
    this.view = "code";
    this.activeId = null;
    this.open = new Set();
    const first = this.order[0];
    if (first && this.explained()) this.open.add(first._id);
    this.activeId = first ? first._id : null;

    this.onKey = this.onKey.bind(this);
    document.addEventListener("keydown", this.onKey);
  }

  collectSources() {
    const sources = { ...(this.result.sources || {}) };
    if (!Object.keys(sources).length && this.result.original_code) {
      const path = (this.result.files && this.result.files[0]) || this.result.file_name || "main.tf";
      sources[path] = this.result.original_code;
    }
    return sources;
  }

  collectPatches() {
    const patches = {};
    (this.result.patches || []).forEach((p) => { patches[p.file] = p; });
    const paths = Object.keys(this.sources);
    if (!Object.keys(patches).length && this.result.patched_code && paths.length === 1) {
      patches[paths[0]] = { file: paths[0], original: this.sources[paths[0]], patched: this.result.patched_code };
    }
    return patches;
  }

  orderFiles() {
    const stats = {};
    this.placed.forEach((f) => {
      const s = stats[f.file] || (stats[f.file] = { worst: 4, count: 0 });
      s.worst = Math.min(s.worst, severityRank(f));
      s.count += 1;
    });
    const files = Object.keys(stats).sort((a, b) =>
      stats[a].worst - stats[b].worst || stats[b].count - stats[a].count || a.localeCompare(b));
    Object.keys(this.patches).forEach((path) => {
      if (!files.includes(path) && this.sources[path] !== undefined) files.push(path);
    });
    return files;
  }

  findingsIn(file) {
    return this.placed.filter((f) => f.file === file)
      .sort((a, b) => a.line_start - b.line_start || severityRank(a) - severityRank(b));
  }

  explained() {
    return this.analysis.mode && this.analysis.mode !== "static";
  }

  /* Rendering */

  render() {
    const hasFindings = this.findings.length > 0;
    this.el.innerHTML = `
      ${this.head()}
      ${this.callouts()}
      ${this.files.length ? this.review() : ""}
      ${this.unplacedSection()}
      ${hasFindings || this.files.length ? "" : this.clean()}`;
    if (this.files.length) this.renderSheet();
    this.bind();
  }

  summary() {
    const checks = this.findings.filter((f) => f.source === "checkov").length;
    const review = this.findings.length - checks;
    if (this.result.security_score === null || this.result.security_score === undefined) {
      const found = this.findings.length ? `${plural(this.findings.length, "finding")} from the review. ` : "";
      return `${found}Checkov doesn't cover these file types, so there's no score.`;
    }
    if (!this.findings.length) return "Every Checkov policy that applies passed.";
    const counts = countBySeverity(this.findings);
    const lead = counts.critical || counts.high
      ? "Fix the critical and high ones before deploying."
      : "Nothing serious, but worth tidying up.";
    const extra = review ? ` and ${review} more from the review` : "";
    return `${plural(checks, "Checkov finding")}${extra}. ${lead}`;
  }

  head() {
    const r = this.result;
    const counts = countBySeverity(this.findings);
    const score = r.security_score;
    const scored = score !== null && score !== undefined;
    const source = SOURCE_LABELS[this.analysis.source] || "Scan";
    const when = r.created_at ? formatDate(r.created_at) : "Just now";
    const meta = [];
    if ((r.files || []).length > 1) meta.push(plural(r.files.length, "file") + " scanned");
    if (this.analysis.checkov_version) meta.push(`Checkov ${escapeHtml(this.analysis.checkov_version)}`);
    if (this.analysis.model) {
      const whose = this.analysis.mode === "own_key" ? "your key" : "free tier";
      meta.push(`Explained by ${escapeHtml(this.analysis.model.provider)} ${escapeHtml(this.analysis.model.model)} (${whose})`);
    } else {
      meta.push("Checkov results only");
    }
    return `
      <header class="report-head">
        <div>
          <span class="eyebrow">${escapeHtml(source)} · ${escapeHtml(when)}${r.audit_id ? ` · ${escapeHtml(r.audit_id)}` : ""}</span>
          <h2>${escapeHtml(r.file_name || "main.tf")}</h2>
          <p class="report-sub">${escapeHtml(this.summary())}</p>
          <p class="report-meta">${meta.join(" · ")}</p>
        </div>
        <div class="scorecard" data-tone="${scoreTone(scored ? score : null)}">
          <div class="score-figure" aria-label="${scored ? `Score ${score} out of 100` : "Not scored"}">
            <span class="score-num">${scored ? score : "Not scored"}</span>${scored ? `<span class="score-of">/100</span>` : ""}
          </div>
          ${riskbar(counts)}
          <ul class="sev-legend">${SEVERITIES.map((s) => `<li><span class="swatch sev-${s}"></span>${counts[s]} ${s}</li>`).join("")}</ul>
        </div>
      </header>`;
  }

  callouts() {
    const limit = this.analysis.limit;
    const notices = [...(this.analysis.notices || [])];
    const parts = [];
    if (limit) {
      const message = limit.message || notices[0] || "";
      const index = notices.indexOf(message);
      if (index >= 0) notices.splice(index, 1);
      parts.push(this.limitCallout(limit, message));
    }
    notices.forEach((notice) => {
      // Failures with the visitor's own key start with "Your <provider> key/account".
      const keyProblem = /^Your .+ (key|account)/.test(notice);
      parts.push(`
        <div class="callout" data-kind="${keyProblem ? "error" : "info"}">
          <div class="callout-body"><p>${escapeHtml(notice)}</p></div>
          ${keyProblem ? `<div class="callout-actions"><button class="btn btn-quiet btn-sm" type="button" data-open-model>Model settings</button></div>` : ""}
        </div>`);
    });
    return parts.join("");
  }

  limitCallout(limit, message) {
    const actions = [];
    const retryable = (limit.kind === "busy" || limit.kind === "patch_busy") && this.options.onRetry;
    if (retryable) {
      this.retryAt = Date.now() + (limit.retry_after || 60) * 1000;
      actions.push(`<button class="btn btn-quiet btn-sm" type="button" data-retry disabled>${icon("refresh")}<span>Scan again</span></button>`);
    }
    actions.push(`<button class="btn btn-primary btn-sm" type="button" data-open-key>Use your own API key</button>`);
    return `
      <div class="callout" data-kind="${escapeHtml(limit.kind)}">
        <div class="callout-body">
          <strong>${escapeHtml(LIMIT_TITLES[limit.kind] || "Explanations weren't included")}</strong>
          <p>${escapeHtml(message)}</p>
        </div>
        <div class="callout-actions">${actions.join("")}</div>
      </div>`;
  }

  review() {
    const rail = this.files.map((file) => {
      const counts = countBySeverity(this.findingsIn(file));
      const badges = SEVERITIES.filter((s) => counts[s]).map((s) => `<span class="sev-${s}">${counts[s]}</span>`).join("");
      return `<li><button class="rail-file" type="button" data-file="${escapeHtml(file)}" aria-current="${file === this.file}">
        <span class="rail-path" title="${escapeHtml(file)}">${escapeHtml(file)}</span>
        <span class="rail-counts">${badges || `<span class="sev-low">patch</span>`}</span>
      </button></li>`;
    }).join("");
    return `
      <div class="review">
        <nav class="rail" aria-label="Files with findings">
          <span class="eyebrow">${plural(this.files.length, "file")}</span>
          <ul class="rail-list">${rail}</ul>
          <p class="rail-note">Step through findings with <kbd>j</kbd> and <kbd>k</kbd>.</p>
        </nav>
        <div class="sheet" data-sheet></div>
        <div class="minimap" data-minimap aria-hidden="true"></div>
      </div>`;
  }

  unplacedSection() {
    if (!this.unplaced.length) return "";
    const items = this.unplaced.map((f) => `
      <li>
        <span class="sev sev-${f.sev}">${severityLabel(f.sev)}</span>
        <div>
          <div class="title">${inlineMarkdown(f.title || "Untitled finding")}</div>
          ${f.description ? `<p>${inlineMarkdown(f.description)}</p>` : ""}
          ${f.remediation ? `<p><strong>Fix:</strong> ${inlineMarkdown(f.remediation)}</p>` : ""}
          <div class="where">${escapeHtml([f.check_id || "review", f.file, f.resource].filter(Boolean).join(" · "))}</div>
        </div>
      </li>`).join("");
    const heading = this.files.length ? "Other findings" : "Findings";
    const note = this.files.length
      ? "These aren't tied to a line in the files above, usually because the review found them in a file that wasn't kept or a setting that spans files."
      : "These findings don't point at specific lines.";
    return `<section class="unplaced"><h3>${heading}</h3><p>${note}</p><ul class="unplaced-list">${items}</ul></section>`;
  }

  clean() {
    const covered = (this.analysis.covered_files || []).length > 0 || this.result.security_score !== null;
    return `
      <div class="sheet"><div class="sheet-empty">
        <h3>${covered ? "No findings" : "Nothing to report"}</h3>
        <p>${covered
          ? "Every Checkov policy that applies to these files passed. That's a good sign, not proof they're secure."
          : "Checkov doesn't cover these file types and the review didn't flag anything."}</p>
      </div></div>`;
  }

  renderSheet() {
    const sheet = this.el.querySelector("[data-sheet]");
    const patch = this.patches[this.file];
    const index = this.order.findIndex((f) => f._id === this.activeId);
    const patchTitle = patch ? "" : (this.explained() ? "No patch was written for this file" : "Patches come with explained scans");
    const tools = this.view === "patch" && patch
      ? `<button class="btn btn-quiet btn-sm" type="button" data-action="copy">${icon("copy")}Copy</button>
         <button class="btn btn-quiet btn-sm" type="button" data-action="download">${icon("download")}Download</button>`
      : "";
    sheet.innerHTML = `
      <div class="sheet-bar">
        <span class="sheet-path">${escapeHtml(this.file)}</span>
        <span class="spacer"></span>
        ${this.order.length ? `<span class="finding-nav">
          <button class="icon-btn" type="button" data-nav="-1" aria-label="Previous finding">${icon("up")}</button>
          <span>${index >= 0 ? index + 1 : "–"} / ${this.order.length}</span>
          <button class="icon-btn" type="button" data-nav="1" aria-label="Next finding">${icon("down")}</button>
        </span>` : ""}
        <div class="segmented" role="group" aria-label="View">
          <button type="button" data-view="code" aria-pressed="${this.view === "code"}">Annotated</button>
          <button type="button" data-view="patch" aria-pressed="${this.view === "patch"}" ${patch ? "" : "disabled"} title="${escapeHtml(patchTitle)}">Patch</button>
        </div>
        ${tools}
      </div>
      <div class="sheet-body">${this.view === "patch" && patch ? this.patchView(patch) : this.codeView()}</div>`;
    this.renderMinimap();
    this.highlight();
    this.trackWidth(sheet.querySelector(".sheet-body"));
  }

  // Notes live inside the code table, which grows with long lines; keeping
  // them the width of the visible sheet stops them sliding off to the right.
  trackWidth(body) {
    if (!body) return;
    const apply = () => body.style.setProperty("--sheet-w", `${body.clientWidth}px`);
    apply();
    if (this.resizeObserver) this.resizeObserver.disconnect();
    this.resizeObserver = new ResizeObserver(apply);
    this.resizeObserver.observe(body);
  }

  codeView() {
    const source = this.sources[this.file] || "";
    const lines = source.replace(/\n$/, "").split("\n");
    const byLine = new Map();
    this.findingsIn(this.file).forEach((f) => {
      const line = Math.min(Number(f.line_start), lines.length);
      if (!byLine.has(line)) byLine.set(line, []);
      byLine.get(line).push(f);
    });

    const rows = lines.map((text, i) => {
      const n = i + 1;
      const here = byLine.get(n);
      if (!here) {
        return `<tr class="line" data-line="${n}"><td class="ln">${n}</td><td class="pin-cell"></td><td class="src">${escapeHtml(text) || " "}</td></tr>`;
      }
      here.sort((a, b) => severityRank(a) - severityRank(b));
      const worst = here[0].sev;
      return `<tr class="line" data-line="${n}"><td class="ln">${n}</td><td class="pin-cell"><button class="pin sev-${worst}" type="button" data-pin="${here[0]._id}" aria-label="${plural(here.length, "finding")} on line ${n}"></button></td><td class="src">${escapeHtml(text) || " "}</td></tr>${this.noteRow(here)}`;
    }).join("");
    return `<table class="code"><tbody>${rows}</tbody></table>`;
  }

  noteRow(findings) {
    const first = findings[0];
    const range = first.line_end && first.line_end !== first.line_start
      ? `lines ${first.line_start}–${first.line_end}` : `line ${first.line_start}`;
    const items = findings.map((f) => this.noteItem(f)).join("");
    return `
      <tr class="note-row"><td colspan="3"><div class="note-wrap"><div class="note">
        <div class="note-head"><strong>${escapeHtml(first.resource || this.file)}</strong><span>${range}</span><span class="spacer"></span><span>${plural(findings.length, "finding")}</span></div>
        ${items}
      </div></div></td></tr>`;
  }

  noteItem(f) {
    const open = this.open.has(f._id);
    let body;
    if (f.description) {
      body = `<p>${inlineMarkdown(f.description)}</p>`;
      if (f.remediation) body += `<h4>Fix</h4><p>${inlineMarkdown(f.remediation)}</p>`;
    } else {
      body = `<p class="muted">${this.explained()
        ? "No explanation came back for this one. The check name describes what failed."
        : "This scan ran Checkov only, so there's no explanation. The check name describes what failed."}</p>`;
    }
    if (f.source === "review") {
      body += `<p class="muted">Found by the review rather than a Checkov policy, so it isn't counted in the score. Double-check it.</p>`;
    }
    return `
      <div class="note-item" data-id="${f._id}" data-open="${open}" data-active="${f._id === this.activeId}">
        <button type="button" data-toggle="${f._id}" aria-expanded="${open}">
          <span class="sev sev-${f.sev}">${severityLabel(f.sev)}</span>
          <span class="note-title">${inlineMarkdown(f.title || "Untitled finding")}</span>
          <span class="note-check">${escapeHtml(f.check_id || "review")}</span>
          ${icon("chevron")}
        </button>
        <div class="note-detail" ${open ? "" : "hidden"}>${body}</div>
      </div>`;
  }

  patchView(patch) {
    const diff = renderDiff(patch.original, patch.patched);
    return `
      <div class="diff-bar">
        <span class="diff-stats">${diff.stats ? `${diff.stats} lines` : "Patched file"}</span>
        <span class="field-help">Read it through and run <code>terraform plan</code> before applying.</span>
      </div>
      ${diff.html}`;
  }

  renderMinimap() {
    const map = this.el.querySelector("[data-minimap]");
    if (!map) return;
    if (this.view !== "code") {
      map.innerHTML = "";
      return;
    }
    const total = Math.max(1, (this.sources[this.file] || "").split("\n").length);
    const worstByLine = new Map();
    this.findingsIn(this.file).forEach((f) => {
      const prev = worstByLine.get(f.line_start);
      if (!prev || severityRank(f) < severityRank(prev)) worstByLine.set(f.line_start, f);
    });
    map.innerHTML = [...worstByLine.values()].map((f) =>
      `<button class="sev-${f.sev}" type="button" tabindex="-1" data-pin="${f._id}" style="top:calc(${((f.line_start - 1) / total) * 100}% - 2px)" title="Line ${f.line_start}"></button>`).join("");
  }

  /* Behaviour */

  highlight() {
    const sheet = this.el.querySelector("[data-sheet]");
    if (!sheet) return;
    sheet.querySelectorAll("tr.line.hl").forEach((row) => row.classList.remove("hl"));
    const active = this.findings[this.activeId];
    if (!active || active.file !== this.file || this.view !== "code") return;
    const end = Number(active.line_end) || Number(active.line_start);
    for (let n = Number(active.line_start); n <= end; n++) {
      const row = sheet.querySelector(`tr.line[data-line="${n}"]`);
      if (row) row.classList.add("hl");
    }
  }

  activate(id, { openIt = true, scroll = true } = {}) {
    const finding = this.findings[id];
    if (!finding) return;
    this.activeId = id;
    if (openIt) this.open.add(id);
    const changedFile = finding.file !== this.file || this.view !== "code";
    if (changedFile) {
      this.file = finding.file;
      this.view = "code";
      this.el.querySelectorAll("[data-file]").forEach((b) => b.setAttribute("aria-current", String(b.dataset.file === this.file)));
    }
    this.renderSheet();
    if (scroll) {
      const item = this.el.querySelector(`.note-item[data-id="${id}"]`);
      if (item) item.scrollIntoView({ block: "center", behavior: changedFile ? "auto" : "smooth" });
    }
  }

  step(delta) {
    if (!this.order.length) return;
    const index = this.order.findIndex((f) => f._id === this.activeId);
    const next = this.order[(index + delta + this.order.length) % this.order.length];
    this.activate(next._id);
  }

  toggle(id) {
    if (this.open.has(id) && this.activeId === id) this.open.delete(id);
    else this.open.add(id);
    this.activate(id, { openIt: false, scroll: false });
  }

  async copyPatch() {
    try {
      await navigator.clipboard.writeText(this.patches[this.file].patched);
      toast("Patched file copied");
    } catch {
      toast("Couldn't access the clipboard.", "error");
    }
  }

  downloadPatch() {
    const patch = this.patches[this.file];
    const name = this.file.split("/").pop() || "patched";
    const dot = name.lastIndexOf(".");
    const url = URL.createObjectURL(new Blob([patch.patched], { type: "text/plain" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = dot > 0 ? `${name.slice(0, dot)}.patched${name.slice(dot)}` : `${name}.patched`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  bind() {
    this.el.onclick = (e) => {
      if (handleFold(e)) return;
      const target = e.target.closest("[data-file],[data-pin],[data-toggle],[data-nav],[data-view],[data-action],[data-retry]");
      if (!target) return;
      const d = target.dataset;
      if (d.file !== undefined) {
        this.file = d.file;
        this.view = "code";
        const first = this.findingsIn(this.file)[0];
        this.el.querySelectorAll("[data-file]").forEach((b) => b.setAttribute("aria-current", String(b.dataset.file === this.file)));
        if (first) this.activate(first._id, { openIt: this.explained() });
        else this.renderSheet();
      } else if (d.pin !== undefined) {
        this.activate(Number(d.pin));
      } else if (d.toggle !== undefined) {
        this.toggle(Number(d.toggle));
      } else if (d.nav !== undefined) {
        this.step(Number(d.nav));
      } else if (d.view !== undefined) {
        this.view = d.view;
        this.renderSheet();
      } else if (d.action === "copy") {
        this.copyPatch();
      } else if (d.action === "download") {
        this.downloadPatch();
      } else if (d.retry !== undefined && !target.disabled) {
        this.options.onRetry();
      }
    };
    this.startRetryCountdown();
  }

  startRetryCountdown() {
    const button = this.el.querySelector("[data-retry]");
    if (!button) return;
    const label = button.querySelector("span");
    const tick = () => {
      if (this.el.__report !== this || !button.isConnected) return;
      const left = Math.round((this.retryAt - Date.now()) / 1000);
      if (left > 0) {
        label.textContent = `Scan again in ${formatWait(left)}`;
        setTimeout(tick, 1000);
      } else {
        label.textContent = "Scan again";
        button.disabled = false;
      }
    };
    tick();
  }

  onKey(e) {
    if (this.el.__report !== this) {
      document.removeEventListener("keydown", this.onKey);
      return;
    }
    if (isTyping(e) || e.metaKey || e.ctrlKey || e.altKey || !this.el.offsetParent) return;
    if (document.querySelector("dialog[open]")) return;
    if (e.key === "j") { e.preventDefault(); this.step(1); }
    if (e.key === "k") { e.preventDefault(); this.step(-1); }
  }
}
