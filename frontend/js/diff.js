import { escapeHtml, plural } from "./util.js";

const CONTEXT = 3;

export function diffLines(a, b) {
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

function row(op, a, b) {
  const sign = op.type === "add" ? "+" : op.type === "del" ? "−" : "";
  const text = op.type === "add" ? b[op.b] : a[op.a];
  return `<tr class="${op.type}"><td class="ln">${op.type === "add" ? "" : op.a + 1}</td><td class="ln">${op.type === "del" ? "" : op.b + 1}</td><td class="sign">${sign}</td><td class="code-cell">${escapeHtml(text)}</td></tr>`;
}

function table(ops, a, b) {
  const parts = [];
  let run = [];
  const flush = (atStart, atEnd) => {
    const keepHead = atStart ? 0 : CONTEXT;
    const keepTail = atEnd ? 0 : CONTEXT;
    if (run.length <= keepHead + keepTail + 2) {
      parts.push(`<tbody>${run.map((op) => row(op, a, b)).join("")}</tbody>`);
    } else {
      const hidden = run.slice(keepHead, run.length - keepTail);
      if (keepHead) parts.push(`<tbody>${run.slice(0, keepHead).map((op) => row(op, a, b)).join("")}</tbody>`);
      parts.push(`<tbody class="fold"><tr><td colspan="4"><button class="fold-btn" type="button">Show ${plural(hidden.length, "unchanged line")}</button></td></tr></tbody>`);
      parts.push(`<tbody hidden>${hidden.map((op) => row(op, a, b)).join("")}</tbody>`);
      if (keepTail) parts.push(`<tbody>${run.slice(run.length - keepTail).map((op) => row(op, a, b)).join("")}</tbody>`);
    }
    run = [];
  };

  let sawChange = false;
  ops.forEach((op) => {
    if (op.type === "same") {
      run.push(op);
      return;
    }
    if (run.length) flush(!sawChange, false);
    sawChange = true;
    parts.push(`<tbody>${row(op, a, b)}</tbody>`);
  });
  if (run.length) flush(!sawChange, true);
  return `<table>${parts.join("")}</table>`;
}

// Returns { stats, html } for a patch shown against its original.
export function renderDiff(original, patched) {
  const a = String(original || "").replace(/\n$/, "").split("\n");
  const b = String(patched || "").replace(/\n$/, "").split("\n");
  const ops = original ? diffLines(a, b) : null;
  if (!ops) {
    return { stats: "", html: `<pre class="plain-code">${escapeHtml(patched)}</pre>` };
  }
  const added = ops.filter((o) => o.type === "add").length;
  const removed = ops.filter((o) => o.type === "del").length;
  return {
    stats: `<span class="plus">+${added}</span> <span class="minus">−${removed}</span>`,
    html: `<div class="diff">${table(ops, a, b)}</div>`,
  };
}

export function handleFold(event) {
  const fold = event.target.closest(".fold-btn");
  if (!fold) return false;
  const tbody = fold.closest("tbody");
  tbody.nextElementSibling.hidden = false;
  tbody.remove();
  return true;
}
