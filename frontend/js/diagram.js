import { applyAnalysis, hasOwnKey, llmHeaders, openModelDialog } from "./model.js";
import { renderMarkdown } from "./markdown.js";
import { renderReport } from "./report.js";
import { $, API, apiError, setBusy, toast } from "./util.js";

const MAX_BYTES = 8 * 1024 * 1024;
const TYPES = ["image/png", "image/jpeg", "image/webp"];
let diagramFile = null;
let previewUrl = null;

function accept(file) {
  if (!file) return;
  if (!TYPES.includes(file.type)) {
    toast("Use a PNG, JPEG or WebP image.", "error");
    return;
  }
  if (file.size > MAX_BYTES) {
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

async function compare() {
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
  if (!hasOwnKey()) {
    toast("Diagram checks need your own API key.", "error");
    openModelDialog({ preferOwnKey: true });
    return;
  }

  const btn = $("btn-compare");
  setBusy(btn, true, "Comparing");
  const form = new FormData();
  form.append("iac_content", code);
  form.append("file_name", "main.tf");
  form.append("diagram", diagramFile);

  try {
    const res = await fetch(`${API}/audit/diagram`, { method: "POST", body: form, headers: llmHeaders() });
    if (!res.ok) throw await apiError(res, "The comparison failed.");
    const result = await res.json();
    document.dispatchEvent(new CustomEvent("cloudguard:scanned"));
    applyAnalysis(result.analysis);

    const container = $("diagram-report");
    container.innerHTML = `
      <section class="drift">
        <span class="eyebrow">Diagram vs. code</span>
        <h2>What doesn't line up</h2>
        <div class="md">${renderMarkdown(result.diagram_analysis || "No comparison came back. The scan results are below.")}</div>
      </section>
      <div data-scan></div>`;
    renderReport(container.querySelector("[data-scan]"), { ...result, original_code: code });
    container.hidden = false;
    container.scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (err) {
    toast(err.message, "error");
  } finally {
    setBusy(btn, false);
  }
}

export function initDiagram() {
  const drop = $("dropzone");
  $("diagram-file").addEventListener("change", (e) => accept(e.target.files[0]));
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("dragover"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("dragover"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("dragover");
    accept(e.dataTransfer.files[0]);
  });
  $("btn-compare").addEventListener("click", compare);
}
