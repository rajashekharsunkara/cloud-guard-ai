import {
  $, API, apiError, escapeHtml, formatLocalTime, formatWait, plural, setBusy, toast,
} from "./util.js";

/* Own API key settings */

const LLM_STORAGE = "cg-llm";
const providers = { list: [], loaded: false };
let settings = readSettings();

function readSettings() {
  for (const storage of ["localStorage", "sessionStorage"]) {
    try {
      const raw = window[storage].getItem(LLM_STORAGE);
      if (raw) return JSON.parse(raw);
    } catch {
      // Unavailable or corrupt storage just means no saved key.
    }
  }
  return null;
}

function writeSettings(value) {
  for (const storage of ["localStorage", "sessionStorage"]) {
    try { window[storage].removeItem(LLM_STORAGE); } catch { /* ignore */ }
  }
  if (!value) return;
  try {
    window[value.remember ? "localStorage" : "sessionStorage"].setItem(LLM_STORAGE, JSON.stringify(value));
  } catch {
    toast("This browser won't store the key, so it will be forgotten on reload.", "error");
  }
}

export function hasOwnKey() {
  return Boolean(settings);
}

export function llmHeaders() {
  if (!settings) return {};
  return { "X-LLM-Provider": settings.provider, "X-LLM-Model": settings.model, "X-LLM-Key": settings.key };
}

export function providerLabel(id) {
  const found = providers.list.find((p) => p.id === id);
  return found ? found.label : id;
}

async function loadProviders() {
  if (providers.loaded) return;
  const res = await fetch(`${API}/llm/providers`);
  providers.list = await res.json();
  providers.loaded = true;
  $("llm-provider").innerHTML = providers.list
    .map((p) => `<option value="${escapeHtml(p.id)}">${escapeHtml(p.label)}</option>`).join("");
}

function setMode(mode) {
  document.querySelector(`input[name="model-mode"][value="${mode}"]`).checked = true;
  $("own-key-fields").hidden = mode !== "own";
}

function resetModels(message = "Check your key to load models") {
  $("llm-model").innerHTML = `<option value="">${escapeHtml(message)}</option>`;
  $("llm-model").disabled = true;
  $("llm-model-note").textContent = "";
}

function updateKeyLink() {
  const provider = providers.list.find((p) => p.id === $("llm-provider").value);
  $("llm-key-link").href = provider ? provider.key_url : "#";
}

export async function openModelDialog({ preferOwnKey = false } = {}) {
  try {
    await loadProviders();
  } catch {
    toast("Couldn't load the provider list.", "error");
    return;
  }
  setMode(settings || preferOwnKey ? "own" : "free");
  $("btn-forget-key").hidden = !settings;
  if (settings) {
    $("llm-provider").value = settings.provider;
    $("llm-key").value = settings.key;
    $("llm-remember").checked = settings.remember !== false;
    $("llm-model").innerHTML = `<option value="${escapeHtml(settings.model)}">${escapeHtml(settings.model)}</option>`;
    $("llm-model").disabled = false;
  } else {
    $("llm-key").value = "";
    resetModels();
  }
  updateKeyLink();
  $("model-dialog").showModal();
  if (preferOwnKey && !settings) $("llm-key").focus();
}

function describeModel() {
  const option = $("llm-model").selectedOptions[0];
  $("llm-model-note").textContent = option && option.dataset.vision === "false"
    ? "This model can't read images, so it won't work for diagram checks."
    : "";
}

async function checkKey() {
  const provider = $("llm-provider").value;
  const key = $("llm-key").value.trim();
  if (key.length < 8) {
    toast("Paste your API key first.", "error");
    return;
  }
  const btn = $("btn-load-models");
  setBusy(btn, true, "Checking");
  try {
    const res = await fetch(`${API}/llm/models`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-LLM-Key": key },
      body: JSON.stringify({ provider }),
    });
    if (!res.ok) throw await apiError(res, "The key couldn't be checked.");
    const data = await res.json();
    if (!data.models.length) throw new Error("This key has no chat models available.");
    $("llm-model").innerHTML = data.models.map((m) =>
      `<option value="${escapeHtml(m.id)}" data-vision="${m.vision}"${m.id === data.default ? " selected" : ""}>${escapeHtml(m.id)}</option>`).join("");
    $("llm-model").disabled = false;
    describeModel();
    toast(`Key works · ${plural(data.models.length, "model")} available`);
  } catch (err) {
    resetModels();
    toast(err.message, "error");
  } finally {
    setBusy(btn, false);
  }
}

function save(event) {
  event.preventDefault();
  const mode = document.querySelector('input[name="model-mode"]:checked').value;
  if (mode === "free") {
    settings = null;
  } else {
    const model = $("llm-model").value;
    if (!model || $("llm-model").disabled) {
      toast("Check your key and pick a model first.", "error");
      return;
    }
    settings = {
      provider: $("llm-provider").value,
      model,
      key: $("llm-key").value.trim(),
      remember: $("llm-remember").checked,
    };
  }
  writeSettings(settings);
  $("model-dialog").close();
  render();
  toast(settings ? `Using your ${providerLabel(settings.provider)} key` : "Using the free tier");
}

/* Free tier status */

const usage = {
  loaded: false,
  available: false,
  perDay: 0,
  left: 0,
  state: "ok",
  retryUntil: 0,
  resetsAt: null,
};
let ticker = null;

export async function refreshUsage() {
  try {
    const res = await fetch(`${API}/usage`);
    if (!res.ok) return;
    const data = await res.json();
    Object.assign(usage, {
      loaded: true,
      available: data.explanations_available,
      perDay: data.free_scans_per_day,
      left: data.free_scans_left,
      state: data.free_tier_state,
      retryUntil: Date.now() + data.retry_after * 1000,
      resetsAt: data.resets_at,
    });
    $("free-tier-note").textContent = data.explanations_available
      ? `${data.free_scans_per_day} explained scans a day on this site's Groq key.`
      : "Not offered on this server. Scans show Checkov results only.";
  } catch {
    // The status display is optional; scans work without it.
  }
  render();
}

// A finished scan knows the latest numbers without another request.
export function applyAnalysis(analysis) {
  if (!analysis) return;
  if (typeof analysis.free_scans_left === "number" && analysis.mode !== "own_key") {
    usage.left = analysis.free_scans_left;
  }
  const limit = analysis.limit;
  if (limit && (limit.kind === "busy" || limit.kind === "patch_busy")) {
    usage.state = "busy";
    usage.retryUntil = Date.now() + (limit.retry_after || 60) * 1000;
  } else if (limit && limit.kind === "site_daily") {
    usage.state = "exhausted";
    usage.retryUntil = Date.now() + (limit.retry_after || 3600) * 1000;
  }
  render();
}

function secondsLeft() {
  return Math.max(0, Math.round((usage.retryUntil - Date.now()) / 1000));
}

function describe() {
  if (settings) {
    const label = providerLabel(settings.provider);
    return {
      state: "key",
      pill: `${label} · ${settings.model}`,
      hint: `Explained with your <strong>${escapeHtml(label)}</strong> key · ${escapeHtml(settings.model)}`,
      box: null,
    };
  }
  if (!usage.loaded) return { state: "free", pill: "Free tier", hint: "", box: null };
  if (!usage.available) {
    return {
      state: "static",
      pill: "Checkov only",
      hint: "Checkov results only on this server · add your own key for explanations",
      box: { title: "Explanations aren't offered here", text: "Scans show every Checkov finding. Add your own API key to get explanations and patches." },
    };
  }
  const wait = secondsLeft();
  if (usage.state === "busy" && wait > 0) {
    return {
      state: "busy",
      pill: `Free · busy ${formatWait(wait)}`,
      hint: `Free explanations are busy for about <strong>${formatWait(wait)}</strong> · Checkov scans still run`,
      box: { title: "Free model is busy", text: `It's shared by everyone using the site and frees up in about ${formatWait(wait)}. Scans still show every Checkov finding in the meantime.` },
    };
  }
  if (usage.state === "exhausted" && wait > 0) {
    return {
      state: "out",
      pill: "Free · out today",
      hint: `Free explanations are out for today, back in about <strong>${formatWait(wait)}</strong> · Checkov scans stay free`,
      box: { title: "Free explanations are out for today", text: `They come back in about ${formatWait(wait)}. Checkov scans stay free and unlimited until then.` },
    };
  }
  if (usage.left === 0) {
    const at = formatLocalTime(usage.resetsAt);
    return {
      state: "out",
      pill: "Free · 0 left",
      hint: `You've used today's free explained scans · they reset at <strong>${escapeHtml(at)}</strong> · Checkov scans stay free`,
      box: { title: "You've used today's free explained scans", text: `They reset at ${at} your time (midnight UTC). Checkov scans stay free and unlimited.` },
    };
  }
  return {
    state: "free",
    pill: `Free · ${usage.left}/${usage.perDay} today`,
    hint: `<strong>${usage.left} of ${usage.perDay}</strong> free explained scans left today`,
    meter: true,
    box: null,
  };
}

function render() {
  const view = describe();
  const pill = $("plan-pill");
  pill.dataset.state = view.state;
  $("plan-text").textContent = view.pill;
  $("scan-hint").innerHTML = view.hint || "<kbd>Ctrl</kbd> <kbd>Enter</kbd> to scan";

  const box = $("tier-box");
  if (view.box) {
    box.hidden = false;
    box.innerHTML = `
      <p><strong>${escapeHtml(view.box.title)}</strong></p>
      <p>${escapeHtml(view.box.text)}</p>
      <p><button class="link-btn inline" type="button" data-open-key>Use your own API key</button></p>`;
  } else if (view.meter) {
    box.hidden = false;
    box.innerHTML = `
      <span class="eyebrow">Free explained scans today</span>
      <div class="tier-meter" aria-hidden="true">${Array.from({ length: usage.perDay }, (_, i) => `<span class="${i < usage.left ? "on" : ""}"></span>`).join("")}</div>
      <p>${usage.left} of ${usage.perDay} left. Checkov scans are unlimited. <button class="link-btn inline" type="button" data-open-key>Use your own key</button> for no limit.</p>`;
  } else {
    box.hidden = true;
  }

  const counting = !settings && (usage.state === "busy" || usage.state === "exhausted") && secondsLeft() > 0;
  if (counting && !ticker) {
    ticker = setInterval(() => {
      if (secondsLeft() === 0) {
        clearInterval(ticker);
        ticker = null;
        usage.state = "ok";
        refreshUsage();
      } else {
        render();
      }
    }, 1000);
  }
}

export function initModel() {
  settings = readSettings();
  $("plan-pill").addEventListener("click", () => openModelDialog());
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-open-key]")) openModelDialog({ preferOwnKey: true });
    else if (e.target.closest("[data-open-model]")) openModelDialog();
  });
  $("btn-model-cancel").addEventListener("click", () => $("model-dialog").close());
  document.querySelectorAll('input[name="model-mode"]').forEach((radio) => {
    radio.addEventListener("change", () => setMode(radio.value));
  });
  $("llm-provider").addEventListener("change", () => { updateKeyLink(); resetModels(); });
  $("llm-key").addEventListener("input", () => resetModels());
  $("btn-load-models").addEventListener("click", checkKey);
  $("llm-model").addEventListener("change", describeModel);
  $("model-form").addEventListener("submit", save);
  $("btn-forget-key").addEventListener("click", () => {
    settings = null;
    writeSettings(null);
    $("model-dialog").close();
    render();
    toast("Key removed from this browser");
  });
  loadProviders().then(render).catch(() => {});
  refreshUsage();
}
