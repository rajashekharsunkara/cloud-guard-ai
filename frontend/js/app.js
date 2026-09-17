import { initDiagram } from "./diagram.js";
import { initHistory, showDetail, showIndex } from "./history.js";
import { initModel } from "./model.js";
import { initScan, showScanForm, showScanResult } from "./scan.js";
import { $, API, store } from "./util.js";

/* Theme */

function syncThemeButton() {
  const dark = document.documentElement.dataset.theme === "dark";
  $("theme-toggle").setAttribute("aria-label", dark ? "Switch to light theme" : "Switch to dark theme");
  document.querySelector('meta[name="theme-color"]').content = dark ? "#13120e" : "#f3f0e8";
}

$("theme-toggle").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = next;
  store("cg-theme", next);
  syncThemeButton();
});

/* Service status */

async function checkHealth() {
  const el = $("status");
  const text = el.querySelector(".status-text");
  try {
    const res = await fetch(`${API}/health`);
    const data = await res.json();
    const healthy = data.status === "healthy";
    el.dataset.state = healthy ? "ok" : "degraded";
    text.textContent = healthy ? "All systems normal" : "Degraded";
    el.title = `Database ${data.database}, storage ${data.s3}`;
  } catch {
    el.dataset.state = "down";
    text.textContent = "API unreachable";
  }
}

/* Routing */

const VIEWS = ["scan", "diagram", "history", "how"];

function route() {
  const [name, param] = location.hash.replace(/^#/, "").split("/");
  const view = VIEWS.includes(name) ? name : "scan";
  VIEWS.forEach((v) => { $(`view-${v}`).hidden = v !== view; });
  document.querySelectorAll(".nav a").forEach((a) => {
    if (a.dataset.route === view) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  const title = $(`view-${view}`).dataset.title;
  document.title = view === "scan" ? "CloudGuard" : `${title} · CloudGuard`;
  if (view === "scan") {
    if (param) {
      document.title = "Scan result · CloudGuard";
      showScanResult(decodeURIComponent(param));
    } else {
      showScanForm();
    }
  }
  if (view === "history") {
    if (param) showDetail(param);
    else showIndex();
  }
}

window.addEventListener("hashchange", () => {
  route();
  window.scrollTo(0, 0);
});

// Guide links scroll within the page without changing the route.
document.addEventListener("click", (e) => {
  const jump = e.target.closest("[data-jump]");
  if (!jump) return;
  e.preventDefault();
  $(jump.dataset.jump).scrollIntoView({ behavior: "smooth", block: "start" });
});

syncThemeButton();
initModel();
initScan();
initDiagram();
initHistory();
route();
checkHealth();
setInterval(checkHealth, 60000);
