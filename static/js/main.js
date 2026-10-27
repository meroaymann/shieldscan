/*
 * ShieldScan frontend
 * - Sends the URL to POST /scan and renders the results dashboard
 * - Security: every value from the scanned site is inserted with textContent (never innerHTML),
 *   so a malicious website can't inject HTML/JS into this page (XSS)
 * - Bonuses: dark mode, Chart.js statistics, CSV export (with formula-injection protection), PDF via print
 */

// ---------- State ----------
const SEVERITIES = ["high", "medium", "low", "info", "pass"];
const SEV_LABEL = { high: "High", medium: "Medium", low: "Low", info: "Info", pass: "Passed" };
const GAUGE_LENGTH = 326.73;   // 2 * PI * r (r = 52)
const SCAN_TIMEOUT_MS = 60000; // give up if the server doesn't answer in 60s

let currentData = null;     // last scan result (used by charts, CSV and PDF)
let currentFindings = [];
let charts = [];
let printState = null;

// ---------- Elements ----------
const root = document.documentElement;
const themeToggle = document.getElementById("themeToggle");
const form = document.getElementById("scanForm");
const urlInput = document.getElementById("urlInput");
const authCheck = document.getElementById("authCheck");
const scanBtn = document.getElementById("scanBtn");
const formError = document.getElementById("formError");
const results = document.getElementById("results");

// ---------- Dark mode ----------
function applyTheme(theme) {
  if (theme === "dark") root.dataset.theme = "dark";
  else delete root.dataset.theme;
  themeToggle.textContent = theme === "dark" ? "☀️" : "🌙";
}

applyTheme(root.dataset.theme === "dark" ? "dark" : "light");

themeToggle.addEventListener("click", () => {
  const next = root.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(next);
  if (currentData) renderCharts(currentData); // redraw charts in the new colors
  try { localStorage.setItem("theme", next); } catch (e) {}
});

// ---------- Scan form ----------
function showError(msg) {
  formError.textContent = msg;
  formError.hidden = false;
}

function hideError() {
  formError.hidden = true;
}

function setLoading(on) {
  scanBtn.disabled = on;
  scanBtn.setAttribute("aria-busy", on ? "true" : "false");
  scanBtn.querySelector(".btn-text").textContent = on ? "Scanning..." : "Scan";
  scanBtn.querySelector(".spinner").hidden = !on;
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  hideError();

  const url = urlInput.value.trim();
  if (!url) return showError("Please enter a website URL.");
  if (!authCheck.checked) return showError("Please confirm you own this website or have permission to test it.");

  setLoading(true);
  results.hidden = true;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

  try {
    const res = await fetch("/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, authorized: true }),
      signal: controller.signal,
    });

    let data;
    try {
      data = await res.json();
    } catch {
      throw new Error("The server returned an unexpected response. Please try again.");
    }

    if (!res.ok) {
      showError(data.error || "Something went wrong. Please try again.");
      return;
    }

    renderResults(data);
  } catch (err) {
    if (err.name === "AbortError") showError("The scan took too long. Please try again.");
    else if (err instanceof TypeError) showError("Couldn't reach the server. Check your connection and try again.");
    else showError(err.message);
  } finally {
    clearTimeout(timer);
    setLoading(false);
  }
});

// ---------- Results dashboard ----------
// Builds elements with textContent only: scanned sites can't inject HTML into our page
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = text;
  return node;
}

function afterPaint(fn) {
  requestAnimationFrame(() => requestAnimationFrame(fn));
}

function levelFor(score) {
  if (score >= 80) return "pass";
  if (score >= 60) return "low";
  if (score >= 40) return "medium";
  return "high";
}

function renderResults(data) {
  currentData = data;
  data.scannedAt = new Date().toLocaleString();
  document.getElementById("scannedUrl").textContent = `${data.final_url} · scanned ${data.scannedAt}`;
  results.hidden = false;

  renderScore(data.score, data.grade, data.summary);
  renderCounts(data.counts);
  renderCategories(data.categories);
  renderSSL(data.ssl);
  renderCharts(data);
  currentFindings = data.findings;
  setFilter("all");

  results.scrollIntoView({ behavior: "smooth" });
}

function renderScore(score, grade, summary) {
  const fill = document.getElementById("gaugeFill");
  const value = document.getElementById("scoreValue");
  const g = grade.toLowerCase();

  fill.setAttribute("class", `gauge-fill stroke-${g}`);
  fill.style.strokeDashoffset = GAUGE_LENGTH;
  afterPaint(() => { fill.style.strokeDashoffset = GAUGE_LENGTH * (1 - score / 100); });

  const start = performance.now();
  function tick(now) {
    const t = Math.min((now - start) / 900, 1);
    value.textContent = Math.round(score * t);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);

  const badge = document.getElementById("gradeBadge");
  badge.textContent = `Grade ${grade}`;
  badge.className = `grade-badge bg-grade-${g}`;
  document.getElementById("scoreSummary").textContent = summary;
}

function renderCounts(counts) {
  document.getElementById("severityCounts").replaceChildren(...SEVERITIES.map((sev) => {
    const item = el("div", `sev-count sev-${sev}`);
    item.append(el("strong", "", counts[sev] || 0), el("span", "", SEV_LABEL[sev]));
    return item;
  }));
}

function renderCategories(categories) {
  document.getElementById("categoryBars").replaceChildren(...categories.map((cat) => {
    const row = el("div", "cat-row");
    const label = el("div", "cat-label");
    label.append(el("span", "", cat.name), el("strong", "", `${cat.score}%`));

    const bar = el("div", "bar");
    const fill = el("div", `bar-fill bg-${levelFor(cat.score)}`);
    bar.append(fill);
    afterPaint(() => { fill.style.width = `${cat.score}%`; });

    row.append(label, bar);
    return row;
  }));
}

function renderSSL(ssl) {
  const rows = [
    ["HTTPS", ssl.https ? "✅ Supported" : "❌ Not supported"],
    ["Certificate", ssl.valid ? "✅ Trusted" : "❌ Not trusted"],
    ["Issuer", ssl.issuer || "—"],
    ["Expires", ssl.expires ? `${ssl.expires} (${ssl.days_left} days)` : "—"],
    ["TLS version", ssl.tls_version ? ssl.tls_version.replace("TLSv", "TLS ") : "—"],
  ];
  document.getElementById("sslInfo").replaceChildren(
    ...rows.flatMap(([key, val]) => [el("dt", "", key), el("dd", "", val)])
  );
}

// ---------- Findings + filters ----------
const FILTERS = {
  all: () => true,
  issues: (f) => f.severity !== "pass",
  pass: (f) => f.severity === "pass",
  ports: (f) => f.category === "Ports",
};

function setFilter(filter) {
  document.querySelectorAll(".filter").forEach((b) =>
    b.classList.toggle("active", b.dataset.filter === filter));

  const list = currentFindings.filter(FILTERS[filter] || FILTERS.all);
  renderFindings(list, filter);
}

function renderFindings(list, filter) {
  const box = document.getElementById("findingsList");
  if (!list.length) {
    box.replaceChildren(el("p", "empty", filter === "issues" ? "No issues found 🎉" : "Nothing to show."));
    return;
  }
  box.replaceChildren(...list.map((f) => {
    const card = el("div", `finding border-${f.severity}`);
    const top = el("div", "finding-top");
    top.append(el("span", `sev-badge sev-${f.severity}`, SEV_LABEL[f.severity]),
               el("span", "cat-tag", f.category));
    card.append(top, el("h4", "", f.title), el("p", "", f.description));

    if (f.recommendation) {
      const fix = el("p", "fix");
      fix.append(el("strong", "", "How to fix: "), document.createTextNode(f.recommendation));
      card.append(fix);
    }
    return card;
  }));
}

document.getElementById("filters").addEventListener("click", (e) => {
  const btn = e.target.closest(".filter");
  if (btn) setFilter(btn.dataset.filter);
});

document.getElementById("newScanBtn").addEventListener("click", () => {
  results.hidden = true;
  hideError();
  window.scrollTo({ top: 0, behavior: "smooth" });
  urlInput.select();
});

// ---------- Charts (Chart.js) ----------
function cssVar(name) {
  return getComputedStyle(root).getPropertyValue(name).trim();
}

function renderCharts(data, animate = true) {
  if (!window.Chart) return; // if the CDN is blocked, the rest of the dashboard still works
  charts.forEach((c) => c.destroy());

  const text = cssVar("--text");
  const muted = cssVar("--muted");
  const border = cssVar("--border");

  charts = [
    new Chart(document.getElementById("severityChart"), {
      type: "doughnut",
      data: {
        labels: SEVERITIES.map((s) => SEV_LABEL[s]),
        datasets: [{
          data: SEVERITIES.map((s) => data.counts[s] || 0),
          backgroundColor: SEVERITIES.map((s) => cssVar(`--sev-${s}`)),
          borderColor: cssVar("--surface"),
          borderWidth: 3,
        }],
      },
      options: {
        animation: animate,
        maintainAspectRatio: false,
        cutout: "62%",
        plugins: { legend: { position: "bottom", labels: { color: text, usePointStyle: true, padding: 14 } } },
      },
    }),
    new Chart(document.getElementById("categoryChart"), {
      type: "bar",
      data: {
        labels: data.categories.map((c) => c.name),
        datasets: [
          { label: "Issues", data: data.categories.map((c) => c.issues),
            backgroundColor: cssVar("--sev-medium"), borderRadius: 6 },
          { label: "Passed", data: data.categories.map((c) => c.passed),
            backgroundColor: cssVar("--sev-pass"), borderRadius: 6 },
        ],
      },
      options: {
        animation: animate,
        maintainAspectRatio: false,
        scales: {
          x: { ticks: { color: muted }, grid: { display: false } },
          y: { beginAtZero: true, ticks: { color: muted, precision: 0 }, grid: { color: border } },
        },
        plugins: { legend: { position: "bottom", labels: { color: text, usePointStyle: true } } },
      },
    }),
  ];
}

// ---------- CSV export ----------
function csvCell(value) {
  let s = String(value ?? "");
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // block spreadsheet formula injection
  return `"${s.replace(/"/g, '""')}"`;
}

function downloadCSV() {
  if (!currentData) return;
  const d = currentData;
  const rows = [
    ["ShieldScan Security Report"],
    ["Website", d.final_url],
    ["Scanned", d.scannedAt],
    ["Score", `${d.score}/100`],
    ["Grade", d.grade],
    [],
    ["Severity", "Category", "Title", "Description", "Recommendation"],
    ...d.findings.map((f) => [SEV_LABEL[f.severity], f.category, f.title, f.description, f.recommendation]),
  ];
  const csv = "\uFEFF" + rows.map((r) => r.map(csvCell).join(",")).join("\r\n"); // BOM so Excel reads UTF-8

  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  link.download = `shieldscan-${d.target.host}-${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

document.getElementById("csvBtn").addEventListener("click", downloadCSV);

// ---------- PDF (print) ----------
window.addEventListener("beforeprint", () => {
  printState = {
    filter: document.querySelector(".filter.active")?.dataset.filter || "all",
    theme: root.dataset.theme === "dark" ? "dark" : "light",
    title: document.title,
  };
  setFilter("all"); // the PDF always includes every finding
  if (currentData) document.title = `ShieldScan report - ${currentData.target.host}`; // PDF file name
  if (printState.theme === "dark") applyTheme("light"); // the PDF is always light
  if (currentData) renderCharts(currentData, false);   // no animation, so the charts print fully drawn
});

window.addEventListener("afterprint", () => {
  if (!printState) return;
  setFilter(printState.filter);
  document.title = printState.title;
  if (printState.theme === "dark") applyTheme("dark");
  if (currentData) renderCharts(currentData, false);
  printState = null;
});

document.getElementById("pdfBtn").addEventListener("click", () => window.print());