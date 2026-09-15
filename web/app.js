"use strict";

// Read-only view over the lobby API. The lobby is untrusted: this page
// renders records as served and never asserts a verdict — the wasm build of
// the stoffel-verify crate does not compile (see web/README.md), so per the
// issue's fallback the Evidence view shows the bundle and the exact command.

const STATE_ORDER = ["open", "forming", "running", "finished", "failed"];
const $ = (id) => document.getElementById(id);

const baseUrl = () => $("base").value.trim().replace(/\/+$/, "");

async function getJSON(path) {
  const res = await fetch(baseUrl() + path, { headers: { accept: "application/json" } });
  const text = await res.text();
  if (!res.ok) throw new Error(`GET ${path} -> HTTP ${res.status} ${text.slice(0, 300)}`);
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`GET ${path}: response is not JSON (${e.message})`);
  }
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

const short = (hex, n = 16) => hex.length <= n ? hex : `${hex.slice(0, n)}…`;

function lastSeen(unixSec) {
  const d = new Date(unixSec * 1000);
  const diff = Date.now() / 1000 - unixSec;
  const rel =
    diff < -300 ? "in the future" :
    diff < 3600 ? `${Math.max(0, Math.floor(diff / 60))} min ago` :
    diff < 86400 ? `${Math.floor(diff / 3600)} h ago` :
    `${Math.floor(diff / 86400)} d ago`;
  return `${d.toISOString()} (${rel})`;
}

const iso = (unixSec) => new Date(unixSec * 1000).toISOString();

async function sha256HexOf(hexStr) {
  const bytes = new Uint8Array(hexStr.match(/../g).map((h) => parseInt(h, 16)));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function errorBox(err) {
  const box = el("div", "error");
  // A cross-origin lobby fetch dies as a bare TypeError; name the real cause.
  const hint = err instanceof TypeError
    ? "\n\nfetch failed. If this is a cross-origin lobby: the stoffel-lobby service sends no CORS headers — serve this page from the lobby's origin, or proxy it (web/README.md)."
    : "";
  box.textContent = err.message + hint;
  return box;
}

function replace(container, node) {
  container.replaceChildren(node);
}

/* ---------------- nodes ---------------- */

async function renderNodes() {
  const box = $("nodes");
  let nodes;
  try {
    nodes = await getJSON("/nodes");
  } catch (err) {
    return replace(box, errorBox(err));
  }
  if (!Array.isArray(nodes)) {
    return replace(box, errorBox(new Error("GET /nodes did not return an array")));
  }
  const table = el("table");
  const head = el("tr");
  for (const h of ["node", "label", "endpoint", "capabilities", "pubkey", "last seen", "attestation"]) {
    head.appendChild(el("th", undefined, h));
  }
  table.appendChild(head);
  for (const n of nodes) {
    const tr = el("tr");
    const id = el("td", "mono", short(n.node_id));
    id.title = n.node_id;
    tr.appendChild(id);
    tr.appendChild(el("td", undefined, n.operator_label));
    tr.appendChild(el("td", "mono", n.endpoint));
    tr.appendChild(el("td", undefined, `n≤${n.max_parties}, t∈{${(n.supported_thresholds || []).join(",")}}`));
    const pk = el("td", "mono", short(n.pubkey));
    pk.title = n.pubkey;
    tr.appendChild(pk);
    tr.appendChild(el("td", undefined, lastSeen(n.announced_at)));
    const att = el("td");
    // Identifier only — the TDX measurement is established by stoffel-verify.
    const fp = el("div", "mono", "fingerprint…");
    sha256HexOf(n.attestation.quote_hex)
      .then((h) => { fp.textContent = `quote sha256 ${short(h)}`; fp.title = h; })
      .catch(() => { fp.textContent = "quote sha256 unavailable"; });
    att.appendChild(fp);
    att.appendChild(el("div", "muted",
      `quote ${(n.attestation.quote_hex.length / 2).toLocaleString()} B, ` +
      `collateral ${n.attestation.collateral_json.length.toLocaleString()} B, ` +
      `event log ${n.attestation.event_log.length.toLocaleString()} B`));
    tr.appendChild(att);
    table.appendChild(tr);
  }
  replace(box, table);
}

/* ---------------- jobs ---------------- */

function policyBlock(policy) {
  const wrap = el("div", "policy");
  if (!policy.allowed_measurements.length) {
    wrap.appendChild(el("span", "warn",
      "UNCONSTRAINED — no accepted measurements: any code is admitted to this job"));
    wrap.appendChild(el("div", "muted",
      policy.allowed_compose_hashes.length
        ? "compose hashes are still pinned; measurements are not"
        : "neither measurements nor compose hashes are pinned"));
  } else {
    const ul = el("ul");
    for (const m of policy.allowed_measurements) {
      const li = el("li", "mono", short(m));
      li.title = m;
      ul.appendChild(li);
    }
    wrap.appendChild(el("div", "muted", `accepted measurements (${policy.allowed_measurements.length}):`));
    wrap.appendChild(ul);
    if (policy.allowed_compose_hashes.length) {
      wrap.appendChild(el("div", "muted", `+ ${policy.allowed_compose_hashes.length} accepted compose hash(es)`));
    }
  }
  return wrap;
}

async function renderJobs() {
  const box = $("jobs");
  let jobs;
  try {
    jobs = await getJSON("/jobs");
  } catch (err) {
    return replace(box, errorBox(err));
  }
  if (!Array.isArray(jobs)) {
    return replace(box, errorBox(new Error("GET /jobs did not return an array")));
  }
  box.replaceChildren();
  let any = false;
  for (const state of STATE_ORDER) {
    const group = jobs.filter((j) => j.state === state);
    const g = el("div", "group");
    g.appendChild(el("h3", undefined, `${state} `)).appendChild(el("span", "count", `(${group.length})`));
    for (const j of group) {
      any = true;
      const card = el("div", "job");
      const dl = el("dl");
      const rows = [
        ["job", short(j.job_id)],
        ["program", short(j.program_id)],
        ["entry", j.entry],
        ["committee", `n=${j.n_parties}, t=${j.threshold}`],
        ["created", iso(j.created_at)],
      ];
      if (j.not_before !== null && j.not_before !== undefined) {
        rows.push(["not before", iso(j.not_before)]);
      }
      for (const [k, v] of rows) {
        const dt = el("dt", undefined, k);
        const dd = el("dd", "mono", v);
        if (k === "job" || k === "program") dd.title = j.job_id === v ? j.job_id : j.program_id;
        dl.append(dt, dd);
      }
      card.appendChild(dl);
      card.appendChild(policyBlock(j.policy));
      const btn = el("button", undefined, "Evidence →");
      btn.addEventListener("click", () => renderEvidence(j.job_id));
      card.appendChild(btn);
      g.appendChild(card);
    }
    box.appendChild(g);
  }
  const unknown = jobs.filter((j) => !STATE_ORDER.includes(j.state));
  if (unknown.length) {
    box.appendChild(errorBox(new Error(
      `GET /jobs returned records in unknown states: ${unknown.map((j) => j.state).join(", ")}`)));
  }
  if (!any) box.appendChild(el("p", "muted", "no jobs"));
}

/* ---------------- evidence ---------------- */

// The one --at that lies inside every node's collateral validity window,
// so a single `stoffel-verify --at` run covers the whole bundle.
function pinnedAt(bundle) {
  let lo = -Infinity, hi = Infinity;
  const rows = [];
  for (const n of bundle.nodes) {
    const collateral = JSON.parse(n.attestation.collateral_json);
    const tcb = JSON.parse(collateral.tcb_info); // string-in-string, per DCAP V3
    const from = Date.parse(tcb.issueDate) / 1000;
    const to = Date.parse(tcb.nextUpdate) / 1000;
    if (!Number.isFinite(from) || !Number.isFinite(to)) {
      throw new Error(`node ${short(n.node_id)}: collateral has no usable validity window ` +
        `(issueDate ${tcb.issueDate}, nextUpdate ${tcb.nextUpdate})`);
    }
    lo = Math.max(lo, from);
    hi = Math.min(hi, to);
    rows.push([n, tcb]);
  }
  if (lo >= hi) {
    throw new Error("No single verification time lies in every node's collateral window; " +
      "these nodes cannot be verified as one bundle. Windows:\n" +
      rows.map(([n, t]) => `${short(n.node_id)}: ${t.issueDate} .. ${t.nextUpdate}`).join("\n"));
  }
  return { at: Math.floor((lo + hi) / 2), rows };
}

async function renderEvidence(jobId) {
  $("evidence-view").hidden = false;
  const box = $("evidence");
  box.replaceChildren(el("p", "muted", `loading bundle for ${short(jobId)}…`));
  $("evidence-view").scrollIntoView();
  let bundle;
  try {
    bundle = await getJSON(`/jobs/${jobId}/bundle`);
  } catch (err) {
    return replace(box, errorBox(err));
  }
  box.replaceChildren();

  const summary = el("div", "summary");
  const dl = el("dl");
  const values = [...new Set(bundle.results.map((r) => r.value))];
  const rows = [
    ["bundle version", bundle.version],
    ["job", short(bundle.job.job_id)],
    ["committee", `n=${bundle.job.n_parties}, t=${bundle.job.threshold}`],
    ["nodes", bundle.nodes.length],
    ["joins", bundle.joins.length],
    ["results", bundle.results.length],
    ["values reported", values.join(" | ") || "—"],
  ];
  for (const [k, v] of rows) {
    const dd = el("dd", "mono", String(v));
    if (k === "job") dd.title = bundle.job.job_id;
    dl.append(el("dt", undefined, k), dd);
  }
  summary.appendChild(dl);
  box.appendChild(summary);
  box.appendChild(el("p", "note muted",
    "Everything above is what the records claim. Signatures, quotes, policy and agreement " +
    "are checked by stoffel-verify — not by this page."));

  let pinned;
  try {
    pinned = pinnedAt(bundle);
  } catch (err) {
    return box.appendChild(errorBox(err));
  }
  const windowRows = el("table");
  windowRows.appendChild(el("tr"))
    .append(el("th", undefined, "node"), el("th", undefined, "collateral valid from"),
            el("th", undefined, "valid to"));
  for (const [n, t] of pinned.rows) {
    const tr = el("tr");
    const id = el("td", "mono", short(n.node_id));
    id.title = n.node_id;
    tr.append(id, el("td", undefined, t.issueDate), el("td", undefined, t.nextUpdate));
    windowRows.appendChild(tr);
  }
  box.appendChild(windowRows);

  const file = `${jobId.slice(0, 16)}.bundle.json`;
  const command = `stoffel-verify --at ${pinned.at} ${file}`;
  const cmd = el("div", "command");
  const row = el("div", "row");
  row.appendChild(el("code", undefined, command));
  const copy = el("button", undefined, "copy");
  copy.addEventListener("click", () => navigator.clipboard.writeText(command));
  row.appendChild(copy);
  cmd.appendChild(row);
  cmd.appendChild(el("div", "muted",
    `--at ${pinned.at} is pinned inside every node's collateral window above ` +
    `(window midpoint). Download the bundle, save it as ${file}, run the command — ` +
    `stoffel-verify prints the verdict and names the failing link.`));
  box.appendChild(cmd);

  const pretty = JSON.stringify(bundle, null, 2);
  const link = el("a", undefined, `download ${file}`);
  link.href = URL.createObjectURL(new Blob([pretty], { type: "application/json" }));
  link.download = file;
  const details = el("details", undefined);
  details.open = true;
  details.appendChild(el("summary", undefined, "Bundle JSON as served ")).appendChild(link);
  details.appendChild(el("pre", "bundle mono", pretty));
  box.appendChild(details);
}

/* ---------------- wiring ---------------- */

$("controls").addEventListener("submit", (e) => {
  e.preventDefault();
  renderNodes();
  renderJobs();
  $("evidence-view").hidden = true;
  $("evidence").replaceChildren();
});

renderNodes();
renderJobs();

// Deep link: #job=<id> opens that job's evidence view, on load or on later
// hash navigation (a hash change does not reload the page).
const jobInHash = () => location.hash.match(/^#job=([0-9a-f]+)$/);
const m = jobInHash();
if (m) renderEvidence(m[1]);
window.addEventListener("hashchange", () => {
  const h = jobInHash();
  if (h) renderEvidence(h[1]);
});
