"use strict";

// Every request carries the X-CTRE header; the server rejects calls without it,
// which prevents other sites in the browser from driving this local API.
const H = { "X-CTRE": "1" };
const KINDS = [
  { id: "mft", label: "$MFT", hint: "NTFS master file table" },
  { id: "usnjrnl", label: "$UsnJrnl:$J", hint: "NTFS change journal" },
  { id: "pcap", label: ".pcap", hint: "classic packet capture" },
];

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text != null) n.textContent = text; // textContent: never innerHTML
  return n;
};

let state = { files: {}, has_analysis: false };

function setStatus(msg, isError) {
  const s = $("#status");
  s.textContent = msg || "";
  s.classList.toggle("err", !!isError);
}

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { ...H, ...(opts.headers || {}) } });
  const ctype = res.headers.get("Content-Type") || "";
  const data = ctype.includes("json") ? await res.json() : null;
  if (!res.ok) throw new Error((data && data.error) || ("HTTP " + res.status));
  return data;
}

function humanBytes(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB", "TB"];
  let i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + " " + u[i];
}

function renderSlots() {
  const wrap = $("#slots");
  wrap.textContent = "";
  for (const k of KINDS) {
    const info = state.files[k.id];
    const slot = el("div", "slot" + (info ? " loaded" : ""));
    slot.appendChild(el("div", "kind", k.label));
    if (info) {
      slot.appendChild(el("div", "meta", info.name + " · " + humanBytes(info.size)));
      const rm = el("button", "remove", "×");
      rm.title = "Remove";
      rm.addEventListener("click", async (e) => {
        e.preventDefault(); e.stopPropagation();
        await removeKind(k.id);
      });
      slot.appendChild(rm);
    } else {
      slot.appendChild(el("div", "meta", k.hint + " — click or drop"));
    }
    const input = el("input");
    input.type = "file";
    input.addEventListener("change", () => {
      if (input.files[0]) upload(k.id, input.files[0]);
    });
    slot.appendChild(input);
    slot.addEventListener("dragover", (e) => { e.preventDefault(); slot.classList.add("drag"); });
    slot.addEventListener("dragleave", () => slot.classList.remove("drag"));
    slot.addEventListener("drop", (e) => {
      e.preventDefault(); slot.classList.remove("drag");
      if (e.dataTransfer.files[0]) upload(k.id, e.dataTransfer.files[0]);
    });
    wrap.appendChild(slot);
  }
  const any = Object.keys(state.files).length > 0;
  $("#analyze").disabled = !any;
  if (!any) { $("#results").hidden = true; }
}

async function upload(kind, file) {
  setStatus("Uploading " + file.name + "…");
  try {
    const q = "?kind=" + encodeURIComponent(kind) + "&name=" + encodeURIComponent(file.name);
    state = await api("/api/upload" + q, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: file,
    });
    setStatus("Loaded " + file.name);
    renderSlots();
  } catch (err) { setStatus(err.message, true); }
}

async function removeKind(kind) {
  state = await api("/api/remove?kind=" + encodeURIComponent(kind), { method: "POST" });
  setStatus("");
  renderSlots();
}

async function loadSample() {
  setStatus("Generating sample case…");
  try {
    state = await api("/api/sample", { method: "POST" });
    setStatus("Sample case loaded");
    renderSlots();
  } catch (err) { setStatus(err.message, true); }
}

async function analyze() {
  setStatus("Analyzing…");
  $("#analyze").disabled = true;
  const body = {
    min_exfil_bytes: Number($("#min_exfil_bytes").value),
    window_minutes: Number($("#window_minutes").value),
    mft_record_size: Number($("#mft_record_size").value),
  };
  try {
    const data = await api("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    renderResults(data);
    setStatus("Done");
  } catch (err) {
    setStatus(err.message, true);
  } finally {
    $("#analyze").disabled = false;
  }
}

// A plain-language summary built from the actual results, so it is correct
// for any input and doubles as the "what did the engine conclude" narrative.
function renderStory(data) {
  const box = $("#story");
  box.textContent = "";
  const s = data.summary;
  const points = [];

  const parsed = [];
  if (s.mft_entries) parsed.push(s.mft_entries + " MFT entries");
  if (s.usn_records) parsed.push(s.usn_records + " journal records");
  if (s.packets) parsed.push(s.packets + " packets in " + s.flows + " flows");
  if (parsed.length) points.push("Parsed " + parsed.join(", ") + ".");

  if (s.findings) {
    const files = (s.flagged_files || []).join(", ");
    points.push("Flagged timestamp tampering on " + s.findings +
      (s.findings === 1 ? " file" : " findings") +
      (files ? " (" + files + ")" : "") +
      ". The kernel-maintained records disagree with the file's own " +
      "timestamps, which points to backdating.");
  } else {
    points.push("No timestamp tampering was detected.");
  }

  if (s.correlations) {
    points.push("Linked " + s.correlations + " outbound transfer" +
      (s.correlations === 1 ? "" : "s") + " to a disk change within the time " +
      "window. That is the shape of staging a file and sending it out.");
  }

  if (s.timeline_events) {
    points.push("Placed " + s.timeline_events +
      " disk and network events on one timeline, below.");
  }

  if (!points.length) { box.hidden = true; return; }
  const h = el("h4", null, "What the engine found");
  box.appendChild(h);
  const ol = document.createElement("ol");
  for (const p of points) ol.appendChild(el("li", null, p));
  box.appendChild(ol);
  box.hidden = false;
}

function card(num, lbl) {
  const c = el("div", "card");
  c.appendChild(el("div", "num", String(num)));
  c.appendChild(el("div", "lbl", lbl));
  return c;
}

function renderResults(data) {
  $("#results").hidden = false;
  const s = data.summary;
  const sum = $("#summary");
  sum.textContent = "";
  sum.append(
    card(s.mft_entries, "MFT entries"),
    card(s.usn_records, "USN records"),
    card(s.packets, "packets"),
    card(s.flows, "flows"),
    card(s.findings, "findings"),
    card(s.correlations, "correlations"),
  );

  renderStory(data);

  // Findings
  $("#n-findings").textContent = data.findings.length;
  const f = $("#findings");
  f.textContent = "";
  if (!data.findings.length) {
    f.appendChild(el("div", "empty", "No timestomping indicators detected."));
  } else {
    const t = el("table");
    const head = el("tr");
    ["Severity", "File", "Rule", "Explanation"].forEach((h) => head.appendChild(el("th", null, h)));
    t.appendChild(head);
    for (const item of data.findings) {
      const tr = el("tr");
      const sev = el("td");
      sev.appendChild(el("span", "badge sev-" + item.severity, item.severity.toUpperCase()));
      tr.appendChild(sev);
      tr.appendChild(el("td", null, item.name));
      const rule = el("td"); rule.appendChild(el("code", null, item.rule)); tr.appendChild(rule);
      tr.appendChild(el("td", null, item.explanation));
      t.appendChild(tr);
    }
    f.appendChild(t);
  }

  // Correlations
  $("#n-corr").textContent = data.correlations.length;
  const c = $("#correlations");
  c.textContent = "";
  if (!data.correlations.length) {
    c.appendChild(el("div", "empty", "No network/disk exfil correlations found."));
  } else {
    const t = el("table");
    const head = el("tr");
    ["Time (UTC)", "Correlation"].forEach((h) => head.appendChild(el("th", null, h)));
    t.appendChild(head);
    for (const item of data.correlations) {
      const tr = el("tr");
      tr.appendChild(el("td", null, item.time || ""));
      tr.appendChild(el("td", null, item.summary));
      t.appendChild(tr);
    }
    c.appendChild(t);
  }

  // Timeline + filters
  $("#n-timeline").textContent = data.timeline.length;
  renderTimeline(data.timeline);
}

function renderTimeline(events) {
  const sources = Array.from(new Set(events.map((e) => e.source)));
  const filters = $("#filters");
  filters.textContent = "";
  const tableHost = $("#timeline");
  tableHost.textContent = "";

  const t = el("table");
  const head = el("tr");
  ["Time (UTC)", "Source", "Event"].forEach((h) => head.appendChild(el("th", null, h)));
  t.appendChild(head);
  for (const ev of events) {
    const tr = el("tr");
    tr.dataset.source = ev.source;
    tr.appendChild(el("td", null, ev.time || ""));
    const src = el("td");
    src.appendChild(el("span", "tag src-" + ev.source, ev.source));
    tr.appendChild(src);
    tr.appendChild(el("td", null, ev.summary));
    t.appendChild(tr);
  }
  tableHost.appendChild(t);

  for (const src of sources) {
    const lab = el("label");
    const cb = el("input"); cb.type = "checkbox"; cb.checked = true;
    cb.addEventListener("change", () => {
      t.querySelectorAll('tr[data-source="' + src + '"]').forEach((r) => {
        r.style.display = cb.checked ? "" : "none";
      });
    });
    lab.appendChild(cb);
    lab.appendChild(document.createTextNode(" " + src));
    filters.appendChild(lab);
  }
}

$("#sample").addEventListener("click", loadSample);
$("#clear").addEventListener("click", async () => {
  state = await api("/api/remove?kind=all", { method: "POST" });
  setStatus("");
  renderSlots();
});
$("#analyze").addEventListener("click", analyze);

(async function init() {
  try { state = await api("/api/state"); } catch (e) { /* fresh */ }
  renderSlots();
})();
