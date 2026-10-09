import { decodeFrame, hexToBytes } from "./decode.js";

const $ = (sel) => document.querySelector(sel);

const state = {
  packets: [],
  selected: 0,
  activeLayer: null,
};

const fileInput = $("#file");
const listEl = $("#list");
const layersEl = $("#layers");
const hexEl = $("#hex");
const metaEl = $("#meta");
const dropEl = $("#drop");

fileInput.addEventListener("change", async (e) => {
  const f = e.target.files?.[0];
  if (f) await loadFile(f);
});

["dragenter", "dragover"].forEach((ev) => {
  dropEl.addEventListener(ev, (e) => {
    e.preventDefault();
    dropEl.classList.add("drag");
  });
});
["dragleave", "drop"].forEach((ev) => {
  dropEl.addEventListener(ev, (e) => {
    e.preventDefault();
    dropEl.classList.remove("drag");
  });
});
dropEl.addEventListener("drop", async (e) => {
  const f = e.dataTransfer?.files?.[0];
  if (f) await loadFile(f);
});

async function loadFile(file) {
  const text = await file.text();
  if (file.name.endsWith(".pcap") || looksPcap(text)) {
    metaEl.textContent = "Open the .jsonl capture (PCAP is for Wireshark).";
    return;
  }
  const packets = parseJSONL(text);
  if (!packets.length) {
    metaEl.textContent = "No packets in file.";
    return;
  }
  state.packets = packets.map((p, i) => {
    const bytes = hexToBytes(p.data);
    const decoded = decodeFrame(bytes);
    return { ...p, i, bytes, decoded };
  });
  state.selected = 0;
  state.activeLayer = null;
  metaEl.textContent = `${file.name} · ${state.packets.length} packets`;
  renderList();
  select(0);
}

function looksPcap(s) {
  // binary garbage when read as text
  return s.length > 4 && s.charCodeAt(0) === 0xd4;
}

function parseJSONL(text) {
  return text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => JSON.parse(l));
}

function renderList() {
  listEl.innerHTML = "";
  for (const p of state.packets) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "pkt" + (p.i === state.selected ? " active" : "");
    row.innerHTML = `
      <span class="n">${p.n}</span>
      <span class="dir ${p.dir}">${p.dir}</span>
      <span class="proto">${escapeHtml(p.decoded.proto)}</span>
      <span class="sum">${escapeHtml(p.decoded.summary)}</span>
      <span class="len">${p.bytes.length}B</span>`;
    row.addEventListener("click", () => select(p.i));
    listEl.appendChild(row);
  }
}

function select(i) {
  state.selected = i;
  state.activeLayer = null;
  renderList();
  const p = state.packets[i];
  if (!p) return;
  renderLayers(p);
  renderHex(p, null);
}

function renderLayers(p) {
  layersEl.innerHTML = "";
  for (const layer of p.decoded.layers) {
    const el = document.createElement("button");
    el.type = "button";
    el.className =
      "layer" + (state.activeLayer === layer.id ? " active" : "");
    el.style.setProperty("--accent", layer.color);
    el.innerHTML = `
      <span class="lname">${escapeHtml(layer.name)}</span>
      <span class="lsum">${escapeHtml(layer.summary)}</span>
      <span class="loff">${layer.start}…${layer.end}</span>`;
    if (layer.detail) {
      const pre = document.createElement("pre");
      pre.className = "ldetail";
      pre.textContent = layer.detail;
      el.appendChild(pre);
    }
    el.addEventListener("click", () => {
      state.activeLayer = layer.id;
      renderLayers(p);
      renderHex(p, layer);
    });
    layersEl.appendChild(el);
  }
}

function renderHex(p, highlight) {
  const bytes = p.bytes;
  const cols = 16;
  let html = "";
  for (let i = 0; i < bytes.length; i += cols) {
    const end = Math.min(i + cols, bytes.length);
    let hex = "";
    let asc = "";
    for (let j = i; j < i + cols; j++) {
      if (j < end) {
        const b = bytes[j];
        const on =
          highlight && j >= highlight.start && j < highlight.end
            ? " on"
            : "";
        const layerClass = layerClassAt(p, j);
        hex += `<span class="b${on} ${layerClass}" data-i="${j}">${b
          .toString(16)
          .padStart(2, "0")}</span>`;
        asc += `<span class="b${on} ${layerClass}">${
          b >= 0x20 && b <= 0x7e ? escapeHtml(String.fromCharCode(b)) : "."
        }</span>`;
      } else {
        hex += `<span class="b pad">  </span>`;
      }
      if (j === i + 7) hex += " ";
    }
    html += `<div class="row"><span class="off">${i
      .toString(16)
      .padStart(4, "0")}</span><span class="hx">${hex}</span><span class="asc">${asc}</span></div>`;
  }
  hexEl.innerHTML = html;

  hexEl.querySelectorAll(".b[data-i]").forEach((el) => {
    el.addEventListener("mouseenter", () => {
      const idx = Number(el.dataset.i);
      const layer = p.decoded.layers.find((l) => idx >= l.start && idx < l.end);
      if (layer && state.activeLayer !== layer.id) {
        state.activeLayer = layer.id;
        renderLayers(p);
        renderHex(p, layer);
      }
    });
  });
}

function layerClassAt(p, i) {
  for (let k = p.decoded.layers.length - 1; k >= 0; k--) {
    const l = p.decoded.layers[k];
    if (i >= l.start && i < l.end) return `lc-${l.id}`;
  }
  return "";
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// Try loading default capture if served from repo root / mytcp
async function tryDefault() {
  try {
    const res = await fetch("../captures/latest.jsonl");
    if (!res.ok) return;
    const text = await res.text();
    const fake = new File([text], "latest.jsonl", { type: "application/jsonl" });
    await loadFile(fake);
  } catch {
    /* file:// or missing — use picker */
  }
}

tryDefault();
