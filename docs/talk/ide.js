// In-deck code viewer: click a source path on a slide to browse the repo in
// Monaco (the editor inside VS Code), then press Esc to return to the slide.
// Locally, serve.py exposes the repo under /src/. On GitHub Pages there is no
// server: we load src-index.json and fetch files from raw.githubusercontent.com.
(() => {
  const MONACO = "https://cdn.jsdelivr.net/npm/monaco-editor@0.52.0/min/vs";
  const LANG = { go: "go", sh: "shell", md: "markdown" };

  let index = null;      // {root?, files, remote?, blob?}
  let editor = null;
  let decorations = null;
  let current = null;    // {path, line}
  let fontSize = 20;
  const cache = new Map();

  const $ = (sel, el = document) => el.querySelector(sel);

  async function loadIndex() {
    try {
      const r = await fetch("/src/index.json", { cache: "no-store" });
      if (r.ok) return r.json();
    } catch (_) { /* not running under serve.py */ }
    const r = await fetch("src-index.json");
    if (!r.ok) throw new Error("could not load source index");
    return r.json();
  }

  function buildOverlay() {
    const el = document.createElement("div");
    el.id = "ide";
    el.hidden = true;
    el.innerHTML = `
      <div class="ide-bar">
        <span class="ide-dots"><i></i><i></i><i></i></span>
        <span class="ide-path"></span>
        <span class="ide-spacer"></span>
        <button class="ide-btn" data-act="smaller" title="Smaller text">A−</button>
        <button class="ide-btn" data-act="bigger" title="Bigger text">A+</button>
        <a class="ide-btn ide-cursor" title="Open this file in Cursor">Open in Cursor ↗</a>
        <button class="ide-btn ide-back" data-act="close">Back to slide <kbd>Esc</kbd></button>
      </div>
      <div class="ide-body">
        <nav class="ide-tree"><p class="ide-tree-title">mytcp</p></nav>
        <div class="ide-editor"></div>
      </div>`;
    document.body.appendChild(el);
    el.addEventListener("click", (e) => {
      const act = e.target.closest("[data-act]")?.dataset.act;
      if (act === "close") close();
      if (act === "smaller") zoom(-2);
      if (act === "bigger") zoom(+2);
      const file = e.target.closest("[data-file]")?.dataset.file;
      if (file) show(file);
    });
    return el;
  }

  function buildTree(el) {
    const tree = $(".ide-tree", el);
    const dirs = new Map();
    for (const f of index.files) {
      const dir = f.includes("/") ? f.slice(0, f.lastIndexOf("/")) : "";
      if (!dirs.has(dir)) dirs.set(dir, []);
      dirs.get(dir).push(f);
    }
    for (const [dir, files] of dirs) {
      if (dir) {
        const h = document.createElement("p");
        h.className = "ide-dir";
        h.textContent = dir + "/";
        tree.appendChild(h);
      }
      for (const f of files) {
        const a = document.createElement("a");
        a.className = "ide-file" + (dir ? " nested" : "");
        a.dataset.file = f;
        a.textContent = f.slice(f.lastIndexOf("/") + 1);
        tree.appendChild(a);
      }
    }
  }

  function loadMonaco() {
    return new Promise((resolve) => {
      const s = document.createElement("script");
      s.src = `${MONACO}/loader.js`;
      s.onload = () => {
        window.require.config({ paths: { vs: MONACO } });
        window.require(["vs/editor/editor.main"], () => resolve(window.monaco));
      };
      document.head.appendChild(s);
    });
  }

  async function ensureReady() {
    const el = $("#ide") || buildOverlay();
    if (editor) return el;
    const [monaco, idx] = await Promise.all([
      loadMonaco(),
      loadIndex(),
    ]);
    index = idx;
    buildTree(el);
    monaco.editor.defineTheme("deck", {
      base: "vs-dark",
      inherit: true,
      rules: [{ token: "comment", foreground: "9fb8a8" }],
      colors: {
        "editor.background": "#0f151a",
        "editor.lineHighlightBackground": "#16211c",
        "editorLineNumber.foreground": "#4b5a53",
      },
    });
    editor = monaco.editor.create($(".ide-editor", el), {
      value: "",
      language: "go",
      theme: "deck",
      readOnly: true,
      fontFamily: "IBM Plex Mono, monospace",
      fontSize,
      lineHeight: Math.round(fontSize * 1.5),
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      automaticLayout: true,
      renderLineHighlight: "all",
    });
    decorations = editor.createDecorationsCollection();
    return el;
  }

  async function text(path) {
    if (!cache.has(path)) {
      const url = index.root
        ? `/src/${path}`
        : `${index.remote || ""}${path}`;
      const p = fetch(url, { cache: "no-cache" }).then((r) => {
        if (!r.ok) throw new Error(`could not load ${path} (HTTP ${r.status})`);
        return r.text();
      });
      // Only successes are cached; a failed fetch is retried on the next click.
      p.catch(() => cache.delete(path));
      cache.set(path, p);
    }
    return cache.get(path);
  }

  function blobURL(path, line = 1) {
    return `${index.blob || "https://github.com/doodlesbykumbi/mytcp/blob/main/"}${path}#L${line}`;
  }

  // Find the slide's code in the file: by symbol name first, then by the
  // snippet's own lines. Returns the enclosing top-level declaration.
  function locate(src, symbol, snippet) {
    const lines = src.split("\n");
    let hit = -1;
    if (symbol) {
      const re = new RegExp(`^(func (\\([^)]*\\) )?|type )${symbol}\\b`);
      hit = lines.findIndex((l) => re.test(l));
    }
    if (hit < 0) {
      const probes = snippet
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l.length >= 12 && !l.startsWith("//") && !l.includes("/*"));
      for (const p of probes) {
        hit = lines.findIndex((l) => l.trim() === p);
        if (hit >= 0) break;
      }
    }
    if (hit < 0) return null;
    let start = hit;
    while (start > 0 && !/^(func|type) /.test(lines[start])) start--;
    if (!/^(func|type) /.test(lines[start])) return { start: hit + 1, end: hit + 1 };
    while (start > 0 && lines[start - 1].startsWith("//")) start--;
    let end = start;
    while (end < lines.length - 1 && lines[end] !== "}" && lines[end] !== ")") end++;
    return { start: start + 1, end: end + 1 };
  }

  async function show(path, symbol = "", snippet = "") {
    const el = await ensureReady();
    let src, failed = false;
    try {
      src = await text(path);
    } catch (e) {
      failed = true;
      src = `// ${e.message}\n// Click the file again to retry, or open it on GitHub:\n// ${blobURL(path)}\n`;
    }
    const ext = path.split(".").pop();
    const model = window.monaco.editor.createModel(src, failed ? "plaintext" : LANG[ext] || "plaintext");
    editor.getModel()?.dispose();
    editor.setModel(model);

    const where = !failed && (symbol || snippet) ? locate(src, symbol, snippet) : null;
    decorations.set(
      where
        ? [{
            range: new window.monaco.Range(where.start, 1, where.end, 1),
            options: { isWholeLine: true, className: "ide-hl", linesDecorationsClassName: "ide-hl-gutter" },
          }]
        : [],
    );
    const line = where ? where.start : 1;
    editor.revealLineNearTop(line);
    editor.setPosition({ lineNumber: line, column: 1 });
    current = { path, line };

    $(".ide-path", el).textContent = path;
    const openLink = $(".ide-cursor", el);
    if (index.root) {
      openLink.href = `cursor://file/${index.root}/${path}:${line}`;
      openLink.textContent = "Open in Cursor ↗";
    } else {
      openLink.href = blobURL(path, line);
      openLink.textContent = "Open on GitHub ↗";
      openLink.target = "_blank";
      openLink.rel = "noopener";
    }
    el.querySelectorAll(".ide-file").forEach((a) =>
      a.classList.toggle("active", a.dataset.file === path),
    );
    el.querySelector(".ide-file.active")?.scrollIntoView({ block: "nearest" });
  }

  async function open(path, symbol, snippet) {
    const el = await ensureReady();
    el.hidden = false;
    Reveal.configure({ keyboard: false });
    await show(path, symbol, snippet);
    editor.layout();
    editor.focus();
  }

  function close() {
    const el = $("#ide");
    if (!el || el.hidden) return;
    el.hidden = true;
    Reveal.configure({ keyboard: true });
    document.activeElement?.blur();
  }

  function zoom(delta) {
    fontSize = Math.min(32, Math.max(12, fontSize + delta));
    editor?.updateOptions({ fontSize, lineHeight: Math.round(fontSize * 1.5) });
  }

  window.addEventListener(
    "keydown",
    (e) => {
      const el = $("#ide");
      if (e.key === "Escape" && el && !el.hidden) {
        e.stopImmediatePropagation();
        e.preventDefault();
        close();
      }
    },
    true,
  );

  // Turn "internal/eth/ethernet.go · handleARP" paths into buttons.
  function wirePaths() {
    document.querySelectorAll(".reveal .code-path").forEach((p) => {
      const [path, rest = ""] = p.textContent.split(" · ");
      if (!/^(internal|cmd|scripts)\/\S+\.\w+$/.test(path.trim())) return;
      const symbol = (rest.trim().match(/^[A-Za-z_]\w*/) || [""])[0];
      p.classList.add("openable");
      p.title = "Open in the code viewer";
      p.addEventListener("click", () => {
        const pre = p.nextElementSibling?.matches("pre") ? p.nextElementSibling : null;
        open(path.trim(), symbol, pre ? pre.textContent : "");
      });
    });
  }

  window.DeckIDE = { open, close, get current() { return current; } };
  if (window.Reveal?.isReady()) wirePaths();
  else Reveal.on("ready", wirePaths);
})();
