// gnb-smh.com landing and brand pages: copy buttons and the scratchpad
// animation. Moved out of inline <script> blocks so a strict CSP
// (script-src 'self') applies site-wide (audit WAL-3).
(() => {
  // ---------------------------------------------------------------- copy buttons
  for (const btn of document.querySelectorAll("[data-copy]")) {
    btn.addEventListener("click", async () => {
      const src = document.getElementById(btn.dataset.copy);
      if (!src) return;
      const svg = src.querySelector("svg");
      const text = svg ? svg.outerHTML : src.textContent.trim();
      const label = btn.textContent;
      try {
        await navigator.clipboard.writeText(text);
        btn.textContent = "Copied";
      } catch (e) {
        const range = document.createRange();
        range.selectNodeContents(src);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        btn.textContent = "Selected";
      }
      setTimeout(() => { btn.textContent = label; }, 1600);
    });
  }

  // ---------------------------------------------------------------- scratchpad
  const pad = document.getElementById("pad-grid");
  if (!pad) return;
  const cells = Array.from(pad.querySelectorAll("rect.c"));
  const N_CELLS = cells.length;            // 512 cells, each standing for 1,024 blocks
  const N_REAL = 524288;                   // real scratchpad blocks (2^19)
  const READS = 512;                       // reads shown per cycle
  const T_FILL = 2600, T_MIX = 4200, T_FINAL = 1900;
  const T_ALL = T_FILL + T_MIX + T_FINAL;
  const out = "c05129a877e99e4fd8f1bd6bd39963a95c9ece39bc5055047db51bfaa4f44bef";

  const el = (id) => document.getElementById(id);
  const rPhase = el("r-phase"), rStep = el("r-step"), rJ = el("r-j"), rOut = el("r-out");
  const btn = el("pad-toggle");
  const fmt = (n) => n.toLocaleString("en-US");

  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let playing = !reduce;
  let visible = true;
  let t0 = null, tPaused = 0, cycle = 0;
  let filled = 0, readsDone = 0, rng = 1;
  const active = new Map();             // cell index -> expiry time

  function xorshift() {
    rng ^= rng << 13; rng >>>= 0;
    rng ^= rng >>> 17;
    rng ^= rng << 5; rng >>>= 0;
    return rng;
  }

  function reset() {
    for (const c of cells) c.setAttribute("class", "c");
    active.clear();
    filled = 0; readsDone = 0;
    rng = (0x9e3779b9 ^ (cycle * 2654435761)) >>> 0 || 1;
    rOut.textContent = "pending";
    rOut.classList.remove("hot");
  }

  function frame(now) {
    if (!playing || !visible) { t0 = null; return; }
    if (t0 === null) t0 = now - tPaused;
    let t = now - t0;
    if (t >= T_ALL) {
      cycle += 1;
      t0 = now; t = 0; tPaused = 0;
      reset();
    }
    tPaused = t;

    if (t < T_FILL) {
      const k = Math.min(N_CELLS, Math.floor((t / T_FILL) * N_CELLS));
      for (; filled < k; filled++) cells[filled].setAttribute("class", "c w");
      rPhase.textContent = "fill";
      rStep.textContent = fmt(Math.floor((t / T_FILL) * N_REAL));
      rJ.textContent = "–";
    } else if (t < T_FILL + T_MIX) {
      for (; filled < N_CELLS; filled++) cells[filled].setAttribute("class", "c w");
      const q = (t - T_FILL) / T_MIX;
      const m = Math.min(READS, Math.floor(q * READS));
      let lastJ = null;
      for (; readsDone < m; readsDone++) {
        const r = xorshift();
        const j = r % N_CELLS;
        cells[j].setAttribute("class", "c r");
        active.set(j, now + 380);
        lastJ = j * 1024 + ((r >>> 9) & 1023);
      }
      for (const [j, exp] of active) {
        if (now >= exp) { cells[j].setAttribute("class", "c w"); active.delete(j); }
      }
      rPhase.textContent = "mix";
      rStep.textContent = fmt(Math.floor(q * N_REAL));
      if (lastJ !== null) rJ.textContent = fmt(lastJ);
    } else {
      for (const [j] of active) cells[j].setAttribute("class", "c w");
      active.clear();
      rPhase.textContent = "final";
      rStep.textContent = fmt(N_REAL);
      rOut.textContent = out.slice(0, 16) + "…";
      rOut.classList.add("hot");
    }
    requestAnimationFrame(frame);
  }

  function setPlaying(p) {
    playing = p;
    btn.textContent = p ? "Pause" : "Play";
    btn.setAttribute("aria-pressed", p ? "false" : "true");
    if (p) {
      if (!reduce && filled === N_CELLS && readsDone === 0 && tPaused === 0) reset();
      requestAnimationFrame(frame);
    }
  }

  btn.addEventListener("click", () => {
    if (reduce && !playing && tPaused === 0) reset();
    setPlaying(!playing);
  });

  if ("IntersectionObserver" in window) {
    new IntersectionObserver((entries) => {
      for (const e of entries) {
        const was = visible;
        visible = e.isIntersecting;
        if (visible && !was && playing) requestAnimationFrame(frame);
      }
    }, { threshold: 0.1 }).observe(pad);
  }

  btn.textContent = playing ? "Pause" : "Play";
  if (playing) {
    // start from the finished picture for one beat, then run the loop
    setTimeout(() => { if (playing) { reset(); requestAnimationFrame(frame); } }, 900);
  }
})();

