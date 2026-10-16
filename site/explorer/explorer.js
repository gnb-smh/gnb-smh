// GnB Explorer: one module, hash routes, read-only /api. No inline script (CSP).
import { api, scriptToAddress, gnb, short, ago, esc } from "../shared/gnb.js";

const $ = (s) => document.querySelector(s);
const app = $("#app");
let NET = { testnet: true, name: "…" };
let timer = null;

// ── helpers ─────────────────────────────────────────────────────────────────
const link = {
  block: (h, label) => `<a class="mono" href="#/block/${esc(h)}">${esc(label ?? short(h, 10))}</a>`,
  tx: (h, label) => `<a class="mono" href="#/tx/${esc(h)}">${esc(label ?? short(h, 10))}</a>`,
  addr: (a, label) => (a ? `<a class="mono" href="#/address/${esc(a)}">${esc(label ?? short(a, 14))}</a>` : "—"),
};
const card = (title, body, sub = "") => `<section class="card"><h2>${title}${sub ? ` <small>${sub}</small>` : ""}</h2>${body}</section>`;
const kpi = (k, v, s = "", hot = false) => `<div class="card kpi"><span class="k">${k}</span><span class="v${hot ? " hot" : ""}">${v}</span><span class="s">${s}</span></div>`;
const loading = () => { app.innerHTML = `<p class="empty">Loading…</p>`; };
const fail = (e) => { app.innerHTML = `<section class="card"><p class="err">${esc(e.message || e)}</p></section>`; };
const num = (n) => Number(n ?? 0).toLocaleString("en-US");
const vaultAddr = () => { try { return localStorage.getItem("gnb.vault") || ""; } catch { return ""; } };
const vaultScript = () => { const a = vaultAddr(); return /^gnb1[mn][0-9a-f]{72}$/.test(a) ? "02" + a.slice(5, 69) : ""; };

function setTab(name) {
  document.querySelectorAll("#tabs a[data-tab]").forEach((a) => a.classList.toggle("active", a.dataset.tab === name));
}

// Recognise bridge and PoWit outputs in a transaction.
function outputTags(tx, i, out) {
  const tags = [];
  const vs = vaultScript();
  const spk = out.script_pubkey;
  if (tx.coinbase) tags.push(i === 0 ? `<span class="tag">miner</span>` : `<span class="tag hot">witness share</span>`);
  if (vs && spk === vs) tags.push(`<span class="tag hot">bridge vault</span>`);
  const o0 = tx.outputs[0], o2 = tx.outputs[2];
  if (!tx.coinbase && i === 1 && out.value === "546" && spk.length === 40) {
    if (vs && o0 && o0.script_pubkey === vs) tags.push(`<span class="tag ok">lock → Bloch L2 0x${esc(spk)}</span>`);
    else if (vs && o2 && o2.script_pubkey === vs) tags.push(`<span class="tag ok">release · burn marker</span>`);
    else tags.push(`<span class="tag">546 marker</span>`);
  }
  if (spk.length === 66) tags.push(`<span class="tag blue">policy</span>`);
  return tags.join("");
}

function outputsTable(tx) {
  const rows = tx.outputs.map((o, i) => {
    const a = scriptToAddress(o.script_pubkey, NET.testnet);
    return `<tr><td class="num">${i}</td><td>${a ? link.addr(a, short(a, 18)) : `<span class="mono">${esc(short(o.script_pubkey, 16))}</span>`}</td>
      <td>${outputTags(tx, i, o)}</td><td class="num mono">${gnb(o.value)}</td></tr>`;
  }).join("");
  return `<div class="scroll"><table class="tbl"><thead><tr><th class="num">#</th><th>Address</th><th>Kind</th><th class="num">GNB</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

// ── charts (canvas, no library) ─────────────────────────────────────────────
function lineChart(canvas, values, { color = "#ff5f15", fill = true } = {}) {
  const dpr = window.devicePixelRatio || 1, w = canvas.clientWidth, h = canvas.clientHeight || 140;
  canvas.width = w * dpr; canvas.height = h * dpr;
  const c = canvas.getContext("2d"); c.scale(dpr, dpr);
  if (values.length < 2) return;
  const min = Math.min(...values), max = Math.max(...values), span = max - min || 1;
  const x = (i) => (i / (values.length - 1)) * (w - 8) + 4, y = (v) => h - 8 - ((v - min) / span) * (h - 16);
  c.strokeStyle = "#2b2420"; c.lineWidth = 1;
  for (let i = 1; i < 4; i++) { c.beginPath(); c.moveTo(0, (h / 4) * i); c.lineTo(w, (h / 4) * i); c.stroke(); }
  c.beginPath(); values.forEach((v, i) => (i ? c.lineTo(x(i), y(v)) : c.moveTo(x(i), y(v))));
  c.strokeStyle = color; c.lineWidth = 2; c.stroke();
  if (fill) {
    c.lineTo(x(values.length - 1), h); c.lineTo(x(0), h); c.closePath();
    const g = c.createLinearGradient(0, 0, 0, h); g.addColorStop(0, "rgba(255,95,21,.28)"); g.addColorStop(1, "rgba(255,95,21,0)");
    c.fillStyle = g; c.fill();
  }
}

// DAG: x = height, lanes by arrival; edges to every parent, the selected parent bold.
function drawDag(canvas, nodes, onPick) {
  const dpr = window.devicePixelRatio || 1, w = canvas.clientWidth, h = canvas.clientHeight || 260;
  canvas.width = w * dpr; canvas.height = h * dpr;
  const c = canvas.getContext("2d"); c.scale(dpr, dpr);
  if (!nodes.length) return;
  const hs = nodes.map((n) => n.height), minH = Math.min(...hs), maxH = Math.max(...hs);
  const lanes = {}; const pos = {};
  const sorted = [...nodes].sort((a, b) => a.height - b.height || a.blue_score - b.blue_score);
  for (const n of sorted) {
    const lane = lanes[n.height] = (lanes[n.height] ?? -1) + 1;
    const x = 24 + ((n.height - minH) / Math.max(1, maxH - minH)) * (w - 48);
    const y = h / 2 + (lane % 2 ? 1 : -1) * Math.ceil(lane / 2) * 34;
    pos[n.hash] = { x, y: Math.max(14, Math.min(h - 14, y)), n };
  }
  const col = { chain: "#ff5f15", blue: "#7fb3ff", red: "#ff6b6b", pending: "#a0958d" };
  for (const n of sorted) {
    const p = pos[n.hash];
    for (const par of n.parents) {
      const q = pos[par]; if (!q) continue;
      c.beginPath(); c.moveTo(p.x, p.y); c.lineTo(q.x, q.y);
      const sel = par === n.selected_parent;
      c.strokeStyle = sel ? "rgba(255,95,21,.75)" : "rgba(160,149,141,.35)"; c.lineWidth = sel ? 2 : 1; c.stroke();
    }
  }
  for (const n of sorted) {
    const p = pos[n.hash];
    c.beginPath(); c.arc(p.x, p.y, n.colour === "chain" ? 6 : 5, 0, Math.PI * 2);
    c.fillStyle = col[n.colour] || "#a0958d"; c.fill();
  }
  canvas.onclick = (ev) => {
    const r = canvas.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top;
    let best = null, bd = 144;
    for (const k in pos) { const d = (pos[k].x - mx) ** 2 + (pos[k].y - my) ** 2; if (d < bd) { bd = d; best = k; } }
    if (best) onPick(best);
  };
}
const dagLegend = `<div class="legend"><span><i style="background:#ff5f15"></i>selected chain</span><span><i style="background:#7fb3ff"></i>blue (merged)</span>
  <span><i style="background:#ff6b6b"></i>red</span><span><i style="background:#a0958d"></i>pending</span><span>bold edge = selected parent</span></div>`;

// ── pages ───────────────────────────────────────────────────────────────────
async function overview() {
  setTab("overview");
  const [dag, hr, sup, pct, pw, mp, chain, diff, win] = await Promise.all([
    api("getdaginfo"), api("gethashrate"), api("getsupplyinfo"), api("getblocktimepercentiles"),
    api("getpowitinfo").catch(() => null), api("getmempoolstats"), api("getselectedchain", [0, 12]),
    api("getdifficultyhistory", [200]).catch(() => null), api("getdagwindow", [60]).catch(() => null),
  ]);
  const fin = pw && pw.finalized, jus = pw && pw.justified;
  app.innerHTML = `
    <div class="grid kpis">
      ${kpi("Height", num(dag.tip_height), `blue score ${num(dag.tip_blue_score)} · ${num(dag.block_count)} DAG blocks`)}
      ${kpi("Finalized", fin ? link.block(fin.hash, `#${num(fin.block_height)}`) : "—", pw ? (pw.active ? `PoWit · justified slot ${jus ? num(jus.slot) : "—"}` : "PoWit not active · depth rule") : "", true)}
      ${kpi("Hashrate", esc(hr.hashrate_human), `${esc(pw ? pw.pow : "")} · block p50 ${pct.p50_secs}s · target ${pct.target_secs}s`)}
      ${kpi("Issued", `${gnb(sup.issued_sat)} <small>GNB</small>`, `subsidy ${sup.subsidy_per_block_gnb} GNB · cap 12.5M`)}
    </div>
    <div class="grid two" style="margin-top:12px">
      ${card("Block DAG", `<div class="dagwrap"><canvas id="dagmini" style="height:230px"></canvas></div>${dagLegend}`, "last 60 blocks · click a node")}
      ${card("Proof of Context and Time", pw && pw.active ? `
        <div class="kv">
          <div>PoWit epoch</div><div class="mono">${num(pw.epoch)}</div>
          <div>Witness set</div><div class="mono">${num(pw.witness_set.size)} keys · weight ${esc(pw.witness_set.total_weight)}</div>
          <div>Barred keys</div><div class="mono">${num(pw.barred_keys)}</div>
          <div>Pool</div><div class="mono">${num(pw.pool.shares)} shares · ${num(pw.pool.attestations)} attestations · ${num(pw.pool.evidence)} proofs</div>
        </div>
        <p class="note">Witnesses sign each checkpoint with the KES leaf of its epoch; earlier leaves are erased. <a href="#/finality">See the witnesses →</a></p>`
        : `<p class="empty">PoWit is not active on this network yet (activation ${pw && pw.activation_height != null ? num(pw.activation_height) : "off"}).</p>`)}
    </div>
    <div class="grid two" style="margin-top:12px">
      ${card("Latest blocks on the selected chain", `<div class="scroll"><table class="tbl"><thead><tr><th>Height</th><th>Block</th><th class="hide-sm">Miner</th><th class="num">Merged</th><th class="num">Txs</th><th class="num">Age</th></tr></thead><tbody>
        ${chain.blocks.map((b) => `<tr><td class="mono">${num(b.height)}</td><td>${link.block(b.hash)}</td><td class="hide-sm">${link.addr(b.miner, short(b.miner, 12))}</td>
          <td class="num mono">${b.merged}${b.reds ? ` <span class="tag red">${b.reds} red</span>` : ""}</td><td class="num mono">${b.tx_count}</td><td class="num mono">${ago(b.timestamp)}</td></tr>`).join("")}
        </tbody></table></div><div class="row-actions"><a class="btn" href="#/blocks">All blocks</a></div>`)}
      ${card("Block time and difficulty", `
        <div class="bars">
          ${[["p50", pct.p50_secs], ["p90", pct.p90_secs], ["p99", pct.p99_secs], ["avg", pct.avg_secs]].map(([k, v]) =>
            `<div class="bar"><span>${k}</span><span class="track"><span class="fill${k === "avg" ? " mute" : ""}" style="width:${Math.min(100, (v / Math.max(pct.p99_secs, pct.avg_secs, 1)) * 100)}%"></span></span><span class="num">${v}s</span></div>`).join("")}
        </div>
        <canvas id="diffchart" style="height:120px;margin-top:16px"></canvas>
        <div class="chart-cap"><span>difficulty (target⁻¹), last ${diff ? diff.count : 0} changes</span><span>mempool ${num(mp.size)} txs</span></div>`)}
    </div>`;
  if (win) drawDag($("#dagmini"), win.nodes, (h) => (location.hash = `#/block/${h}`));
  if (diff && diff.points) {
    const vals = diff.points.slice().reverse().map((p) => 1 / parseInt(p.target_hex.slice(0, 16), 16));
    lineChart($("#diffchart"), vals);
  }
  refreshIn(12000, overview);
}

async function blocks(page = 0) {
  setTab("blocks");
  const per = 25, chain = await api("getselectedchain", [page * per, per]);
  app.innerHTML = `<div class="section-title"><h1>Selected chain</h1><span class="sub">page ${page + 1}</span></div>
    ${card("", `<div class="scroll"><table class="tbl"><thead><tr><th>Height</th><th>Block</th><th class="hide-sm">Miner</th><th class="num">Reward</th><th class="num">Merged</th><th class="num">Txs</th><th class="num hide-sm">Size</th><th class="num">Age</th></tr></thead><tbody>
    ${chain.blocks.map((b) => `<tr><td class="mono">${num(b.height)}</td><td>${link.block(b.hash)}</td><td class="hide-sm">${link.addr(b.miner, short(b.miner, 12))}</td>
      <td class="num mono">${gnb(b.reward)}</td><td class="num mono">${b.merged}</td><td class="num mono">${b.tx_count}</td><td class="num mono hide-sm">${num(b.size)}</td><td class="num mono">${ago(b.timestamp)}</td></tr>`).join("")}
    </tbody></table></div>
    <div class="row-actions">${page > 0 ? `<a class="btn" href="#/blocks/${page - 1}">← Newer</a>` : ""}<a class="btn" href="#/blocks/${page + 1}">Older →</a></div>`)}`;
}

async function dagPage() {
  setTab("dag");
  const win = await api("getdagwindow", [200]);
  app.innerHTML = `<div class="section-title"><h1>Block DAG</h1><span class="sub">GhostDAG k = ${win.k} · last ${win.nodes.length} blocks</span></div>
    ${card("", `<div class="dagwrap"><canvas id="dagbig" style="height:420px"></canvas></div>${dagLegend}
      <p class="note">Every block references all tips it saw; GhostDAG colours them blue or red and picks one selected parent. Click a node to open it.</p>`)}`;
  drawDag($("#dagbig"), win.nodes, (h) => (location.hash = `#/block/${h}`));
  refreshIn(15000, dagPage);
}

async function finality() {
  setTab("finality");
  const pw = await api("getpowitinfo");
  if (!pw.active) {
    app.innerHTML = `<div class="section-title"><h1>Finality</h1></div>${card("PoWit is not active on this network",
      `<p>Activation height: <span class="mono">${pw.activation_height == null ? "off" : num(pw.activation_height)}</span>. Until then, nodes refuse reorganisations deeper than 1,000 blocks.</p>`)}`;
    return;
  }
  // Recent attestations: scan the latest selected-chain blocks.
  const chain = await api("getselectedchain", [0, 20]);
  const blocksFull = await Promise.all(chain.blocks.map((b) => api("getblock", [b.hash, false]).catch(() => null)));
  const atts = [];
  blocksFull.forEach((b) => b && b.powit && b.powit.attestations.forEach((a) => atts.push({ ...a, in: b.hash, h: b.height })));
  const shares = blocksFull.reduce((n, b) => n + (b && b.powit ? b.powit.shares.length : 0), 0);
  const ws = pw.witness_set, total = Number(ws.total_weight) || 1;
  const ep = pw.epoch;
  const line = Array.from({ length: Math.min(ep + 4, 16) }, (_, i) => Math.max(0, ep - Math.min(ep, 11)) + i)
    .map((e) => `<span class="${e === ep ? "now" : e > ep ? "fut" : ""}">e${e}</span>`).join("");
  app.innerHTML = `<div class="section-title"><h1>Finality · PoWit KES</h1><span class="sub">${esc(pw.pow)} · epoch ${ep} · checkpoint every ${pw.params.checkpoint_interval} heights</span></div>
    <div class="steps">
      <div class="slot fin"><span class="k">Finalized</span><div class="v">slot ${num(pw.finalized.slot)}</div>${link.block(pw.finalized.hash, `block #${num(pw.finalized.block_height)}`)}</div>
      <div class="slot just"><span class="k">Justified</span><div class="v">slot ${num(pw.justified.slot)}</div>${link.block(pw.justified.hash, `block #${num(pw.justified.block_height)}`)}</div>
      <div class="slot"><span class="k">Tip</span><div class="v">#${num(pw.tip_height)}</div><span class="mono" style="font-size:.78rem;color:var(--mute)">${num(pw.tip_height - (pw.finalized.block_height || 0))} blocks above finality</span></div>
    </div>
    <div class="grid two" style="margin-top:12px">
      ${card("Witness set", `<div class="scroll"><table class="tbl"><thead><tr><th>Witness id</th><th>Weight</th><th class="num">Share</th></tr></thead><tbody>
        ${ws.top.map((w) => `<tr><td class="mono">${esc(short(w.key, 12))}</td><td><div class="bar" style="grid-template-columns:minmax(0,1fr)"><span class="track"><span class="fill" style="width:${(Number(w.weight) / total) * 100}%"></span></span></div></td>
          <td class="num mono">${((Number(w.weight) / total) * 100).toFixed(1)}%</td></tr>`).join("")}
        </tbody></table></div><p class="note">${num(ws.size)} of ${pw.params.max_witnesses} seats · weight = witness-share work over ${pw.params.window_epochs} epochs · ${num(pw.barred_keys)} barred</p>`, "earned by work, no stake")}
      ${card("Proof of Context and Time", `
        <p>Each witness key is a Merkle root over one hybrid ML-DSA-65 + Falcon-1024 key per epoch. Signing a checkpoint uses the
        leaf of <b>that checkpoint's epoch</b>; earlier seeds are erased, so the past cannot be signed again, not even by the owner.</p>
        <div class="epochline">${line}</div>
        <p class="note">Striped epochs are erased for an up-to-date witness. Consensus rejects any attestation whose KES leaf is not its target's epoch.</p>`, "PoWit KES")}
    </div>
    ${card(`Recent attestations <small>last 20 blocks · ${atts.length} attestations · ${shares} witness shares</small>`, atts.length ? `<div class="scroll"><table class="tbl"><thead><tr><th>In block</th><th>Witness</th><th>Link</th><th class="num">KES leaf</th><th class="num hide-sm">Signature</th></tr></thead><tbody>
      ${atts.map((a) => `<tr><td>${link.block(a.in, `#${num(a.h)}`)}</td><td class="mono">${esc(short(a.witness, 10))}</td>
        <td class="mono">slot ${num(a.source.slot)} → ${link.block(a.target.hash, `slot ${num(a.target.slot)}`)}</td>
        <td class="num"><span class="tag hot">epoch ${a.kes_epoch} / ${2 ** a.kes_depth}</span></td><td class="num mono hide-sm">${num(a.sig_bytes)} B</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="empty">No attestations in the last 20 blocks.</p>`)}`;
  refreshIn(15000, finality);
}

async function vault() {
  setTab("vault");
  const addr = vaultAddr();
  let body = `<p>The bridge vault holds every GNB locked for wGnB on the Bloch L2. It is a policy tree: a <i>k</i>-of-<i>n</i> release branch for the
    signers and a cold recovery branch behind a long relative timelock. Paste the published vault address to follow it.</p>
    <form id="vf" class="row-actions"><input class="field" id="va" placeholder="gnb1n… / gnb1m… vault address" value="${esc(addr)}"><button class="btn primary">Follow</button></form>`;
  if (addr) {
    try {
      const u = await api("getutxos", [addr, 200]);
      body += `<div class="grid kpis" style="margin-top:14px">${kpi("Locked", `${gnb(u.satoshis)} <small>GNB</small>`, "= wGnB that can exist", true)}${kpi("Vault outputs", num(u.utxo_count), "each a lock or release change")}</div>
      <div class="scroll" style="margin-top:12px"><table class="tbl"><thead><tr><th>Transaction</th><th class="num">Output</th><th class="num">GNB</th></tr></thead><tbody>
      ${u.utxos.map((x) => `<tr><td>${link.tx(x.txid)}</td><td class="num mono">${x.index}</td><td class="num mono">${gnb(x.value)}</td></tr>`).join("") || `<tr><td colspan="3" class="empty">Empty.</td></tr>`}
      </tbody></table></div>`;
    } catch (e) { body += `<p class="err">${esc(e.message)}</p>`; }
  }
  app.innerHTML = `<div class="section-title"><h1>Bloch bridge</h1><span class="sub">GnB ↔ Bloch L2 · v1 set-once signers</span></div>
    <div class="grid two">${card("Vault", body)}${card("How to read a bridge transaction", `
      <div class="kv">
        <div>Lock</div><div>Output 0 pays the vault. Output 1 is a <b>546</b> marker whose 20 bytes are the Bloch L2 recipient (0x…).</div>
        <div>Release</div><div>Output 0 pays the burn's gnb1… address, output 1 is a 546 marker of SHA3("GNB-RELEASE-v1" ‖ burn id), output 2 returns change to the vault.</div>
        <div>Invariant</div><div>A release takes exactly the burned amount out of the vault; each burn's marker can appear once.</div>
        <div>Finality</div><div>Signers mint only after the lock is PoWit-finalized (or 1,000 confirmations before PoWit).</div>
      </div>`)}</div>`;
  $("#vf").onsubmit = (ev) => { ev.preventDefault(); try { localStorage.setItem("gnb.vault", $("#va").value.trim()); } catch {} vault(); };
}

async function mempool() {
  setTab("mempool");
  const [st, raw] = await Promise.all([api("getmempoolstats"), api("getrawmempool")]);
  const ids = Array.isArray(raw) ? raw : (raw.txids || raw.transactions || []);
  app.innerHTML = `<div class="section-title"><h1>Mempool</h1><span class="sub">${num(st.size)} transactions waiting</span></div>
    <div class="grid kpis">${kpi("Size", num(st.size))}${kpi("Median fee", `${gnb(st.median_fee)}`)}${kpi("Max fee", gnb(st.max_fee))}${kpi("Total fees", gnb(st.total_fees))}</div>
    ${card("Pending", ids.length ? `<table class="tbl"><tbody>${ids.slice(0, 200).map((t) => `<tr><td>${link.tx(typeof t === "string" ? t : t.txid)}</td></tr>`).join("")}</tbody></table>` : `<p class="empty">Empty.</p>`)}`;
  refreshIn(10000, mempool);
}

async function block(id) {
  setTab("");
  let hash = id;
  if (/^\d+$/.test(id)) hash = await api("getblockhash", [Number(id)]);
  const b = await api("getblock", [hash, true]);
  const pw = b.powit;
  app.innerHTML = `<div class="section-title"><h1>Block #${num(b.height)}</h1><span class="sub">${esc(b.pow || "")}</span></div>
    <div class="grid two">
      ${card("Header", `<div class="kv">
        <div>Hash</div><div class="mono">${esc(b.hash)}</div>
        <div>Height · blue score</div><div class="mono">${num(b.height)} · ${num(b.blue_score)}</div>
        <div>Time</div><div class="mono">${new Date(b.timestamp * 1000).toISOString().replace("T", " ").slice(0, 19)} UTC · ${ago(b.timestamp)}</div>
        <div>Parents</div><div>${b.parents.map((p) => link.block(p)).join("<br>")}</div>
        <div>Bits · nonce</div><div class="mono">${esc(b.bits)} · ${esc(b.nonce)}</div>
        <div>Size</div><div class="mono">${num(b.size)} bytes · ${b.tx_count} txs</div>
        <div>Merkle root</div><div class="mono">${esc(b.merkle_root)}</div></div>`)}
      ${card("PoWit section", pw ? `<div class="kv">
        <div>Witness shares</div><div>${pw.shares.length ? pw.shares.map((s) => `<span class="tag hot">${esc(short(s.witness, 8))}</span>`).join("") : "none"}</div>
        <div>Attestations</div><div>${pw.attestations.length ? pw.attestations.map((a) => `<div class="mono" style="font-size:.78rem">${esc(short(a.witness, 8))} · slot ${a.source.slot} → ${a.target.slot} · <span class="tag hot">KES epoch ${a.kes_epoch}</span></div>`).join("") : "none"}</div>
        <div>Equivocation proofs</div><div>${pw.evidence.length ? pw.evidence.map((e) => `<span class="tag red">bars ${esc(short(e.witness, 8))}</span>`).join("") : "none"}</div></div>`
        : `<p class="empty">Before PoWit activation: no shares, attestations or proofs.</p>`)}
    </div>
    ${b.transactions.map((tx) => card(`${tx.coinbase ? "Coinbase" : "Transaction"} ${link.tx(tx.txid)}`, outputsTable(tx))).join("")}`;
}

async function tx(id) {
  setTab("");
  const r = await api("gettransaction", [id]);
  const t = r.transaction;
  app.innerHTML = `<div class="section-title"><h1>Transaction</h1><span class="sub">${r.confirmations} confirmations</span></div>
    <div class="grid two">
      ${card("Summary", `<div class="kv">
        <div>Txid</div><div class="mono">${esc(t.txid)}</div>
        <div>Block</div><div>${link.block(r.block_hash, `#${num(r.block_height)} ${short(r.block_hash, 10)}`)}</div>
        <div>Time</div><div class="mono">${ago(r.timestamp)}</div>
        <div>Locktime</div><div class="mono">${t.locktime}</div>
        <div>Inputs</div><div>${t.coinbase ? "coinbase" : t.inputs.map((i) => `${link.tx(i.prev_txid)}:${i.prev_index}`).join("<br>")}</div></div>`)}
      ${card("Outputs", outputsTable(t))}
    </div>`;
}

async function address(a) {
  setTab("");
  const testnet = a.startsWith("gnb1t") || a.startsWith("gnb1n");
  const policy = a.startsWith("gnb1m") || a.startsWith("gnb1n");
  const u = await api("getutxos", [a, 100]);
  const isVault = a === vaultAddr();
  app.innerHTML = `<div class="section-title"><h1>Address</h1><span class="sub">${policy ? "spend policy" : "key hash"} · ${testnet ? "testnet" : "mainnet"}${isVault ? " · bridge vault" : ""}</span></div>
    <div class="grid kpis">${kpi("Balance", `${gnb(u.satoshis)} <small>GNB</small>`, "", true)}${kpi("Outputs", num(u.utxo_count))}</div>
    ${card("Address", `<p class="mono" style="overflow-wrap:anywhere">${esc(a)}</p>`)}
    ${card("Unspent outputs", `<div class="scroll"><table class="tbl"><thead><tr><th>Transaction</th><th class="num">Out</th><th>Kind</th><th class="num">GNB</th></tr></thead><tbody>
      ${u.utxos.map((x) => `<tr><td>${link.tx(x.txid)}</td><td class="num mono">${x.index}</td><td>${x.coinbase_height != null ? `<span class="tag${x.spendable ? "" : " red"}">coinbase${x.spendable ? "" : " · immature"}</span>` : ""}</td><td class="num mono">${gnb(x.value)}</td></tr>`).join("") || `<tr><td colspan="4" class="empty">None.</td></tr>`}
    </tbody></table></div>`)}`;
}

// ── routing ─────────────────────────────────────────────────────────────────
function refreshIn(ms, fn) { clearTimeout(timer); timer = setTimeout(() => { if (!document.hidden) fn().catch(() => {}); }, ms); }

async function route() {
  clearTimeout(timer);
  const parts = location.hash.replace(/^#\/?/, "").split("/");
  loading();
  try {
    switch (parts[0]) {
      case "": return await overview();
      case "blocks": return await blocks(Number(parts[1] || 0));
      case "dag": return await dagPage();
      case "finality": return await finality();
      case "vault": return await vault();
      case "mempool": return await mempool();
      case "block": return await block(parts[1]);
      case "tx": return await tx(parts[1]);
      case "address": return await address(parts[1]);
      default: app.innerHTML = `<p class="empty">Not found.</p>`;
    }
  } catch (e) { fail(e); }
}

$("#search").onsubmit = async (ev) => {
  ev.preventDefault();
  const q = $("#q").value.trim().toLowerCase();
  if (!q) return;
  if (/^\d+$/.test(q)) location.hash = `#/block/${q}`;
  else if (/^gnb1[qtmn][0-9a-f]+$/.test(q)) location.hash = `#/address/${q}`;
  else if (/^[0-9a-f]{64}$/.test(q)) {
    try { await api("getblock", [q, false]); location.hash = `#/block/${q}`; }
    catch { location.hash = `#/tx/${q}`; }
  }
};

async function netstatus() {
  const chip = $("#netchip");
  try {
    const n = await api("getnetworkinfo");
    NET = { testnet: n.network === "testnet", name: n.network };
    chip.className = "chip live";
    $("#nettext").textContent = `${n.network} · #${(await api("getdaginfo")).tip_height.toLocaleString("en-US")} · ${n.peers} peers`;
  } catch {
    chip.className = "chip down"; $("#nettext").textContent = "node unreachable";
  }
}

// A published vault can be pre-selected with ?vault=gnb1n…
{
  const v = new URLSearchParams(location.search).get("vault");
  if (v && /^gnb1[mn][0-9a-f]{72}$/.test(v)) { try { localStorage.setItem("gnb.vault", v); } catch {} }
}
window.addEventListener("hashchange", route);
netstatus().then(route);
setInterval(netstatus, 15000);
