// GnB web wallet. Keys are decrypted and used only inside the WebAssembly
// core (core.js / gnb_wallet.wasm); this file never sees a private key.
import { loadCore } from "/wallet/core.js";

const SAT = 100000000n;
const IDLE_LOCK_MS = 10 * 60 * 1000;
const app = document.getElementById("app");
const lockBtn = document.getElementById("lock");
let core = null;
let state = { mode: "locked", address: null, tab: "send", balance: null, utxos: [], pending: null };
let idleTimer = null, pollTimer = null;

// ── helpers ──────────────────────────────────────────────────────────────────
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function fmt(sat, dp = 8) {
  if (sat === null || sat === undefined) return "—";
  const v = BigInt(sat), whole = (v / SAT).toLocaleString("en-US");
  const frac = (v % SAT).toString().padStart(8, "0").slice(0, dp).replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : whole;
}
function parseGnb(s) {
  s = String(s).trim().replace(/,/g, "");
  if (!/^\d+(\.\d{1,8})?$/.test(s)) throw new Error("Enter an amount like 12.5 (up to 8 decimals).");
  const [w, f = ""] = s.split(".");
  return BigInt(w) * SAT + BigInt(f.padEnd(8, "0"));
}
async function api(method, params = []) {
  const r = await fetch(`/api/${method}?p=${encodeURIComponent(JSON.stringify(params))}`, { cache: "no-store" });
  const doc = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  if (doc.error) throw new Error(doc.error);
  return doc.result;
}
async function broadcast(hex) {
  const r = await fetch("/api/sendrawtransaction", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hex }) });
  const doc = await r.json().catch(() => ({ error: `HTTP ${r.status}` }));
  if (doc.error) throw new Error(doc.error);
  return doc.result;
}
function download(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  a.download = name; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
const nextFrame = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 0)));
async function getCore() {
  if (!core) core = await loadCore("/wallet/gnb_wallet.wasm");
  return core;
}
function busy(btn, label) { btn.disabled = true; btn.dataset.label = btn.innerHTML; btn.innerHTML = `<span class="busy"></span>${esc(label)}`; }
function unbusy(btn) { btn.disabled = false; if (btn.dataset.label) btn.innerHTML = btn.dataset.label; }
function showError(where, e) { where.innerHTML = `<div class="alert bad">${esc(e.message || e)}</div>`; }

function armIdleLock() {
  clearTimeout(idleTimer);
  if (state.mode === "keys") idleTimer = setTimeout(() => lock("Locked after 10 minutes without activity."), IDLE_LOCK_MS);
}
["pointerdown", "keydown"].forEach((ev) => document.addEventListener(ev, armIdleLock, { passive: true }));

function lock(message) {
  try { core?.wipe(); } catch {}
  clearTimeout(idleTimer); clearInterval(pollTimer);
  state = { mode: "locked", address: null, tab: "send", balance: null, utxos: [], pending: null };
  lockBtn.hidden = true;
  renderGate(message);
}
lockBtn.addEventListener("click", () => lock());
window.addEventListener("pagehide", () => { try { core?.wipe(); } catch {} });

// ── the gate (locked) ────────────────────────────────────────────────────────
function renderGate(message) {
  app.innerHTML = `<div class="gate">
  <div class="gate-head"><span class="eyebrow">GnB Wallet</span><h1>Hold GNB with post-quantum keys.</h1>
   <p>Open a GnB or Bloch keystore, create a new one, or watch an address. Your keystore is decrypted in this tab with its password, and signing happens here too. Nothing secret is uploaded.</p></div>
  ${message ? `<div class="alert ok">${esc(message)}</div>` : ""}
  <div class="doors">
   <section class="door primary"><span class="num">01 · OPEN</span><h2>Open a keystore</h2>
    <p>A <span class="mono">.json</span> keystore from GnB or from Bloch (Genesis-3). A Bloch address becomes the same <span class="mono">gnb1q…</span> address.</p>
    <div class="drop" id="drop" tabindex="0" role="button" aria-label="Choose keystore file"><b>Drop the keystore here</b><br>or click to choose a file</div>
    <input type="file" id="file" accept=".json,application/json" hidden>
    <label>Password<input type="password" id="pw" autocomplete="current-password"></label>
    <button class="btn" id="open">Unlock</button><div id="open-msg"></div></section>
   <section class="door"><span class="num">02 · CREATE</span><h2>Create a wallet</h2>
    <p>A new ML-DSA-65 + Falcon-1024 key, generated here. You download its encrypted keystore before you can use it.</p>
    <label>Password<input type="password" id="npw" autocomplete="new-password"></label>
    <label>Repeat password<input type="password" id="npw2" autocomplete="new-password"></label>
    <p class="note">At least 12 characters, three of upper, lower, digit, symbol. It cannot be recovered.</p>
    <button class="btn ghost" id="create">Create and download</button><div id="create-msg"></div></section>
   <section class="door"><span class="num">03 · WATCH</span><h2>Watch an address</h2>
    <p>Balance, activity and a receive QR for any <span class="mono">gnb1q…</span> or <span class="mono">bloch1q…</span> address. No keys involved.</p>
    <label>Address<input id="waddr" spellcheck="false" placeholder="gnb1q…"></label>
    <button class="btn ghost" id="watch">Watch</button><div id="watch-msg"></div></section>
  </div>
  <div class="trust">
   <div><b>Keys stay in the tab</b><span>Decryption (Argon2id, AES-256-GCM) and signing run in WebAssembly in this page. The page loads only code from gnb-smh.com.</span></div>
   <div><b>Post-quantum signatures</b><span>Every input is signed with ML-DSA-65 and Falcon-1024 together; both must verify.</span></div>
   <div><b>Locks itself</b><span>The key is wiped from memory on Lock, when the tab closes, and after 10 minutes idle.</span></div>
  </div></div>`;
  let fileText = null;
  const drop = document.getElementById("drop"), file = document.getElementById("file");
  const take = async (f) => { if (!f) return; if (f.size > 4 * 1024 * 1024) return showError(document.getElementById("open-msg"), "That file is too large to be a keystore.");
    fileText = await f.text(); drop.innerHTML = `<b>${esc(f.name)}</b><br>${(f.size / 1024).toFixed(1)} kB · ready`; document.getElementById("pw").focus(); };
  drop.addEventListener("click", () => file.click());
  drop.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); file.click(); } });
  file.addEventListener("change", () => take(file.files[0]));
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); take(e.dataTransfer.files[0]); });

  document.getElementById("open").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = document.getElementById("open-msg"); msg.innerHTML = "";
    if (!fileText) return showError(msg, "Choose a keystore file first.");
    busy(btn, "Decrypting (a few seconds)…"); await nextFrame();
    try {
      const c = await getCore(); const r = c.open(fileText, document.getElementById("pw").value);
      document.getElementById("pw").value = ""; fileText = null;
      enter("keys", r.address);
    } catch (e) { unbusy(btn); showError(msg, e); }
  });
  document.getElementById("create").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = document.getElementById("create-msg"); msg.innerHTML = "";
    const p1 = document.getElementById("npw").value, p2 = document.getElementById("npw2").value;
    if (p1 !== p2) return showError(msg, "The passwords do not match.");
    busy(btn, "Generating and encrypting…"); await nextFrame();
    try {
      const c = await getCore(); const r = c.create();
      let ks;
      try { ks = c.exportKeystore(p1); } catch (e) { c.wipe(); throw e; }
      download(`gnb-wallet-${r.address.slice(0, 14)}.json`, ks);
      document.getElementById("npw").value = document.getElementById("npw2").value = "";
      enter("keys", r.address, "New wallet created. Keep the downloaded keystore and its password: they are the only way back in.");
    } catch (e) { unbusy(btn); showError(msg, e); }
  });
  document.getElementById("watch").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, msg = document.getElementById("watch-msg"); msg.innerHTML = "";
    busy(btn, "Checking…");
    try { const c = await getCore(); enter("watch", c.normalize(document.getElementById("waddr").value)); }
    catch (e) { unbusy(btn); showError(msg, e); }
  });
}

// ── the vault (unlocked or watching) ─────────────────────────────────────────
function enter(mode, address, notice) {
  state = { mode, address, tab: mode === "keys" ? "send" : "receive", balance: null, utxos: [], pending: null, notice };
  lockBtn.hidden = false; lockBtn.textContent = mode === "keys" ? "Lock" : "Close";
  armIdleLock(); renderVault(); refresh();
  clearInterval(pollTimer); pollTimer = setInterval(refresh, 20000);
}

async function refresh() {
  if (state.mode === "locked") return;
  try {
    const [bal, utxos] = await Promise.all([api("getbalance", [state.address]), api("getutxos", [state.address, 50])]);
    state.balance = bal.satoshis ?? bal.balance ?? "0";
    state.utxos = utxos.utxos || [];
    state.utxoTotal = state.utxos.reduce((s, u) => s + BigInt(u.value), 0n);
    state.utxoCount = bal.utxo_count ?? state.utxos.length;
    paintSlab();
    if (state.tab === "activity") paintActivity();
  } catch (e) { const el = document.getElementById("slab-err"); if (el) el.innerHTML = `<div class="alert bad">${esc(e.message)}</div>`; }
}

function renderVault() {
  const keys = state.mode === "keys";
  const tabs = keys ? [["send", "Send"], ["receive", "Receive"], ["activity", "Activity"], ["backup", "Backup"]] : [["receive", "Receive"], ["activity", "Activity"]];
  app.innerHTML = `${state.notice ? `<div class="alert ok" style="margin-bottom:18px">${esc(state.notice)}</div>` : ""}<div class="vault">
   <aside class="slab" id="slab"></aside>
   <section class="panel"><div class="tabs" role="tablist">${tabs.map(([k, l]) => `<button role="tab" data-tab="${k}" aria-selected="${state.tab === k}">${l}</button>`).join("")}</div><div class="pane" id="pane"></div></section></div>`;
  app.querySelectorAll("[data-tab]").forEach((b) => b.addEventListener("click", () => { state.tab = b.dataset.tab; renderVault(); }));
  paintSlab(); paintPane();
}

function paintSlab() {
  const el = document.getElementById("slab"); if (!el) return;
  const keys = state.mode === "keys";
  el.innerHTML = `<span class="k">Balance</span>
   <div class="bal">${state.balance === null ? `<span class="busy"></span>` : esc(fmt(state.balance))}<small>GNB</small></div>
   <div class="row">${keys ? `<span class="chip on">● Unlocked</span>` : `<span class="chip watch">◌ Watching</span>`}<a class="chip" href="/explorer#/address/${esc(state.address)}" target="_blank" rel="noopener">Explorer ↗</a></div>
   <span class="k">Address</span><div class="addr" id="addr">${esc(state.address)}</div>
   <div class="row"><button class="chip" id="copy">Copy address</button><button class="chip" id="refresh">Refresh</button></div>
   <div class="facts"><div><b>${state.utxoCount ?? "—"}</b><span>Unspent outputs</span></div><div><b>${state.utxos.length ? fmt(state.utxoTotal, 4) : "—"}</b><span>Spendable now*</span></div></div>
   <p class="note">* One payment can spend up to 50 outputs (each input carries an ~8.5 kB post-quantum signature).</p><div id="slab-err"></div>`;
  document.getElementById("copy").addEventListener("click", (e) => navigator.clipboard?.writeText(state.address).then(() => { e.target.textContent = "Copied"; setTimeout(() => (e.target.textContent = "Copy address"), 1200); }));
  document.getElementById("refresh").addEventListener("click", refresh);
}

function paintPane() {
  const pane = document.getElementById("pane");
  ({ send: paintSend, receive: paintReceive, activity: paintActivity, backup: paintBackup }[state.tab] || paintReceive)(pane);
}

function paintSend(pane = document.getElementById("pane")) {
  pane.innerHTML = `<h3>Send GNB</h3>
   <label>To<input id="to" spellcheck="false" placeholder="gnb1q… (a bloch1q… address is accepted)"></label>
   <div class="field-row"><label>Amount (GNB)<input id="amt" inputmode="decimal" placeholder="0.00"></label><button class="btn ghost" id="max">Max</button></div>
   <p class="note">The network fee is set to the consensus minimum for the transaction's real size (≈ 0.00002 GNB per kB, at least 0.0001 GNB).</p>
   <button class="btn" id="review">Review payment</button><div id="send-out"></div>`;
  document.getElementById("max").addEventListener("click", () => {
    // Leave room for the fee of up to 50 inputs (~430 kB at 2,000 sat/kB).
    const reserve = 900000n, total = state.utxoTotal || 0n;
    document.getElementById("amt").value = total > reserve ? fmt(total - reserve) : "0";
  });
  document.getElementById("review").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, out = document.getElementById("send-out"); out.innerHTML = "";
    try {
      const to = core.normalize(document.getElementById("to").value);
      const amount = parseGnb(document.getElementById("amt").value);
      if (amount <= 0n) throw new Error("Enter an amount above zero.");
      if (!state.utxos.length) throw new Error("No spendable outputs found for this address yet.");
      busy(btn, "Building and signing…"); await nextFrame();
      const tx = core.pay(state.utxos, to, amount.toString(), "0");
      state.pending = { ...tx, to };
      unbusy(btn);
      out.innerHTML = `<div class="review">
        <div><span>To</span><b>${esc(to)}</b></div>
        <div><span>Amount</span><b>${esc(fmt(tx.amount))} GNB</b></div>
        <div><span>Network fee</span><b>${esc(fmt(tx.fee))} GNB</b></div>
        <div><span>Inputs · size</span><b>${tx.inputs} · ${(tx.size / 1024).toFixed(1)} kB</b></div>
        <div><span>Change back to you</span><b>${esc(fmt(tx.change))} GNB</b></div>
        <div><span>Total leaving this address</span><b>${esc(fmt(BigInt(tx.amount) + BigInt(tx.fee)))} GNB</b></div></div>
        <div class="row" style="margin-top:14px"><button class="btn" id="confirm">Confirm and send</button><button class="btn ghost" id="cancel">Cancel</button></div>`;
      document.getElementById("cancel").addEventListener("click", () => { state.pending = null; out.innerHTML = ""; });
      document.getElementById("confirm").addEventListener("click", async (e2) => {
        const b2 = e2.currentTarget; busy(b2, "Broadcasting…");
        try {
          await broadcast(state.pending.raw);
          const id = state.pending.txid; state.pending = null;
          out.innerHTML = `<div class="alert ok">Sent. Transaction <a class="mono" href="/explorer#/tx/${esc(id)}" target="_blank" rel="noopener">${esc(id.slice(0, 16))}…</a> is in the mempool and will confirm in the next blocks.</div>`;
          setTimeout(refresh, 3000);
        } catch (err) { unbusy(b2); showError(out, err); }
      });
    } catch (e) { unbusy(btn); showError(out, e); }
  });
}

function paintReceive(pane = document.getElementById("pane")) {
  let qrHtml = "";
  try { const q = window.qrcode(0, "M"); q.addData(state.address, "Byte"); q.make(); qrHtml = q.createSvgTag({ cellSize: 6, margin: 0, scalable: true }); } catch {}
  pane.innerHTML = `<h3>Receive GNB</h3><div class="receive"><div class="qr" aria-label="QR code of the address">${qrHtml}</div>
   <div style="display:grid;gap:12px"><p>Share this address. Anyone can send GNB to it; only the keystore can spend it.</p><div class="addr">${esc(state.address)}</div>
   <p class="note">Same key as the Bloch address <span class="mono">bloch1q${esc(state.address.slice(5))}</span>: GNB from the Genesis-3 carryover is already here.</p></div></div>`;
}

async function paintActivity(pane = document.getElementById("pane")) {
  if (!pane || state.tab !== "activity") return;
  if (!pane.dataset.loaded) pane.innerHTML = `<h3>Activity</h3><p class="muted"><span class="busy"></span>Loading…</p>`;
  try {
    const [h, carry] = await Promise.all([api("getaddresshistory", [state.address, 25, 0]), fetch(`/api/carryover/${state.address}`).then((r) => r.json()).catch(() => null)]);
    pane.dataset.loaded = "1";
    const c = carry?.result;
    pane.innerHTML = `<h3>Activity</h3>
     ${c?.in_carryover ? `<div class="alert ok">Genesis carryover: ${esc(fmt(c.amount))} GNB from the Bloch Genesis-3 snapshot (${Number(c.utxos).toLocaleString("en-US")} outputs).</div>` : ""}
     ${h.items.length ? `<table class="activity"><thead><tr><th>Height</th><th>Transaction</th><th></th><th class="num">GNB</th></tr></thead><tbody>
      ${h.items.map((i) => `<tr><td class="mono">${Number(i.height).toLocaleString("en-US")}</td><td><a class="mono" href="/explorer#/tx/${esc(i.txid)}" target="_blank" rel="noopener">${esc(i.txid.slice(0, 12))}…</a></td><td class="muted">${i.direction === "in" ? "received" : "sent"}</td><td class="num ${i.direction === "in" ? "in" : ""}">${i.direction === "in" ? "+" : "−"}${esc(fmt(i.amount))}</td></tr>`).join("")}
      </tbody></table>${h.total > 25 ? `<p class="note">Showing the latest 25 of ${h.total}. <a href="/explorer#/address/${esc(state.address)}" target="_blank" rel="noopener">Full history in the explorer ↗</a></p>` : ""}`
      : `<p class="muted">No on-chain movements yet.</p>`}`;
  } catch (e) { showError(pane, e); }
}

function paintBackup(pane = document.getElementById("pane")) {
  pane.innerHTML = `<h3>Back up this wallet</h3>
   <p>Download the key again as an encrypted GnB keystore (v2). Choose a password; it is the only way to open the file.</p>
   <label>Password<input type="password" id="bpw" autocomplete="new-password"></label>
   <label>Repeat password<input type="password" id="bpw2" autocomplete="new-password"></label>
   <button class="btn ghost" id="bdl">Download encrypted keystore</button><div id="b-out"></div>
   <p class="note">The file can be opened here, with <span class="mono">gnb-cli send</span>, and with any GnB node tool. Never share it together with its password.</p>`;
  document.getElementById("bdl").addEventListener("click", async (ev) => {
    const btn = ev.currentTarget, out = document.getElementById("b-out"); out.innerHTML = "";
    const p1 = document.getElementById("bpw").value, p2 = document.getElementById("bpw2").value;
    if (p1 !== p2) return showError(out, "The passwords do not match.");
    busy(btn, "Encrypting…"); await nextFrame();
    try { download(`gnb-wallet-${state.address.slice(0, 14)}.json`, core.exportKeystore(p1)); unbusy(btn); out.innerHTML = `<div class="alert ok">Keystore downloaded.</div>`;
      document.getElementById("bpw").value = document.getElementById("bpw2").value = ""; }
    catch (e) { unbusy(btn); showError(out, e); }
  });
}

// Shareable watch links: /wallet#watch/<address>
async function boot() {
  const m = location.hash.match(/^#watch\/(gnb1[qt][0-9a-f]{48}|bloch1[qt][0-9a-f]{48})$/);
  if (m) {
    try { const c = await getCore(); return enter("watch", c.normalize(m[1])); } catch {}
  }
  renderGate();
}
boot();
