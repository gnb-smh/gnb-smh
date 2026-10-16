// Offline journeys through the served /wallet/index.html controller and the
// actual pinned WASM. API mocks return ordinary synthetic chain records;
// signing stays real, and no network request or broadcast is performed.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import vm from "node:vm";
import { loadCore, splitByMaturity, COINBASE_MATURITY } from "../wallet/core.js";

const source = readFileSync(new URL("../wallet/main.js", import.meta.url), "utf8");
const wasm = readFileSync(new URL("../wallet/gnb_wallet.wasm", import.meta.url));
const pin = source.match(/^const CORE_SHA256 = "([0-9a-f]{64})";/m)[1];
const activationSource = readFileSync(new URL("../../crates/gnb-crypto/src/core/activation.rs", import.meta.url), "utf8");
const H = Number(activationSource.match(/MAINNET_HARDENING_ACTIVATION_HEIGHT:\s*u64\s*=\s*([0-9_]+);/)[1].replaceAll("_", ""));
const LEGACY = "gnb1q0000000000000000000000000000000000000000335d2ee7";
const V2 = "gnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdaq6uw";
const TESTNET = "tgnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqtxkpzc";
const PASSWORD = "Synthetic-test-wallet-9!";
let core, sender, funding;

async function actualCore() {
  const saved = globalThis.fetch;
  globalThis.fetch = async () => new Response(wasm);
  try { return await loadCore("/wallet/gnb_wallet.wasm", pin); }
  finally { globalThis.fetch = saved; }
}

// A normal previous transaction with one output paying this session key.
// Its txid omits the non-coinbase scriptSig length, as specified in CONSENSUS.
function previousTransaction(script, value = 500000000n) {
  const prefix = Buffer.from("0100000001" + "11".repeat(32) + "00000000", "hex");
  const amount = Buffer.alloc(8); amount.writeBigUInt64LE(value);
  const suffix = Buffer.concat([Buffer.from("ffffffff01", "hex"), amount,
    Buffer.from([20]), Buffer.from(script, "hex"), Buffer.alloc(4)]);
  const hash = b => createHash("sha256").update(b).digest();
  const txid = hash(hash(Buffer.concat([prefix, suffix]))).toString("hex");
  return { raw: Buffer.concat([prefix, Buffer.from([0]), suffix]).toString("hex"),
    row: { txid, index: 0, value: String(value), script_pubkey: script } };
}

before(async () => {
  core = await actualCore(); sender = core.create();
  funding = previousTransaction(sender.address.slice(5, 45));
});
after(() => core?.wipe());

// Deliberately small DOM adapter: HTML assignment creates/removes elements,
// reads disabled/checked attributes, and registers actual event handlers.
function dom() {
  const nodes = new Map();
  function add(id) {
    const children = new Set(); let markup = "";
    const element = { value: "", disabled: false, checked: false, handlers: {}, focus() {},
      addEventListener(event, fn) { this.handlers[event] = fn; },
      async click() { if (!this.disabled) return this.handlers.click?.({ currentTarget: this, target: this }); },
      async change(checked) { this.checked = checked; return this.handlers.change?.({ currentTarget: this, target: this }); },
      get innerHTML() { return markup; },
      set innerHTML(html) {
        for (const child of children) nodes.delete(child); children.clear(); markup = html;
        for (const match of html.matchAll(/<[^>]*\bid="([^"]+)"[^>]*>/g)) {
          const child = add(`#${match[1]}`); children.add(`#${match[1]}`);
          child.disabled = /\sdisabled(?:\s|>|=)/.test(match[0]);
          child.checked = /\schecked(?:\s|>|=)/.test(match[0]);
        }
      },
    };
    nodes.set(id, element); return element;
  }
  return { content: add("content"), get: id => nodes.get(id) || null };
}

async function review({ next = H, destination = V2, rows = [funding.row], previous = funding.raw, dagError, dag = { next_block_height: next, tip_height: 7 } } = {}) {
  const ui = dom(), calls = [], paid = [], planned = [], broadcasts = [];
  const planAttempts = [], payAttempts = [];
  const tracked = { ...core,
    // Count before entering WASM: an exception is still an attempted call.
    plan(...args) { planAttempts.push(args); const plan = core.plan(...args); planned.push({ args, plan }); return plan; },
    pay(...args) { payAttempts.push(args); const tx = core.pay(...args); paid.push({ args, tx }); return tx; },
  };
  const api = async (method, params) => {
    calls.push({ method, params });
    if (method === "getdaginfo") { if (dagError) throw dagError; return dag; }
    if (method === "getrawtransaction") {
      assert.deepEqual(Array.from(params), [funding.row.txid]);
      if (previous === null) throw Error("transaction pruned");
      return { hex: previous };
    }
    throw Error(`Unexpected API method: ${method}`);
  };
  const context = vm.createContext({ content: ui.content, $: ui.get, api, splitByMaturity,
    net: { testnet: false, height: 7 }, st: { spendable: rows, spendableTotal: 500000000n },
    hero: () => "", MAX_INPUTS: 50, paintHeroNumbers: () => {}, getCore: async () => tracked,
    parseGnb: () => 100000000n, busy: b => { b.disabled = true; }, unbusy: b => { b.disabled = false; }, nextFrame: async () => {},
    errBox: e => String(e?.message || e), gnb: String, esc: String, fmt: String,
    broadcast: async raw => { broadcasts.push(raw); throw Error("No broadcast is performed by this test"); },
  });
  const start = source.indexOf("// ── send "), end = source.indexOf("// ── receive", start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(source.slice(start, end) + "\nviewSend();", context);
  ui.get("#to").value = destination; ui.get("#amt").value = "1";
  await ui.get("#review").click();
  return { ui, calls, planned, paid, planAttempts, payAttempts, broadcasts, html: ui.get("#out").innerHTML };
}

function gate(c, testnet) {
  const ui = dom(), entered = [], downloaded = [];
  const context = vm.createContext({ content: ui.content, $: ui.get,
    net: { ok: true, testnet, network: testnet ? "testnet" : "mainnet" },
    getCore: async () => c, esc: String, errBox: e => String(e?.message || e),
    busy: b => { b.disabled = true; }, unbusy: b => { b.disabled = false; }, nextFrame: async () => {},
    enter: (...args) => entered.push(args), download: (...args) => downloaded.push(args),
  });
  const start = source.indexOf("function renderGate()"), end = source.indexOf("// ── wallet (home)", start);
  assert.ok(start >= 0 && end > start);
  vm.runInContext(source.slice(start, end) + "\nrenderGate();", context);
  return { ui, entered, downloaded, async open(keystore) {
    ui.get("#file").files = [{ name: "synthetic.json", size: keystore.length, text: async () => keystore }];
    await ui.get("#file").handlers.change(); ui.get("#pw").value = PASSWORD;
    await ui.get("#open").click();
  } };
}

test("positive control: the pinned core accepts these previous transactions at H-1 and H", () => {
  for (const next of [H - 1, H]) {
    const tx = core.pay([funding.row], LEGACY, "100000000", "0", next, { [funding.row.txid]: funding.raw });
    assert.equal(tx.version, next < H ? 1 : 3);
    assert.equal(tx.unverified_inputs, 0);
    assert.equal(tx.verified_inputs, 1);
  }
});

for (const next of [H - 1, H]) for (const destination of [LEGACY, V2]) {
  test(`secondary payment review signs ${destination === V2 ? "v2" : "legacy"} at ${next === H ? "H" : "H-1"} using the node's next_block_height`, async () => {
    const r = await review({ next, destination });
    assert.match(r.html, /Confirm and send/);
    assert.equal(r.paid.length, 1);
    assert.equal(r.paid[0].tx.version, next < H ? 1 : 3);
    assert.equal(r.paid[0].args[4], next, "tip_height + 1 is deliberately wrong");
    assert.equal(r.planned.length, 1);
    assert.equal(r.planAttempts.length, 1); assert.equal(r.payAttempts.length, 1);
    assert.deepEqual(r.calls.map(c => c.method), next < H ? ["getdaginfo", "getrawtransaction"] : ["getdaginfo"]);
    assert.equal(r.ui.get("#confirm").disabled, false);
    assert.equal(r.paid[0].tx.unverified_inputs, 0);
    assert.deepEqual(r.broadcasts, []);
  });
}

test("secondary review requires next_block_height, and never signs after a failed or malformed height response", async () => {
  for (const input of [{ dagError: Error("node unavailable") }, { dag: { tip_height: H - 1 } },
    ...[null, 0, -1, 1.5, true, "", " ", "17500.1", Number.MAX_SAFE_INTEGER + 1].map(next_block_height => ({ dag: { next_block_height, tip_height: H - 1 } }))]) {
    const r = await review(input);
    assert.deepEqual(r.calls.map(c => c.method), ["getdaginfo"]);
    assert.equal(r.paid.length, 0); assert.equal(r.planned.length, 0);
    assert.equal(r.planAttempts.length, 0); assert.equal(r.payAttempts.length, 0);
    assert.equal(r.ui.get("#confirm"), null);
    assert.match(r.html, /node unavailable|next block height/i);
  }
});

test("secondary review rejects a destination on another network", async () => {
  const r = await review({ destination: TESTNET });
  assert.equal(r.paid.length, 0); assert.equal(r.ui.get("#confirm"), null);
  assert.equal(r.planAttempts.length, 1); assert.equal(r.payAttempts.length, 1);
  assert.match(r.html, /network/i);
});

test("secondary review rechecks coinbase maturity at the current next height", async () => {
  const cb = { ...funding.row, coinbase_height: H - COINBASE_MATURITY };
  const early = await review({ next: H - 1, rows: [cb] });
  assert.equal(early.paid.length, 0); assert.equal(early.planned.length, 0);
  assert.equal(early.planAttempts.length, 0); assert.equal(early.payAttempts.length, 0);
  assert.match(early.html, /No spendable outputs at the next block/);
  const mature = await review({ next: H, rows: [cb] });
  assert.equal(mature.paid.length, 1); assert.match(mature.html, /Confirm and send/);
  assert.equal(mature.planAttempts.length, 1); assert.equal(mature.payAttempts.length, 1);
  const mixed = await review({ next: H - 1, rows: [{ ...cb, index: 1 }, funding.row] });
  // Discard the immature row before even asking the core to plan the payment.
  assert.equal(mixed.planned.length, 1);
  assert.equal(mixed.planAttempts.length, 1); assert.equal(mixed.payAttempts.length, 1);
  assert.deepEqual(mixed.planned[0].args[0].map(row => row.index), [0]);
  assert.equal(mixed.paid.length, 1);
  for (const coinbase_height of ["17400", -1, H]) {
    const rejected = await review({ rows: [{ ...funding.row, coinbase_height }] });
    assert.equal(rejected.paid.length, 0); assert.equal(rejected.planned.length, 0);
    assert.equal(rejected.planAttempts.length, 0); assert.equal(rejected.payAttempts.length, 0);
  }
});

test("secondary review makes missing previous values visible and requires explicit acknowledgement before confirmation", async () => {
  for (const previous of [null, undefined]) {
    // `undefined` in the response represents missing metadata, not a successful raw lookup.
    const r = await review({ next: H - 1, previous: previous === undefined ? 0 : previous });
    assert.equal(r.paid.length, 1);
    assert.equal(r.paid[0].tx.unverified_inputs, 1);
    assert.match(r.html, /could not be checked against their transaction/);
    assert.equal(r.ui.get("#confirm").disabled, true);
    await r.ui.get("#confirm").click();
    await r.ui.get("#confirm").handlers.click({ currentTarget: r.ui.get("#confirm") });
    assert.deepEqual(r.broadcasts, []);
    const accept = r.ui.get("#accept-unverified"); assert.ok(accept);
    await accept.change(true); assert.equal(r.ui.get("#confirm").disabled, false);
    await accept.change(false); assert.equal(r.ui.get("#confirm").disabled, true);
  }
});

test("secondary review refuses supplied previous transaction bytes that do not verify", async () => {
  const r = await review({ next: H - 1, previous: "00" });
  assert.equal(r.paid.length, 0); assert.equal(r.ui.get("#confirm"), null);
  assert.equal(r.planAttempts.length, 1); assert.equal(r.payAttempts.length, 1);
  assert.match(r.html, /previous|transaction|decode|truncat/i);
});

test("mainnet default creation, recovery words and encrypted keystore remain compatible", async () => {
  const c = await actualCore();
  try {
    const created = c.create(); assert.match(created.address, /^gnb1q/);
    assert.equal(created.words.split(" ").length, 24);
    const ks = c.exportKeystore(PASSWORD); c.wipe();
    assert.equal(c.open(ks, PASSWORD).address, created.address); c.wipe();
    assert.equal(c.restore(created.words).address, created.address);
  } finally { c.wipe(); }
});

test("explicit testnet creation uses the Rust testnet path", async () => {
  const c = await actualCore();
  try {
    const created = c.create(true);
    assert.match(created.address, /^gnb1t/);
    assert.equal(created.words, undefined, "the existing Rust testnet key path has no recovery phrase");
    const ks = c.exportKeystore(PASSWORD); c.wipe();
    assert.equal(c.open(ks, PASSWORD, "testnet").address, created.address);
  } finally { c.wipe(); }
});

test("opening a keystore respects an explicit expected network", async () => {
  const c = await actualCore();
  try {
    c.create(); const ks = c.exportKeystore(PASSWORD); c.wipe();
    assert.throws(() => c.open(ks, PASSWORD, "testnet"), /network|testnet/i);
    assert.match(c.open(ks, PASSWORD).address, /^gnb1q/);
  } finally { c.wipe(); }
});

test("explicit network arguments reject mistyped values before changing a session", async () => {
  const c = await actualCore();
  try {
    const created = c.create();
    for (const value of ["testnet", 1, null, {}]) assert.throws(() => c.create(value), /boolean/);
    for (const value of [true, 1, null, {}, "other"]) assert.throws(() => c.open("", PASSWORD, value), /network/);
    assert.equal(c.address(), created.address);
  } finally { c.wipe(); }
});

test("secondary testnet create/download/open journey keeps the same testnet identity", async () => {
  const c = await actualCore();
  try {
    const created = gate(c, true);
    created.ui.get("#npw").value = PASSWORD; created.ui.get("#npw2").value = PASSWORD;
    await created.ui.get("#create").click();
    assert.equal(created.entered.length, 1);
    assert.match(created.entered[0][1], /^gnb1t/);
    assert.equal(created.downloaded.length, 1); c.wipe();
    const reopened = gate(c, true); await reopened.open(created.downloaded[0][1]);
    assert.equal(reopened.entered.length, 1, reopened.ui.get("#open-msg").innerHTML);
    assert.equal(reopened.entered[0][1], created.entered[0][1]);
  } finally { c.wipe(); }
});

test("secondary opening selects the node network instead of silently opening a mainnet key on testnet", async () => {
  const c = await actualCore();
  try {
    c.create(); const ks = c.exportKeystore(PASSWORD); c.wipe();
    const rejected = gate(c, true); await rejected.open(ks);
    assert.equal(rejected.entered.length, 0);
    assert.match(rejected.ui.get("#open-msg").innerHTML, /network|testnet/i);
    const accepted = gate(c, false); await accepted.open(ks);
    assert.equal(accepted.entered.length, 1);
    assert.match(accepted.entered[0][1], /^gnb1q/);
  } finally { c.wipe(); }
});
