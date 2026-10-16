// Runtime routing tests: bounded public address fixtures, no network sockets.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";
import * as safe from "../assets/safe.js";
import worker from "../../worker/index.js";
import { loadCore } from "../wallet/core.js";

const LEGACY = "gnb1q0000000000000000000000000000000000000000335d2ee7";
const V2 = "gnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdaq6uw";
const CASES = [
  [V2, LEGACY],
  ["tgnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqtxkpzc", LEGACY.replace("gnb1q", "gnb1t")],
  ["gnb1zpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqggmvny", "gnb1m" + "00".repeat(32) + "73aa6055"],
  ["tgnb1zpqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqht5fkx", "gnb1n" + "00".repeat(32) + "6404365c"],
];
const src = (p) => readFileSync(new URL(p, import.meta.url), "utf8");
const noImports = (s) => s.replace(/^import .*;\n/gm, "");
const walletBytes = readFileSync(new URL("../wallet/gnb_wallet.wasm", import.meta.url));
const walletPin = src("../wallet/app.js").match(/^const WASM_SHA256 = "([0-9a-f]{64})";$/m)[1];
async function realCore() {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(walletBytes);
  try { return await loadCore("/wallet/gnb_wallet.wasm", walletPin); }
  finally { globalThis.fetch = original; }
}

function explorer(path, address, valid = true) {
  const elements = new Map(), calls = [];
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, { innerHTML: "", value: "", addEventListener(e, fn) { this[e] = fn; }, querySelectorAll: () => [] });
    return elements.get(id);
  };
  const canonical = CASES.find(([a]) => a === address.toLowerCase())?.[1] ?? address;
  const rpc = async (method, args) => {
    calls.push([method, args]);
    if (method === "validateaddress") return { isvalid: valid, canonical_address: valid ? canonical : undefined };
    // Match the dispatcher contract: history indexes only single-key hashes.
    if (method === "getaddresshistory" && /^gnb1[mn]/.test(args[0])) throw new Error("invalid address");
    if (method === "getutxos") return { satoshis: "0", utxo_count: 0, utxos: [] };
    return { balance: "0", utxo_count: 0, total: 0, items: [] };
  };
  const context = vm.createContext({
    ...safe, __rpc: rpc, location: { hash: "#/address/" + address },
    document: { getElementById: element, querySelector: (s) => element(s.slice(1)), querySelectorAll: () => [], addEventListener: () => {} },
    window: { addEventListener: () => {}, scrollTo: () => {} },
    clearInterval() {}, clearTimeout() {}, setInterval() {}, setTimeout() {},
    fetch: async () => ({ json: async () => ({ result: { in_carryover: false } }) }),
    localStorage: { getItem: () => "" }, gnb: String, short: String, ago: String,
    V: { loading: () => "loading", fail: String, addressPage: (a) => a },
  });
  let script = noImports(src(path));
  if (path === "../explorer.js") script = script.replace(/\nroute\(\);\s*$/, "");
  else script = script.slice(0, script.indexOf("async function netstatus()"));
  vm.runInContext(script + "\napi = __rpc;", context);
  return { context, calls, elements, route: () => vm.runInContext("route()", context), search: async (q) => {
    element("q").value = q;
    const el = element("search");
    await (el.submit || el.onsubmit)({ preventDefault() {} });
    return context.location.hash;
  } };
}

async function watch(path, address, accepts = true) {
  const calls = [];
  const core = await realCore();
  const code = src(path).slice(src(path).indexOf("// Shareable watch links:"));
  const context = vm.createContext({ ...safe, location: { hash: "#watch/" + address, pathname: "/wallet", search: "" },
    pollNetwork: async () => {}, history: { replaceState() {} }, setInterval() {},
    getCore: async () => ({ normalize(a) { calls.push(["normalize", a]); if (!accepts) throw Error("invalid address"); return core.normalize(a); } }),
    enter: (mode, a) => calls.push([mode, a]), renderGate: () => calls.push(["gate"]), route: () => calls.push(["gate"]),
  });
  await vm.runInContext(code, context);
  return calls;
}

test("legacy address gate, explorers and watch links remain controls", async () => {
  assert.equal(safe.isAddress(LEGACY), true);
  for (const path of ["../explorer.js", "../explorer/explorer.js"]) {
    const page = explorer(path, LEGACY); await page.route();
    assert.ok(page.calls.some(([m, p]) => ["getaddresshistory", "getutxos"].includes(m) && p[0] === LEGACY));
    assert.equal(await page.search(LEGACY), "#/address/" + LEGACY);
    page.context.location.hash = "#/";
    assert.equal(await page.search(LEGACY.toUpperCase()), "#/address/" + LEGACY);
  }
  for (const path of ["../wallet/app.js", "../wallet/main.js"]) {
    assert.deepEqual(await watch(path, LEGACY), [["normalize", LEGACY], ["watch", LEGACY]]);
  }
});

test("address syntax gate recognizes v2 and rejects unsafe path characters and mixed case", () => {
  for (const [a] of CASES) for (const c of [a, a.toUpperCase()]) assert.equal(safe.isAddress(c), true, c);
  for (const a of [V2 + '"', V2 + "/extra", V2 + "\n", V2.slice(0, -1), "G" + V2.slice(1), null]) assert.equal(safe.isAddress(a), false, String(a));
});

for (const path of ["../explorer.js", "../explorer/explorer.js"]) {
  test(`${path} routes all aliases through RPC normalization and rejects invalid checksums`, async () => {
    for (const [a, legacy] of CASES) for (const input of [a, a.toUpperCase()]) {
      const page = explorer(path, input); await page.route();
      assert.ok(page.calls.some(([m, p]) => m === "validateaddress" && p[0] === input), `${input}: checksum authority not called`);
      if (path === "../explorer.js" && /^gnb1[mn]/.test(legacy)) {
        assert.ok(!page.calls.some(([m]) => m === "getaddresshistory"), "policy must not call the single-key history index");
        assert.match(page.elements.get("app").innerHTML, /history is not available for policy addresses/i);
      } else {
        assert.ok(page.calls.some(([m, p]) => ["getaddresshistory", "getutxos"].includes(m) && p[0] === legacy), `${input}: identity not canonicalized`);
      }
      page.context.location.hash = "#/";
      assert.equal(await page.search(input), "#/address/" + input);
    }
    const bad = V2.slice(0, -1) + "q", page = explorer(path, bad, false);
    await page.route();
    assert.ok(page.calls.some(([m]) => m === "validateaddress"));
    assert.ok(!page.calls.some(([m]) => ["getaddresshistory", "getutxos"].includes(m)));
    page.context.location.hash = "#/";
    assert.equal(await page.search("G" + V2.slice(1)), "#/");
  });
}

for (const path of ["../wallet/app.js", "../wallet/main.js"]) {
  test(`${path} watch links use real WASM and keep the single-key scope`, async () => {
    for (const [a, legacy] of CASES) for (const input of [a, a.toUpperCase()]) {
      const expected = /^gnb1[mn]/.test(legacy) ? ["gate"] : ["watch", legacy];
      assert.deepEqual(await watch(path, input), [["normalize", input], expected]);
    }
    for (const [, legacy] of CASES.slice(2)) assert.deepEqual(await watch(path, legacy), [["normalize", legacy], ["gate"]]);
    assert.deepEqual(await watch(path, V2, false), [["normalize", V2], ["gate"]]);
    for (const a of [V2 + "/more", V2 + '"', "G" + V2.slice(1)]) assert.deepEqual(await watch(path, a), [["gate"]]);
  });
}

test("Worker forwards valid-shaped v2 aliases unchanged and retains legacy routing", async () => {
  const originalFetch = globalThis.fetch, originalCaches = globalThis.caches;
  const calls = [];
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  globalThis.fetch = async (url) => { calls.push(String(url)); return new Response('{"result":{}}'); };
  try {
    const env = { GNB_ORIGINS: "https://origin.example.net", GNB_API_KEY: "fixture" }, ctx = { waitUntil() {} };
    for (const a of [LEGACY, ...CASES.flatMap(([a]) => [a, a.toUpperCase()])]) {
      const result = await worker.fetch(new Request(`https://example.net/api/carryover/${a}`), env, ctx);
      assert.equal(result.status, 200, a);
      assert.equal(calls.at(-1), `https://origin.example.net/v1/carryover/${a}?p=%5B%5D`);
    }
    for (const a of ["G" + V2.slice(1), V2 + "%22", V2 + "%2Fextra"]) {
      assert.equal((await worker.fetch(new Request(`https://example.net/api/carryover/${a}`), env, ctx)).status, 404);
    }
  } finally { globalThis.fetch = originalFetch; globalThis.caches = originalCaches; }
});
