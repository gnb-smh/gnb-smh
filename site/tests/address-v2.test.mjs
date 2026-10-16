// Additive address format only: no node connection or transaction broadcast.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadCore } from "../wallet/core.js";
import { isAddress } from "../assets/safe.js";
import worker from "../../worker/index.js";

// Generated independently from the agreed BIP350 application contract.
const V2 = "gnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdaq6uw";
const V2_TEST = "tgnb1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqtxkpzc";
const LEGACY = "gnb1q0000000000000000000000000000000000000000335d2ee7";
const LEGACY_TEST = LEGACY.replace("gnb1q", "gnb1t");
const wasm = readFileSync(new URL("../wallet/gnb_wallet.wasm", import.meta.url));
const pin = readFileSync(new URL("../wallet/app.js", import.meta.url), "utf8")
  .match(/^const WASM_SHA256 = "([0-9a-f]{64})";$/m)[1];

async function coreInstance() {
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(wasm);
  try { return await loadCore("/wallet/gnb_wallet.wasm", pin); }
  finally { globalThis.fetch = original; }
}

test("legacy normalization and address routing remain valid controls", async () => {
  const core = await coreInstance();
  assert.equal(core.normalize(LEGACY), LEGACY);
  assert.equal(core.normalize(LEGACY_TEST), LEGACY_TEST);
  assert.equal(core.normalize(LEGACY.replace("gnb1q", "bloch1q")), LEGACY);
  assert.ok(isAddress(LEGACY));
});

test("pinned WASM normalizes v2 aliases without changing network or identity", async () => {
  const core = await coreInstance();
  assert.equal(core.normalize(V2), LEGACY);
  assert.equal(core.normalize(V2_TEST), LEGACY_TEST);
  assert.equal(core.normalize(V2.toUpperCase()), LEGACY);
  assert.throws(() => core.normalize(V2.replace(/^gnb/, "tgnb")));
});

test("v2 normalization output is explicit and legacy remains the default", async () => {
  const core = await coreInstance();
  assert.equal(core.normalize(LEGACY, "bech32m"), V2);
  assert.equal(core.normalize(LEGACY_TEST, "bech32m"), V2_TEST);
  assert.equal(core.normalize(V2), LEGACY);
  assert.throws(() => core.normalize(LEGACY, "unknown-format"));
});

test("browser address syntax gate accepts the new lowercase form", () => {
  assert.ok(isAddress(V2));
  assert.ok(isAddress(V2_TEST));
  assert.ok(!isAddress(V2 + "\""));
  assert.ok(!isAddress(V2 + "/extra"));
});

test("Worker forwards an ordinary v2 carryover path", async () => {
  const originalFetch = globalThis.fetch, originalCaches = globalThis.caches;
  const calls = [];
  globalThis.caches = { default: { match: async () => undefined, put: async () => {} } };
  globalThis.fetch = async (url) => { calls.push(String(url)); return new Response('{"result":{}}'); };
  try {
    const env = { GNB_ORIGINS: "https://origin.example.net", GNB_API_KEY: "fixture" };
    const ctx = { waitUntil: () => {} };
    const control = await worker.fetch(new Request(`https://example.net/api/carryover/${LEGACY}`), env, ctx);
    assert.equal(control.status, 200);
    const result = await worker.fetch(new Request(`https://example.net/api/carryover/${V2}`), env, ctx);
    assert.equal(result.status, 200);
    assert.equal(calls.at(-1), `https://origin.example.net/v1/carryover/${V2}?p=%5B%5D`);
  } finally { globalThis.fetch = originalFetch; globalThis.caches = originalCaches; }
});

test("explorer API accepts v2 parameters and preserves carryover identity", () => {
  const path = fileURLToPath(new URL("../../deploy/explorer-api/gnb_explorer_api.py", import.meta.url));
  const script = `
import importlib.util,json,sys
spec=importlib.util.spec_from_file_location("address_v2_api",sys.argv[1])
api=importlib.util.module_from_spec(spec); spec.loader.exec_module(api)
legacy,v2=sys.argv[2:]
assert api.ADDRESS(legacy)==legacy
api._carry[legacy]=[12345,2,67890]
assert api.carryover_of(legacy)["result"]["amount"]=="12345"
assert api.ADDRESS(v2)==v2
value=api.carryover_of(v2)["result"]
assert value["in_carryover"] is True
assert value["amount"]=="12345"
assert value["utxos"]==2
print(json.dumps(value))
`;
  const result = JSON.parse(execFileSync("python3", ["-I", "-c", script, path, LEGACY, V2], { encoding: "utf8" }));
  assert.equal(result.amount, "12345");
});
