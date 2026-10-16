// Additive address format only: no node connection or transaction broadcast.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { loadCore } from "../wallet/core.js";

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

test("legacy normalization remains a valid control", async () => {
  const core = await coreInstance();
  assert.equal(core.normalize(LEGACY), LEGACY);
  assert.equal(core.normalize(LEGACY_TEST), LEGACY_TEST);
  assert.equal(core.normalize(LEGACY.replace("gnb1q", "bloch1q")), LEGACY);
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

test("both served wallet entry points load the pinned binary", async () => {
  const main = readFileSync(new URL("../wallet/main.js", import.meta.url), "utf8");
  const mainPin = main.match(/^const CORE_SHA256 = "([0-9a-f]{64})";$/m)?.[1];
  const original = globalThis.fetch;
  globalThis.fetch = async () => new Response(wasm);
  try {
    assert.equal((await loadCore("/wallet/gnb_wallet.wasm", pin)).normalize(LEGACY), LEGACY);
    assert.equal((await loadCore("/wallet/gnb_wallet.wasm", mainPin)).normalize(LEGACY), LEGACY);
  } finally { globalThis.fetch = original; }
});

const activationSource = readFileSync(new URL("../../crates/gnb-crypto/src/core/activation.rs", import.meta.url), "utf8");
const activation = Number(activationSource.match(/pub const MAINNET_HARDENING_ACTIVATION_HEIGHT:\s*u64\s*=\s*([0-9_]+);/)[1].replaceAll("_", ""));
const reference = fileURLToPath(new URL("../../reference", import.meta.url));
function decodedPayment(raw) {
  return JSON.parse(execFileSync("python3", ["-I", "-c", `
import json,sys
sys.path.insert(0,sys.argv[1])
import gnb_validity
tx=gnb_validity.decode_tx_strict(bytes.fromhex(sys.stdin.read()))
print(json.dumps({"version":tx.version,"value":tx.outputs[0].value,"script":tx.outputs[0].script_pubkey.hex()}))
`, reference], { input: raw, encoding: "utf8" }));
}

for (const [height, version] of [[activation - 1, 1], [activation, 3]]) {
  test(`actual WASM v2 payment preserves script and network at height ${height}`, async () => {
    const core = await coreInstance();
    const sender = core.create();
    const utxos = [{ txid: "33".repeat(32), index: 0, value: "500000000", script_pubkey: sender.address.slice(5, 45) }];
    const expected = { version, value: 100000000, script: "00".repeat(20) };
    try {
      const legacy = core.pay(utxos, LEGACY, "100000000", "0", height, {});
      assert.deepEqual(decodedPayment(legacy.raw), expected);
      const payment = core.pay(utxos, V2, "100000000", "0", height, {});
      assert.deepEqual(decodedPayment(payment.raw), expected);
      assert.throws(() => core.pay(utxos, V2_TEST, "100000000", "0", height, {}), /network/);
    } finally { core.wipe(); }
  });
}
