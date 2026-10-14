// The committed wallet core, loaded exactly as the page loads it (core.js):
// pinned-hash check (WAL-5), phrase-backed create/restore (WAL-7), plan/pay
// with previous-transaction verification and the actual fee (WAL-1/WAL-6).
// node --test site/tests/*.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { loadCore } from "../wallet/core.js";

const wasm = readFileSync(new URL("../wallet/gnb_wallet.wasm", import.meta.url));
const pin = readFileSync(new URL("../wallet/app.js", import.meta.url), "utf8").match(/^const WASM_SHA256 = "([0-9a-f]{64})";$/m)[1];
globalThis.fetch = async () => new Response(wasm);

test("loadCore refuses a missing or wrong pin", async () => {
  await assert.rejects(loadCore("/wallet/gnb_wallet.wasm"), /not pinned/);
  await assert.rejects(loadCore("/wallet/gnb_wallet.wasm", "0".repeat(64)), /integrity check failed/);
});

test("phrase-backed wallet, plan, verified pay and the actual fee", async () => {
  const core = await loadCore("/wallet/gnb_wallet.wasm", pin);
  const created = core.create();
  assert.match(created.address, /^gnb1q[0-9a-f]{48}$/);
  assert.equal(created.words.split(" ").length, 24);
  core.wipe();
  assert.equal(core.restore(created.words).address, created.address);
  const ks = core.exportKeystore("Correct-Horse-9-battery");
  assert.match(ks, /"version": 3/);

  const spk = created.address.slice(5, 45);
  const utxos = [
    { txid: "11".repeat(32), index: 0, value: "500000000", script_pubkey: spk },
    { txid: "22".repeat(32), index: 0, value: "20000000", script_pubkey: spk },
  ];
  const dest = core.normalize(created.address); // own address is a valid destination
  const plan = core.plan(utxos, dest, "100000000", "0");
  assert.deepEqual(plan.prev_txids, ["11".repeat(32)], "one covering input, not the small one");
  // A transaction that does not hash to its claimed id is refused.
  assert.throws(() => core.pay(utxos, dest, "100000000", "0", { ["11".repeat(32)]: "00" }));
  const tx = core.pay(utxos, dest, "100000000", "0", {});
  assert.equal(tx.inputs, 1);
  assert.equal(tx.unverified_inputs, 1);
  assert.equal(BigInt(tx.fee), 500000000n - 100000000n - BigInt(tx.change));
  assert.ok(BigInt(tx.fee) < 100000n);
  // The fee guard holds even if a caller asks for a huge fee.
  assert.throws(() => core.pay(utxos, dest, "1", "490000000", {}), /guard/);
  core.wipe();
});
