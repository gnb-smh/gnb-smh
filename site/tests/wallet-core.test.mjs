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
  // Mainnet, next block far below the hardening activation (110,000): version 1.
  const next = 12;
  const plan = core.plan(utxos, dest, "100000000", "0", next);
  assert.equal(plan.version, 1);
  assert.deepEqual(plan.prev_txids, ["11".repeat(32)], "one covering input, not the small one");
  // A transaction that does not hash to its claimed id is refused.
  assert.throws(() => core.pay(utxos, dest, "100000000", "0", next, { ["11".repeat(32)]: "00" }));
  const tx = core.pay(utxos, dest, "100000000", "0", next, {});
  assert.equal(tx.version, 1);
  assert.equal(tx.inputs, 1);
  assert.equal(tx.unverified_inputs, 1);
  assert.equal(BigInt(tx.fee), 500000000n - 100000000n - BigInt(tx.change));
  assert.ok(BigInt(tx.fee) < 100000n);
  // The fee guard holds even if a caller asks for a huge fee.
  assert.throws(() => core.pay(utxos, dest, "1", "490000000", next, {}), /guard/);
  // Without the next block's height the core refuses to sign.
  assert.throws(() => core.pay(utxos, dest, "100000000", "0", undefined, {}), /next_height/);
  core.wipe();
});

test("from the activation height the core signs version 3 and fetches nothing", async () => {
  const core = await loadCore("/wallet/gnb_wallet.wasm", pin);
  const created = core.create();
  const spk = created.address.slice(5, 45);
  const utxos = [{ txid: "33".repeat(32), index: 1, value: "500000000", script_pubkey: spk }];
  const dest = core.normalize(created.address);
  const activation = 110000;
  const plan = core.plan(utxos, dest, "100000000", "0", activation);
  assert.equal(plan.version, 3);
  assert.deepEqual(plan.prev_txids, [], "a version-3 signature commits every spent value");
  const tx = core.pay(utxos, dest, "100000000", "0", activation, {});
  assert.equal(tx.version, 3);
  assert.equal(tx.amounts_committed, true);
  assert.equal(tx.unverified_inputs, 0);
  // The raw transaction starts with version 3 (u32 little-endian).
  assert.equal(tx.raw.slice(0, 8), "03000000");
  // One block earlier: version 1.
  assert.equal(core.plan(utxos, dest, "100000000", "0", activation - 1).version, 1);
  core.wipe();
});
