// GnB wallet core loader: runs gnb-wallet-wasm (wasm32-wasip1) in the browser.
// The secret key stays inside the WebAssembly memory; this file only moves
// JSON requests and responses. Randomness comes from crypto.getRandomValues.
const WASI_EBADF = 8, WASI_ESUCCESS = 0;

// A number may already have lost integer precision before JSON serialization.
// PQ-PSBT context values use exact decimal strings at the WASM boundary.
function exactContextInteger(value, name) {
  if (typeof value === "number" && !Number.isSafeInteger(value)) {
    throw new Error(`${name} must be an exact integer; use a decimal string`);
  }
  if (!["string", "number", "bigint"].includes(typeof value) || !/^(0|[1-9][0-9]*)$/.test(String(value))) {
    throw new Error(`${name} must be an unsigned decimal integer`);
  }
  return String(value);
}

// WAL-5: the SHA-256 of the binary is mandatory; app.js passes the hash that
// scripts/build-wallet-wasm.sh pins, and any other binary is refused.
export async function loadCore(url, sha256Hex) {
  if (typeof sha256Hex !== "string" || !/^[0-9a-f]{64}$/.test(sha256Hex)) {
    throw new Error("wallet core hash is not pinned; refusing to load it");
  }
  const bytes = new Uint8Array(await (await fetch(url, { cache: "no-cache" })).arrayBuffer());
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hex = [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
  if (hex !== sha256Hex) throw new Error("wallet core integrity check failed");
  let memory = null;
  const view = () => new DataView(memory.buffer);
  const u8 = () => new Uint8Array(memory.buffer);
  const wasi = {
    random_get(ptr, len) {
      const buf = u8().subarray(ptr, ptr + len);
      for (let off = 0; off < len; off += 65536) crypto.getRandomValues(buf.subarray(off, Math.min(len, off + 65536)));
      return WASI_ESUCCESS;
    },
    environ_sizes_get(countPtr, sizePtr) { view().setUint32(countPtr, 0, true); view().setUint32(sizePtr, 0, true); return WASI_ESUCCESS; },
    environ_get() { return WASI_ESUCCESS; },
    clock_time_get(_id, _precision, outPtr) {
      view().setBigUint64(outPtr, BigInt(Date.now()) * 1000000n, true);
      return WASI_ESUCCESS;
    },
    fd_write(fd, iovs, iovsLen, nwrittenPtr) {
      if (fd !== 1 && fd !== 2) return WASI_EBADF;
      let n = 0, text = "";
      for (let i = 0; i < iovsLen; i++) {
        const p = view().getUint32(iovs + i * 8, true), l = view().getUint32(iovs + i * 8 + 4, true);
        text += new TextDecoder().decode(u8().subarray(p, p + l)); n += l;
      }
      if (text.trim()) console.warn("[gnb-wallet-core]", text.trim());
      view().setUint32(nwrittenPtr, n, true);
      return WASI_ESUCCESS;
    },
    proc_exit(code) { throw new Error(`wallet core exited (${code})`); },
  };
  const { instance } = await WebAssembly.instantiate(bytes, { wasi_snapshot_preview1: wasi });
  memory = instance.exports.memory;
  const { gnb_alloc, gnb_call, gnb_free } = instance.exports;
  const enc = new TextEncoder(), dec = new TextDecoder();

  function call(req) {
    const input = enc.encode(JSON.stringify(req));
    const p = gnb_alloc(input.length);
    u8().set(input, p);
    let packed;
    try { packed = gnb_call(p, input.length); }
    finally { u8().fill(0, p, p + input.length); gnb_free(p, input.length); }
    const outPtr = Number(BigInt.asUintN(64, packed) >> 32n), outLen = Number(BigInt.asUintN(64, packed) & 0xffffffffn);
    const out = JSON.parse(dec.decode(u8().slice(outPtr, outPtr + outLen)));
    gnb_free(outPtr, outLen);
    if (out.error) throw new Error(out.error);
    return out.ok;
  }
  return {
    open: (json, password, network = "mainnet") => {
      if (network !== "mainnet" && network !== "testnet") throw new Error("unknown wallet network");
      return call({ op: "open", json, password, network });
    },
    // WAL-7: mainnet remains phrase-backed by default. The existing Rust
    // testnet path returns a random key backed up by its encrypted keystore.
    create: (testnet = false) => {
      if (typeof testnet !== "boolean") throw new Error("testnet must be a boolean");
      return call({ op: "create", mnemonic: true, testnet });
    },
    restore: (words) => call({ op: "restore", words }),
    exportKeystore: (password) => call({ op: "export", password }).keystore,
    // WAL-1: `nextHeight` is the node's getdaginfo next_block_height; it selects
    // the transaction version (3 / sighash v3 from the hardening activation
    // height, 1 below it). Version 1 only: the outpoints whose previous
    // transactions should be fetched...
    plan: (utxos, to, amount, fee, nextHeight) => call({ op: "plan", utxos, to, amount: String(amount), fee: String(fee), next_height: String(nextHeight) }),
    // ...and the payment, with those transactions (txid -> raw hex) so the
    // core can check the claimed UTXO values before it signs. A version-3
    // signature commits to every spent value, so nothing needs fetching.
    pay: (utxos, to, amount, fee, nextHeight, prevtxs = {}) => call({ op: "pay", utxos, to, amount: String(amount), fee: String(fee), next_height: String(nextHeight), prevtxs }),
    address: () => call({ op: "address" }).address,
    normalize: (address, format = "legacy") => call({ op: "normalize", address, format }).address,
    minFee: (size) => call({ op: "minfee", size }).fee,
    // BIP174-style public roles; the document remains a string so duplicate
    // JSON fields reach the strict shared parser. Caller-supplied `op` cannot
    // redirect this public-data binding to an operation using the session key.
    pqpsbt: (request) => call({ ...request, op: "pqpsbt" }),
    // Offline context is supplied by the signer. The core checks commitments
    // and fee/height/network, but cannot attest current chain unspentness.
    signPqPsbt: (hex, network, nextHeight, maxFee) => call({
      op: "pqpsbt_sign", hex, network,
      next_height: exactContextInteger(nextHeight, "nextHeight"),
      max_fee: exactContextInteger(maxFee, "maxFee"),
    }),
    wipe: () => call({ op: "wipe" }),
  };
}

// ── Which coins a payment can spend ──────────────────────────────────────────
// Coinbase outputs are spendable COINBASE_MATURITY blocks after the block that
// created them (gnb_crypto::core::COINBASE_MATURITY; site/tests pins the two).
export const COINBASE_MATURITY = 100;

/** Split getutxos rows into those spendable in the block at `nextHeight` and
 *  the immature coinbase outputs: a row carrying `coinbase_height` only from
 *  coinbase_height + COINBASE_MATURITY on, a row without it always (the rule
 *  of gnb_crypto::wallet::send::utxo_row_spendable_at, which the core and
 *  gnb-cli apply). A malformed coinbase_height counts as immature. */
export function splitByMaturity(rows, nextHeight) {
  const spendable = [], immature = [];
  for (const row of rows) {
    const cb = row.coinbase_height;
    const mature = cb === undefined || cb === null
      || (Number.isSafeInteger(cb) && cb >= 0 && nextHeight - cb >= COINBASE_MATURITY);
    (mature ? spendable : immature).push(row);
  }
  return { spendable, immature };
}

// One payment spends at most UTXO_WINDOW outputs (each input carries an
// ~8.5 kB post-quantum signature), so getutxos is asked for that many rows,
// and for UTXO_WIDE_WINDOW when immature coinbase outputs took part of a
// cut-short list. B2-T3: the explorer API accepts limits up to exactly
// UTXO_WIDE_WINDOW (deploy/explorer-api: GETUTXOS_MAX; its tests and
// site/tests/wallet-api-window.test.mjs keep the two equal).
export const UTXO_WINDOW = 50, UTXO_WIDE_WINDOW = 1000;

/** The coins one payment may spend in the block at `nextHeight`: the first
 *  `window` spendable rows the node lists, and the immature coinbase outputs
 *  seen. `fetchRows(limit)` resolves to { rows, truncated } from getutxos
 *  (the node lists an address's outputs in index order and sets `truncated`
 *  when it stops at the limit). When immature coinbase outputs took part of a
 *  truncated window, a `wide` one is asked for, so mature coins listed after
 *  them are found; `truncated` then says whether even that was cut short.
 *  B2-T3: if the wide request fails, the narrow result is kept (its mature
 *  coins stay spendable and `widenFailed` is set) instead of failing the
 *  whole refresh, which left the wallet with no balance and no coins. */
export async function spendableWindow(fetchRows, nextHeight, window = UTXO_WINDOW, wide = UTXO_WIDE_WINDOW) {
  let { rows, truncated } = await fetchRows(window);
  let { spendable, immature } = splitByMaturity(rows, nextHeight);
  let widenFailed = false;
  if (truncated && immature.length > 0 && wide > window) {
    try {
      const w = await fetchRows(wide);
      ({ rows, truncated } = w);
      ({ spendable, immature } = splitByMaturity(rows, nextHeight));
    } catch {
      widenFailed = true;
    }
  }
  return { spendable: spendable.slice(0, window), immature, truncated: truncated === true, listed: rows.length, widenFailed };
}

/** `fetchRows` for spendableWindow over the explorer API's getutxos:
 *  `api(method, params)` resolves to the method's `result` (throws on error). */
export function getutxosFetcher(api, address) {
  return async (limit) => {
    const r = await api("getutxos", [address, limit]);
    return { rows: Array.isArray(r.utxos) ? r.utxos : [], truncated: r.truncated === true };
  };
}
