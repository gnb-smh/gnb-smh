// GnB wallet core loader: runs gnb-wallet-wasm (wasm32-wasip1) in the browser.
// The secret key stays inside the WebAssembly memory; this file only moves
// JSON requests and responses. Randomness comes from crypto.getRandomValues.
const WASI_EBADF = 8, WASI_ESUCCESS = 0;

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
    open: (json, password) => call({ op: "open", json, password }),
    // WAL-7: phrase-backed by default; returns { address, public_key, words }.
    create: () => call({ op: "create", mnemonic: true }),
    restore: (words) => call({ op: "restore", words }),
    exportKeystore: (password) => call({ op: "export", password }).keystore,
    // WAL-1: `nextHeight` is the node's getdaginfo tip_height + 1; it selects
    // the transaction version (3 / sighash v3 from the hardening activation
    // height, 1 below it). Version 1 only: the outpoints whose previous
    // transactions should be fetched...
    plan: (utxos, to, amount, fee, nextHeight) => call({ op: "plan", utxos, to, amount: String(amount), fee: String(fee), next_height: String(nextHeight) }),
    // ...and the payment, with those transactions (txid -> raw hex) so the
    // core can check the claimed UTXO values before it signs. A version-3
    // signature commits to every spent value, so nothing needs fetching.
    pay: (utxos, to, amount, fee, nextHeight, prevtxs = {}) => call({ op: "pay", utxos, to, amount: String(amount), fee: String(fee), next_height: String(nextHeight), prevtxs }),
    address: () => call({ op: "address" }).address,
    normalize: (address) => call({ op: "normalize", address }).address,
    minFee: (size) => call({ op: "minfee", size }).fee,
    wipe: () => call({ op: "wipe" }),
  };
}
