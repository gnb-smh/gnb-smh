// Shared GnB client code for the explorer and the wallet (no dependencies).
// Data comes from the site's read-only /api (worker/index.js in production,
// tools/site-dev-server.py locally): GET /api/<method>?p=<JSON params>.

export async function api(method, params = []) {
  const r = await fetch(`/api/${method}?p=${encodeURIComponent(JSON.stringify(params))}`, { cache: "no-store" });
  const doc = await r.json();
  if (doc.error) throw new Error(typeof doc.error === "string" ? doc.error : JSON.stringify(doc.error));
  const res = doc.result;
  if (res && typeof res === "object" && !Array.isArray(res) && res.error) throw new Error(res.error);
  return res;
}

export async function broadcast(hex) {
  const r = await fetch("/api/sendrawtransaction", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ hex }),
  });
  const doc = await r.json();
  if (doc.error) throw new Error(doc.error);
  if (doc.result && doc.result.error) throw new Error(doc.result.error);
  return doc.result;
}

// ── SHA3-256 (FIPS 202), 32-bit lanes ───────────────────────────────────────
const RC = [
  [0x00000001, 0x00000000], [0x00008082, 0x00000000], [0x0000808a, 0x80000000], [0x80008000, 0x80000000],
  [0x0000808b, 0x00000000], [0x80000001, 0x00000000], [0x80008081, 0x80000000], [0x00008009, 0x80000000],
  [0x0000008a, 0x00000000], [0x00000088, 0x00000000], [0x80008009, 0x00000000], [0x8000000a, 0x00000000],
  [0x8000808b, 0x00000000], [0x0000008b, 0x80000000], [0x00008089, 0x80000000], [0x00008003, 0x80000000],
  [0x00008002, 0x80000000], [0x00000080, 0x80000000], [0x0000800a, 0x00000000], [0x8000000a, 0x80000000],
  [0x80008081, 0x80000000], [0x00008080, 0x80000000], [0x80000001, 0x00000000], [0x80008008, 0x80000000],
];
const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

function rotl(lo, hi, n) {
  if (n === 0) return [lo, hi];
  if (n >= 32) { [lo, hi] = [hi, lo]; n -= 32; }
  if (n === 0) return [lo, hi];
  return [((lo << n) | (hi >>> (32 - n))) >>> 0, ((hi << n) | (lo >>> (32 - n))) >>> 0];
}

function keccakF(s) {
  const C = new Uint32Array(10), B = new Uint32Array(50);
  for (let r = 0; r < 24; r++) {
    for (let x = 0; x < 5; x++) {
      C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
      C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
    }
    for (let x = 0; x < 5; x++) {
      const [rl, rh] = rotl(C[2 * ((x + 1) % 5)], C[2 * ((x + 1) % 5) + 1], 1);
      const dl = C[2 * ((x + 4) % 5)] ^ rl, dh = C[2 * ((x + 4) % 5) + 1] ^ rh;
      for (let y = 0; y < 5; y++) { s[2 * (x + 5 * y)] ^= dl; s[2 * (x + 5 * y) + 1] ^= dh; }
    }
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
      const i = x + 5 * y, j = y + 5 * ((2 * x + 3 * y) % 5);
      const [l, h] = rotl(s[2 * i], s[2 * i + 1], ROT[i]);
      B[2 * j] = l; B[2 * j + 1] = h;
    }
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) {
      const i = x + 5 * y, a = (x + 1) % 5 + 5 * y, b = (x + 2) % 5 + 5 * y;
      s[2 * i] = B[2 * i] ^ (~B[2 * a] & B[2 * b]);
      s[2 * i + 1] = B[2 * i + 1] ^ (~B[2 * a + 1] & B[2 * b + 1]);
    }
    s[0] ^= RC[r][0]; s[1] ^= RC[r][1];
  }
}

export function sha3_256(bytes) {
  const rate = 136, s = new Uint32Array(50);
  const msg = new Uint8Array(Math.ceil((bytes.length + 1) / rate) * rate);
  msg.set(bytes); msg[bytes.length] ^= 0x06; msg[msg.length - 1] ^= 0x80;
  const dv = new DataView(msg.buffer);
  for (let off = 0; off < msg.length; off += rate) {
    for (let i = 0; i < rate / 4; i++) s[i] ^= dv.getUint32(off + 4 * i, true);
    keccakF(s);
  }
  const out = new Uint8Array(32), ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(4 * i, s[i], true);
  return out;
}

// ── encodings ───────────────────────────────────────────────────────────────
export const hexToBytes = (h) => new Uint8Array((h.match(/../g) || []).map((b) => parseInt(b, 16)));
export const bytesToHex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const cat = (...parts) => { const o = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let i = 0; for (const p of parts) { o.set(p, i); i += p.length; } return o; };

/** Address of an output script: 20-byte key hash (gnb1q/gnb1t) or 33-byte policy (gnb1m/gnb1n). */
export function scriptToAddress(scriptHex, testnet) {
  const b = hexToBytes(scriptHex);
  if (b.length === 20) {
    const ck = sha3_256(sha3_256(b)).slice(0, 4);
    return (testnet ? "gnb1t" : "gnb1q") + bytesToHex(cat(b, ck));
  }
  if (b.length === 33 && b[0] === 0x02) {
    const prefix = testnet ? "gnb1n" : "gnb1m";
    const h = b.slice(1);
    const ck = sha3_256(sha3_256(cat(new TextEncoder().encode(prefix), h))).slice(0, 4);
    return prefix + bytesToHex(cat(h, ck));
  }
  return null;
}

/** Output script of an address (inverse of scriptToAddress); null when the checksum is wrong. */
export function addressToScript(addr) {
  const a = String(addr || "").trim().toLowerCase();
  const m = a.match(/^gnb1([qt])([0-9a-f]{48})$/) || a.match(/^gnb1([mn])([0-9a-f]{72})$/);
  if (!m) return null;
  const testnet = m[1] === "t" || m[1] === "n";
  const script = m[1] === "q" || m[1] === "t" ? m[2].slice(0, 40) : "02" + m[2].slice(0, 64);
  return scriptToAddress(script, testnet) === a ? script : null;
}

/** 20-byte marker a bridge release carries for a burn id. */
export function releaseMarker(burnIdHex) {
  return bytesToHex(sha3_256(cat(new TextEncoder().encode("GNB-RELEASE-v1"), hexToBytes(burnIdHex))).slice(0, 20));
}

// ── formatting ──────────────────────────────────────────────────────────────
export const gnb = (sats) => {
  const v = BigInt(sats ?? 0), whole = v / 100000000n, frac = (v % 100000000n).toString().padStart(8, "0").replace(/0+$/, "");
  return whole.toLocaleString("en-US") + (frac ? "." + frac : "");
};
export const short = (h, n = 8) => (h ? `${h.slice(0, n)}…${h.slice(-4)}` : "—");
export const ago = (ts) => {
  const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (s < 60) return `${s}s ago`; if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`; return `${Math.floor(s / 86400)}d ago`;
};
export const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
