#!/usr/bin/env python3
"""Read-only HTTP API in front of a GnB node, for the gnb-smh.com explorer.

    GET /v1/<method>?p=<JSON array of params>     -> {"result": ...} | {"error": ...}
    GET /v1/carryover/<address>                    -> carryover share of one address
    GET /v1/health                                 -> {"ok": true, "height": ...}
    POST /v1/sendrawtransaction  body {"hex": ...}  -> broadcast a signed transaction

Only methods in ALLOWED are forwarded, with validated parameters, to the
node's localhost JSON-RPC. Responses are cached briefly. Every request must
carry the shared secret in X-GnB-Key (set by the Cloudflare Worker), so the
origin is not an open public API. Standard library only.

Environment:
    GNB_RPC_URL        node JSON-RPC (default http://127.0.0.1:17210/)
    GNB_API_BIND       bind address   (default 0.0.0.0)
    GNB_API_PORT       bind port      (default 2086)
    GNB_API_KEY_FILE   file holding the shared secret (required)
    GNB_CARRYOVER      uncompressed Bloch Genesis-3 carryover TSV (optional)
"""

import hashlib
import hmac
import json
import os
import re
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RPC_URL = os.environ.get("GNB_RPC_URL", "http://127.0.0.1:17210/")
BIND = os.environ.get("GNB_API_BIND", "0.0.0.0")
PORT = int(os.environ.get("GNB_API_PORT", "2086"))
with open(os.environ["GNB_API_KEY_FILE"], "r", encoding="utf-8") as fh:
    API_KEY = fh.readline().strip().encode()
if len(API_KEY) < 32:
    raise SystemExit("GNB_API_KEY_FILE must hold a secret of at least 32 characters")

HEX64 = re.compile(r"^[0-9a-f]{64}$")
ADDR = re.compile(r"^(gnb1[qt][0-9a-f]{48}|gnb1[mn][0-9a-f]{72})$")


def _int(lo, hi):
    def check(v):
        if isinstance(v, bool) or not isinstance(v, int) or not lo <= v <= hi:
            raise ValueError(f"integer in [{lo}, {hi}] expected")
        return v
    return check


def _re(rx, what):
    def check(v):
        if not isinstance(v, str) or not rx.match(v):
            raise ValueError(f"{what} expected")
        return v
    return check


HASH = _re(HEX64, "64-char lowercase hex")
ADDRESS = _re(ADDR, "gnb1q/gnb1t/gnb1m/gnb1n address")
U32 = _int(0, 2**32 - 1)
PAGE = _int(1, 100)
OFFSET = _int(0, 10**9)


def BOOL(v):
    if not isinstance(v, bool):
        raise ValueError("true or false expected")
    return v

# method -> (list of parameter checkers, cache seconds)
ALLOWED = {
    "getblockcount":           ([], 3),
    "getdaginfo":              ([], 3),
    "getnetworkinfo":          ([], 5),
    "getsupplyinfo":           ([], 10),
    "getchainstats":           ([], 30),
    "gethashrate":             ([], 30),
    "getdifficultyhistory":    ([_int(1, 500)], 30),
    "getblocktimepercentiles": ([], 30),
    "getmempoolstats":         ([], 5),
    "getrawmempool":           ([], 5),
    "getselectedchain":        ([OFFSET, PAGE], 3),
    "getblockdag":             ([HASH], 5),
    "gettransactionfull":      ([HASH], 5),
    "getdagwindow":            ([_int(1, 300)], 3),
    "getaddresshistory":       ([ADDRESS, PAGE, OFFSET], 5),
    "getbalance":              ([ADDRESS], 5),
    "getutxos":                ([ADDRESS, _int(1, 500)], 2),
    "getpowitinfo":            ([], 3),
    "getblock":                ([HASH, BOOL], 10),
    "getblockhash":            ([U32], 5),
    "gettransaction":          ([HASH], 5),
    "gettxstatus":             ([HASH], 3),
    "getrichlist":             ([PAGE, OFFSET], 60),
    "getsupplydistribution":   ([], 60),
    "validateaddress":         ([_re(re.compile(r"^.{1,80}$"), "string")], 60),
}

_cache = {}
_cache_lock = threading.Lock()
CACHE_MAX = 4096


def rpc(method, params):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC_URL, data=body, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        doc = json.loads(resp.read())
    if "result" in doc:
        res = doc["result"]
        if isinstance(res, dict) and "error" in res and len(res) <= 2:
            return {"error": res["error"]}
        return {"result": res}
    return {"error": doc.get("error", "node error")}


def cached(key, ttl, fn):
    now = time.monotonic()
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
    value = fn()
    with _cache_lock:
        if len(_cache) >= CACHE_MAX:
            _cache.clear()
        _cache[key] = (now + ttl, value)
    return value


# ── carryover share per address ─────────────────────────────────────────────

CARRY_ALLOC = 1_000_000 * 10**8
CARRY_SOURCE = 3_810_744_000 * 10**8
_carry = {}


def _address(h20: bytes, testnet=False) -> str:
    c = hashlib.sha3_256(hashlib.sha3_256(h20).digest()).digest()[:4]
    return ("gnb1t" if testnet else "gnb1q") + (h20 + c).hex()


def load_carryover(path):
    if not path or not os.path.exists(path):
        return
    out = {}
    with open(path, "rb") as fh:
        for line in fh:
            parts = line.rstrip(b"\n").split(b"\t")
            if len(parts) != 4:
                continue
            value = int(parts[2]) * CARRY_ALLOC // CARRY_SOURCE
            if value == 0:
                continue
            a = _address(bytes.fromhex(parts[3].decode()))
            v = out.setdefault(a, [0, 0, 0])
            v[0] += value
            v[1] += 1
            v[2] += int(parts[2])
    _carry.update(out)


def carryover_of(address):
    v = _carry.get(address)
    if not v:
        return {"result": {"address": address, "in_carryover": False}}
    return {"result": {"address": address, "in_carryover": True, "amount": str(v[0]),
                       "utxos": v[1], "bloch_amount": str(v[2])}}


# ── HTTP ─────────────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    server_version = "gnb-explorer-api"
    sys_version = ""

    def log_message(self, fmt, *args):  # quiet; systemd keeps errors only
        pass

    def send(self, code, doc, ttl=0):
        data = json.dumps(doc, separators=(",", ":")).encode()
        self.send_response(code)
        self.send_header("content-type", "application/json")
        self.send_header("cache-control", f"public, max-age={ttl}" if ttl and code == 200 else "no-store")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        key = self.headers.get("x-gnb-key", "").encode()
        if not hmac.compare_digest(key, API_KEY):
            return self.send(403, {"error": "forbidden"})
        url = urllib.parse.urlsplit(self.path)
        parts = [p for p in url.path.split("/") if p]
        if len(parts) < 2 or parts[0] != "v1":
            return self.send(404, {"error": "not found"})
        name = parts[1]
        try:
            if name == "health":
                r = rpc("getblockcount", [])
                return self.send(200, {"ok": "result" in r, "blocks": r.get("result")})
            if name == "carryover" and len(parts) == 3:
                ADDRESS(parts[2])
                return self.send(200, carryover_of(parts[2]), 300)
            if name not in ALLOWED or len(parts) != 2:
                return self.send(404, {"error": "unknown method"})
            checkers, ttl = ALLOWED[name]
            raw = urllib.parse.parse_qs(url.query).get("p", ["[]"])[0]
            if len(raw) > 512:
                raise ValueError("params too long")
            params = json.loads(raw)
            if not isinstance(params, list) or len(params) > len(checkers):
                raise ValueError("params must be a JSON array")
            params = [check(v) for check, v in zip(checkers, params)]
            ck = name + json.dumps(params)
            result = cached(ck, ttl, lambda: rpc(name, params))
            return self.send(200 if "result" in result else 404, result, ttl)
        except (ValueError, json.JSONDecodeError) as e:
            return self.send(400, {"error": str(e)})
        except Exception:  # node unreachable or timed out
            return self.send(502, {"error": "node unavailable"})


HEXTX = re.compile(r"^[0-9a-f]+$")
MAX_TX_HEX = 2 * 400 * 1024


class PostHandler(Handler):
    def do_POST(self):
        key = self.headers.get("x-gnb-key", "").encode()
        if not hmac.compare_digest(key, API_KEY):
            return self.send(403, {"error": "forbidden"})
        if urllib.parse.urlsplit(self.path).path != "/v1/sendrawtransaction":
            return self.send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("content-length", "0"))
            if not 0 < n <= MAX_TX_HEX + 64:
                raise ValueError("body size out of range")
            doc = json.loads(self.rfile.read(n))
            raw = doc.get("hex") if isinstance(doc, dict) else None
            if not isinstance(raw, str) or not raw or len(raw) > MAX_TX_HEX or len(raw) % 2 or not HEXTX.match(raw):
                raise ValueError("hex-encoded transaction expected")
            r = rpc("sendrawtransaction", [raw])
            return self.send(200 if "result" in r else 400, r)
        except (ValueError, json.JSONDecodeError) as e:
            return self.send(400, {"error": str(e)})
        except Exception:
            return self.send(502, {"error": "node unavailable"})


def main():
    threading.Thread(target=load_carryover, args=(os.environ.get("GNB_CARRYOVER"),), daemon=True).start()
    httpd = ThreadingHTTPServer((BIND, PORT), PostHandler)
    httpd.daemon_threads = True
    httpd.serve_forever()


if __name__ == "__main__":
    main()
