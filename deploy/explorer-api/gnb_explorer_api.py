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

Hardening (audit WAL-2, WAL-4, NET-12):
  * binds 127.0.0.1 by default: expose it through a Cloudflare Tunnel, or
    terminate TLS here (GNB_API_TLS_CERT/KEY) behind the Cloudflare-only
    firewall of firewall-cloudflare.sh; see README.md;
  * every connection has a socket timeout AND an absolute deadline, so idle
    or slow-drip (slowloris) clients cannot hold a worker;
  * at most GNB_API_MAX_CONNECTIONS connections are served at once; further
    connections are refused immediately instead of spawning threads;
  * requests are rate-limited per ORIGINAL client: the X-GnB-Client-IP header
    the Worker sets from CF-Connecting-IP (trusted only on requests that carry
    the shared key), else the peer address.

Environment:
    GNB_RPC_URL              node JSON-RPC (default http://127.0.0.1:17210/)
    GNB_API_BIND             bind address   (default 127.0.0.1)
    GNB_API_PORT             bind port      (default 2086)
    GNB_API_KEY_FILE         file holding the shared secret (required, mode 0600/0640)
    GNB_API_TLS_CERT         PEM certificate chain: serve HTTPS (optional)
    GNB_API_TLS_KEY          PEM private key for GNB_API_TLS_CERT
    GNB_API_TIMEOUT          per-read socket timeout, seconds (default 10)
    GNB_API_DEADLINE         absolute per-connection deadline, seconds (default 30)
    GNB_API_MAX_CONNECTIONS  concurrent connections (default 64)
    GNB_API_RATE_PER_MIN     GET requests per client per minute (default 240)
    GNB_API_POST_PER_MIN     broadcasts per client per minute (default 6)
    GNB_CARRYOVER            uncompressed Bloch Genesis-3 carryover TSV (optional)
"""

import hashlib
import hmac
import json
import os
import re
import socket
import ssl
import stat
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RPC_URL = os.environ.get("GNB_RPC_URL", "http://127.0.0.1:17210/")
API_KEY = b""

HEX64 = re.compile(r"^[0-9a-f]{64}$")
ADDR = re.compile(r"^gnb1[qt][0-9a-f]{48}$")
IP_TEXT = re.compile(r"^[0-9a-fA-F:.]{2,45}$")


def load_api_key(path):
    """Read the shared secret; refuse group/world-writable or world-readable files."""
    st = os.stat(path)
    if st.st_mode & (stat.S_IWGRP | stat.S_IRWXO):
        raise SystemExit(f"{path}: the API key file must be mode 0600 or 0640")
    with open(path, "r", encoding="utf-8") as fh:
        key = fh.readline().strip().encode()
    if len(key) < 32:
        raise SystemExit("GNB_API_KEY_FILE must hold a secret of at least 32 characters")
    return key


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
ADDRESS = _re(ADDR, "gnb1q/gnb1t address")
U32 = _int(0, 2**32 - 1)
PAGE = _int(1, 100)
OFFSET = _int(0, 10**9)
RICH_OFFSET = _int(0, 10_000)

# method -> (list of parameter checkers, cache seconds)
ALLOWED = {
    "getblockcount":           ([], 3),
    "getdaginfo":              ([], 3),
    "getnetworkinfo":          ([], 5),
    "getsupplyinfo":           ([], 10),
    "getchainstats":           ([], 30),
    "gethashrate":             ([], 30),
    # NET-12: the node caps this at 100 points; bounded walk, single-flight.
    "getdifficultyhistory":    ([_int(1, 100)], 30),
    "getblocktimepercentiles": ([], 30),
    "getmempoolstats":         ([], 5),
    "getrawmempool":           ([], 5),
    "getselectedchain":        ([OFFSET, PAGE], 3),
    "getblockdag":             ([HASH], 5),
    "gettransactionfull":      ([HASH], 5),
    # WAL-1: raw bytes of a previous transaction, hashed by the wallet.
    "getrawtransaction":       ([HASH], 60),
    "getdagwindow":            ([_int(1, 300)], 3),
    "getaddresshistory":       ([ADDRESS, PAGE, OFFSET], 5),
    "getbalance":              ([ADDRESS], 5),
    "getutxos":                ([ADDRESS, _int(1, 50)], 2),
    # NET-12: served from the node's incremental holder index; the node
    # serves offsets up to analytics::MAX_RICHLIST_OFFSET = 10,000.
    "getrichlist":             ([PAGE, RICH_OFFSET], 60),
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


# ── per-client rate limiting (WAL-4) ────────────────────────────────────────

class RateLimiter:
    """Fixed-window counter per client and bucket, bounded in size."""

    def __init__(self, per_min, max_clients=50_000):
        self.per_min = per_min
        self.max_clients = max_clients
        self.windows = {}
        self.lock = threading.Lock()

    def allow(self, client):
        now = int(time.monotonic() // 60)
        with self.lock:
            window, n = self.windows.get(client, (now, 0))
            if window != now:
                window, n = now, 0
            if n >= self.per_min:
                return False
            if client not in self.windows and len(self.windows) >= self.max_clients:
                self.windows = {k: v for k, v in self.windows.items() if v[0] == now}
                if len(self.windows) >= self.max_clients:
                    return False
            self.windows[client] = (window, n + 1)
            return True


GET_LIMIT = RateLimiter(int(os.environ.get("GNB_API_RATE_PER_MIN", "240")))
POST_LIMIT = RateLimiter(int(os.environ.get("GNB_API_POST_PER_MIN", "6")))


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
    # Per-read socket timeout (BaseHTTPRequestHandler applies it in setup()).
    timeout = float(os.environ.get("GNB_API_TIMEOUT", "10"))
    # Absolute deadline for a whole connection, whatever the client sends.
    deadline = float(os.environ.get("GNB_API_DEADLINE", "30"))

    def setup(self):
        super().setup()
        self._timer = threading.Timer(self.deadline, self._expire)
        self._timer.daemon = True
        self._timer.start()

    def _expire(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        self._timer.cancel()
        try:
            super().finish()
        except OSError:
            pass

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

    def authorized(self):
        key = self.headers.get("x-gnb-key", "").encode()
        return bool(API_KEY) and hmac.compare_digest(
            hashlib.sha256(key).digest(), hashlib.sha256(API_KEY).digest())

    def client(self):
        """The original client: the Worker's X-GnB-Client-IP (only trusted on
        authorized requests), else CF-Connecting-IP, else the peer address."""
        for header in ("x-gnb-client-ip", "cf-connecting-ip"):
            v = self.headers.get(header, "").strip()
            if v and IP_TEXT.match(v):
                return v
        return self.client_address[0]

    def do_GET(self):
        if not self.authorized():
            return self.send(403, {"error": "forbidden"})
        if not GET_LIMIT.allow(self.client()):
            return self.send(429, {"error": "rate limit exceeded; retry in a minute"})
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
        if not self.authorized():
            return self.send(403, {"error": "forbidden"})
        if urllib.parse.urlsplit(self.path).path != "/v1/sendrawtransaction":
            return self.send(404, {"error": "not found"})
        if not POST_LIMIT.allow(self.client()):
            return self.send(429, {"error": "rate limit exceeded; retry in a minute"})
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


class BoundedServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a hard cap on concurrent connections: a
    connection beyond the cap is closed at once instead of getting a thread."""

    daemon_threads = True
    request_queue_size = 128

    def __init__(self, addr, handler, max_connections=64, ssl_context=None):
        self.slots = threading.BoundedSemaphore(max_connections)
        self.ssl_context = ssl_context
        super().__init__(addr, handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def handle_error(self, request, client_address):
        # Connections cut at the deadline or dropped by the client are routine.
        if isinstance(sys.exc_info()[1], (OSError, ssl.SSLError)):
            return
        super().handle_error(request, client_address)

    def process_request_thread(self, request, client_address):
        try:
            if self.ssl_context is not None:
                request.settimeout(Handler.timeout)
                request = self.ssl_context.wrap_socket(request, server_side=True)
            super().process_request_thread(request, client_address)
        except (OSError, ssl.SSLError):
            self.shutdown_request(request)
        finally:
            self.slots.release()


def make_server(bind, port, max_connections, cert=None, key=None):
    ctx = None
    if cert or key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
    return BoundedServer((bind, port), PostHandler, max_connections, ctx)


def main():
    global API_KEY
    API_KEY = load_api_key(os.environ["GNB_API_KEY_FILE"])
    bind = os.environ.get("GNB_API_BIND", "127.0.0.1")
    port = int(os.environ.get("GNB_API_PORT", "2086"))
    cert, key = os.environ.get("GNB_API_TLS_CERT"), os.environ.get("GNB_API_TLS_KEY")
    if bind not in ("127.0.0.1", "::1", "localhost") and not cert:
        raise SystemExit("refusing to serve plain HTTP on a non-loopback address; set "
                         "GNB_API_TLS_CERT/GNB_API_TLS_KEY or use a Cloudflare Tunnel (README.md)")
    threading.Thread(target=load_carryover, args=(os.environ.get("GNB_CARRYOVER"),), daemon=True).start()
    httpd = make_server(bind, port, int(os.environ.get("GNB_API_MAX_CONNECTIONS", "64")), cert, key)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
