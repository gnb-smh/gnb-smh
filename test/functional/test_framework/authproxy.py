"""Minimal JSON-RPC 2.0 client for the gnb node (urllib, no dependencies).

The node's conventions (node/src/rpc/mod.rs):
  * transport errors use HTTP status + a JSON-RPC `error` object
    (401 unauthorized -32001, 429 rate limited -32002, 403 Host/Origin
    policy -32003, 400 batch -32600);
  * most method-level failures are an HTTP 200 whose `result` is an object
    with an `error` field (e.g. `{"error": "rejected: ..."}`).
Both become JSONRPCException here, so tests can assert on either uniformly.
"""

from __future__ import annotations

import itertools
import json
import urllib.error
import urllib.request

_ids = itertools.count(1)


class JSONRPCException(Exception):
    def __init__(self, error: dict, http_status: int | None = None, method: str = ""):
        self.error = error if isinstance(error, dict) else {"message": str(error)}
        self.code = self.error.get("code")
        self.message = str(self.error.get("message", self.error))
        self.http_status = http_status
        self.method = method
        super().__init__(f"{method}: {self.message} (code={self.code}, http={http_status})")


class AuthServiceProxy:
    """`proxy.getblockcount()` → result, or raises JSONRPCException."""

    def __init__(self, url: str, api_key: str | None = None, timeout: float = 60,
                 headers: dict | None = None):
        self.url = url
        self.api_key = api_key
        self.timeout = timeout
        self.headers = dict(headers or {})

    def with_key(self, api_key: str | None) -> "AuthServiceProxy":
        """A copy that presents `api_key` (None: no X-API-Key header)."""
        return AuthServiceProxy(self.url, api_key, self.timeout, self.headers)

    def with_headers(self, **headers) -> "AuthServiceProxy":
        h = dict(self.headers)
        h.update(headers)
        return AuthServiceProxy(self.url, self.api_key, self.timeout, h)

    def raw(self, method: str, params=None) -> tuple[int, dict]:
        """One request; returns (http_status, decoded JSON body). Never raises
        for an HTTP error status (tests of the auth layer need the status)."""
        body = {"jsonrpc": "2.0", "id": next(_ids), "method": method}
        if params is not None:
            body["params"] = params
        headers = {"Content-Type": "application/json"}
        headers.update(self.headers)
        if self.api_key is not None:
            headers["X-API-Key"] = self.api_key
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers,
                                     method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw or b"null")
            except ValueError:
                return e.code, {"error": {"message": raw.decode("utf-8", "replace")}}

    def call(self, method: str, *params):
        status, resp = self.raw(method, list(params) if params else None)
        if not isinstance(resp, dict):
            raise JSONRPCException({"message": f"malformed response {resp!r}"}, status, method)
        if resp.get("error") is not None:
            raise JSONRPCException(resp["error"], status, method)
        if status != 200:
            raise JSONRPCException({"message": f"HTTP {status}"}, status, method)
        result = resp.get("result")
        if isinstance(result, dict) and "error" in result:
            err = result["error"]
            raise JSONRPCException(err if isinstance(err, dict) else {"message": err}, status, method)
        return result

    def __getattr__(self, name: str):
        if name.startswith("__"):
            raise AttributeError(name)
        return lambda *params: self.call(name, *params)
