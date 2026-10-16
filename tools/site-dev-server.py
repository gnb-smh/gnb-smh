#!/usr/bin/env python3
"""Local preview of gnb-smh.com: serves ./site and mimics the Worker's /api.

    python3 tools/site-dev-server.py [--port 8088] [--rpc http://127.0.0.1:18401]

    GET  /api/<method>?p=<JSON params>   -> node JSON-RPC <method>(params)  (read-only allowlist)
    POST /api/sendrawtransaction {"hex"} -> node sendrawtransaction           (signed tx only)
    everything else                      -> static files from ./site

Same shape as worker/index.js + deploy/explorer-api, so the explorer and the
wallet run unchanged against any node (a local testnet included). Standard
library only. For development: binds 127.0.0.1.
"""
import json
import re
import sys
import urllib.parse
import urllib.request
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def arg(name, default):
    a = sys.argv[1:]
    return a[a.index(name) + 1] if name in a else default


PORT = int(arg('--port', '8088'))
RPC = arg('--rpc', 'http://127.0.0.1:18401')
SITE = Path(__file__).resolve().parent.parent / 'site'
READ = {
    'getnetworkinfo', 'getdaginfo', 'getpowitinfo', 'getsupplyinfo', 'getchainstats', 'gethashrate',
    'getdifficultyhistory', 'getblocktimepercentiles', 'getmempoolstats', 'getrawmempool', 'getselectedchain',
    'getdagwindow', 'getrecentblocks', 'getblock', 'getblockbyheight', 'getblockhash', 'gettransaction',
    'gettxstatus', 'getbalance', 'getutxos', 'getaddressinfo', 'validateaddress', 'estimatefee',
    'getsupplydistribution', 'getpeerinfo', 'decoderawtransaction', 'getaddresshistory',
}
NAME = re.compile(r'^[a-z]{2,40}$')


def rpc(method, params):
    body = json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode()
    req = urllib.request.Request(RPC, data=body, headers={'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=30) as r:
        doc = json.loads(r.read())
    res = doc.get('result')
    if isinstance(res, dict) and 'error' in res and len(res) <= 2:
        return {'error': res['error']}
    return {'result': res} if 'result' in doc else {'error': doc.get('error', 'node error')}


class Handler(SimpleHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send_json(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header('content-type', 'application/json')
        self.send_header('cache-control', 'no-store')
        self.send_header('content-length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def end_headers(self):
        self.send_header('x-content-type-options', 'nosniff')
        super().end_headers()

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        if not u.path.startswith('/api/'):
            return super().do_GET()
        method = u.path[5:].strip('/')
        if not NAME.match(method) or method not in READ:
            return self.send_json({'error': 'not found'}, 404)
        try:
            params = json.loads(urllib.parse.parse_qs(u.query).get('p', ['[]'])[0])
            if not isinstance(params, list) or len(json.dumps(params)) > 512:
                raise ValueError
        except ValueError:
            return self.send_json({'error': 'bad params'}, 400)
        try:
            self.send_json(rpc(method, params))
        except Exception as e:  # noqa: BLE001
            self.send_json({'error': f'node unavailable: {e}'}, 502)

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != '/api/sendrawtransaction':
            return self.send_json({'error': 'method not allowed'}, 405)
        n = int(self.headers.get('content-length', '0'))
        if n > 900_000:
            return self.send_json({'error': 'too large'}, 413)
        try:
            hexstr = json.loads(self.rfile.read(n))['hex']
            if not re.fullmatch(r'[0-9a-f]+', hexstr):
                raise ValueError
            self.send_json(rpc('sendrawtransaction', [hexstr]))
        except Exception as e:  # noqa: BLE001
            self.send_json({'error': f'{e}'}, 400)


if __name__ == '__main__':
    srv = ThreadingHTTPServer(('127.0.0.1', PORT), partial(Handler, directory=str(SITE)))
    print(f'GnB site on http://127.0.0.1:{PORT}/  ·  /api -> {RPC}')
    srv.serve_forever()
