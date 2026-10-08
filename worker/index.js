// gnb-smh.com: static site plus a read-only explorer API proxy.
//
//   /api/<method>?p=<JSON params>  -> origin /v1/<method>  (edge-cached briefly)
//   everything else                -> static assets in ./site
//
// The origin is the explorer API on a GnB node. It accepts only requests that
// carry the shared secret (Worker secret GNB_API_KEY), so the node is reached
// exclusively through this Worker.
const ORIGINS = ["http://139-84-201-52.sslip.io:2086", "http://149-28-180-128.sslip.io:2086", "http://67-219-108-96.sslip.io:2086"];
const NAME = /^[a-z0-9]{2,40}$/;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return withSecurityHeaders(url, await env.ASSETS.fetch(request));
    if (url.pathname === "/api/sendrawtransaction") return broadcast(request, env);
    if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
    const rest = url.pathname.slice(5).split("/").filter(Boolean);
    if (!rest.length || !rest.every((s) => NAME.test(s) || /^gnb1[qt][0-9a-f]{48}$/.test(s))) {
      return json({ error: "not found" }, 404);
    }
    const p = url.searchParams.get("p") || "[]";
    if (p.length > 512) return json({ error: "params too long" }, 400);
    const cacheKey = new Request(`https://cache.gnb-smh.com/${rest.join("/")}?p=${encodeURIComponent(p)}`);
    const cache = caches.default;
    const hit = await cache.match(cacheKey);
    if (hit) return hit;

    let last = null;
    for (const origin of ORIGINS) {
      try {
        const r = await fetch(`${origin}/v1/${rest.join("/")}?p=${encodeURIComponent(p)}`, {
          headers: { "x-gnb-key": env.GNB_API_KEY },
          cf: { cacheTtl: 0 },
          signal: AbortSignal.timeout(8000),
        });
        if (r.status >= 500) { last = r; continue; }
        const body = await r.text();
        const headers = {
          "content-type": "application/json",
          "cache-control": r.headers.get("cache-control") || "no-store",
          "access-control-allow-origin": "*",
          "x-content-type-options": "nosniff",
        };
        const resp = new Response(body, { status: r.status, headers });
        if (r.status === 200 && /max-age=[1-9]/.test(headers["cache-control"])) {
          ctx.waitUntil(cache.put(cacheKey, resp.clone()));
        }
        return resp;
      } catch (e) {
        last = null;
      }
    }
    return json({ error: "explorer backend unavailable" }, last ? last.status : 502);
  },
};

// Signed transactions from the web wallet. The node re-validates everything;
// this only bounds the size and shape.
async function broadcast(request, env) {
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
  const len = Number(request.headers.get("content-length") || "0");
  if (!(len > 0 && len <= 820000)) return json({ error: "body size out of range" }, 413);
  const body = await request.text();
  let last = 502;
  for (const origin of ORIGINS) {
    try {
      const r = await fetch(`${origin}/v1/sendrawtransaction`, {
        method: "POST",
        headers: { "x-gnb-key": env.GNB_API_KEY, "content-type": "application/json" },
        body,
        signal: AbortSignal.timeout(20000),
      });
      if (r.status >= 500) { last = r.status; continue; }
      return new Response(await r.text(), { status: r.status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
    } catch (e) { last = 502; }
  }
  return json({ error: "broadcast backend unavailable" }, last);
}

// The wallet handles keys: lock it to same-origin code and no framing.
const WALLET_CSP = [
  "default-src 'self'", "script-src 'self' 'wasm-unsafe-eval'", "connect-src 'self'",
  "img-src 'self' data:", "style-src 'self' 'unsafe-inline'", "font-src 'self' data:",
  "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
].join("; ");

function withSecurityHeaders(url, resp) {
  const h = new Headers(resp.headers);
  h.set("x-content-type-options", "nosniff");
  h.set("referrer-policy", "no-referrer");
  if (url.pathname === "/wallet" || url.pathname.startsWith("/wallet/") || url.pathname === "/wallet.html") {
    h.set("content-security-policy", WALLET_CSP);
    h.set("x-frame-options", "DENY");
    h.set("cross-origin-opener-policy", "same-origin");
    if (url.pathname.endsWith(".wasm")) h.set("content-type", "application/wasm");
  }
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: h });
}

function json(doc, status) {
  return new Response(JSON.stringify(doc), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });
}
