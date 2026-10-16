#!/usr/bin/env node
// Audit WAL-2: check that Cloudflare verifies the explorer origin's TLS
// certificate before the Worker sends it the X-GnB-Key secret.
//
// The Worker's fetch() to an https:// origin goes through Cloudflare's edge,
// and the edge verifies the origin certificate ONLY in the SSL/TLS encryption
// mode "Full (strict)" (API value "strict", or "origin_pull" for "Strict
// (SSL-Only Origin Pull)"). In "Full" it accepts any certificate, self-signed
// included, so an attacker on the path between Cloudflare and a direct-TLS
// origin could present its own certificate, receive the secret and answer
// with forged balances and UTXO values. The Worker cannot see the mode or the
// certificate, so this script asks the Cloudflare API:
//
//   * the zone's SSL/TLS mode must be strict;
//   * no enabled Configuration Rule (phase http_config_settings) and no active
//     Page Rule that can match the API host name may lower it.
//
// Usage:
//   CF_API_TOKEN=... CF_ZONE_ID=... node worker/check-ssl-mode.mjs <api host name>
// The token needs Zone Settings:Read, Config Rules:Read and Page Rules:Read.
// Exit code 0 when the origin is verified, 1 otherwise (with the reasons).
// A Cloudflare Tunnel origin (deploy/explorer-api, layout A) is authenticated
// by the tunnel itself; the check still applies to its hostname's zone.

const API = "https://api.cloudflare.com/client/v4";
export const VERIFYING_MODES = new Set(["strict", "origin_pull"]);

async function cf(fetchFn, token, path) {
  const res = await fetchFn(`${API}${path}`, { headers: { authorization: `Bearer ${token}` } });
  let body = null;
  try { body = await res.json(); } catch { /* not JSON */ }
  return { status: res.status, body };
}

/** True when a rule expression may match `hostname`. Conservative: only an
 *  expression that restricts the host positively (http.host / full_uri
 *  equality or membership, no negation, no wildcard or regex match) to
 *  names other than `hostname` is taken not to match. */
export function mayMatchHost(expression, hostname) {
  const e = String(expression || "");
  if (e.includes(hostname)) return true;
  // Only http.host and http.request.full_uri restrict the host; a path or
  // address condition applies to every host name.
  if (!/http\.host|http\.request\.full_uri/.test(e)) return true;
  // A negated, pattern or "or" condition may still match this host.
  return /\bne\b|!=|\bnot\b|!|\bor\b|\|\||\bmatches\b|~|\bcontains\b|\bwildcard\b|ends_with|starts_with/.test(e);
}

/** Page Rule target pattern ("host/path*", wildcards allowed) that may match `hostname`. */
export function pageTargetMayMatchHost(pattern, hostname) {
  const host = String(pattern || "").replace(/^[a-z]+:\/\//i, "").split("/")[0];
  const re = new RegExp(`^${host.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`, "i");
  return re.test(hostname);
}

/**
 * Check the zone. Returns { ok, mode, problems: [string] }.
 * `fetchFn` is injectable for tests.
 */
export async function checkOriginTls({ token, zoneId, hostname, fetchFn = fetch }) {
  const problems = [];
  if (!token || !zoneId || !hostname) {
    return { ok: false, mode: null, problems: ["CF_API_TOKEN, CF_ZONE_ID and the API host name are required"] };
  }
  const zone = encodeURIComponent(zoneId);

  const ssl = await cf(fetchFn, token, `/zones/${zone}/settings/ssl`);
  const mode = ssl.body?.success ? ssl.body.result?.value : null;
  if (!mode) {
    problems.push(`cannot read the zone's SSL/TLS mode (HTTP ${ssl.status})`);
  } else if (!VERIFYING_MODES.has(mode)) {
    problems.push(`zone SSL/TLS mode is "${mode}": Cloudflare does not verify the origin certificate; set "Full (strict)"`);
  }

  const rules = await cf(fetchFn, token, `/zones/${zone}/rulesets/phases/http_config_settings/entrypoint`);
  if (rules.status === 404) {
    // No Configuration Rules in this zone.
  } else if (!rules.body?.success) {
    problems.push(`cannot read the zone's Configuration Rules (HTTP ${rules.status})`);
  } else {
    for (const rule of rules.body.result?.rules || []) {
      const lowered = rule.action_parameters?.ssl;
      if (rule.enabled === false || lowered === undefined || VERIFYING_MODES.has(lowered)) continue;
      if (mayMatchHost(rule.expression, hostname)) {
        problems.push(`Configuration Rule "${rule.description || rule.id}" sets SSL to "${lowered}" for ${hostname}`);
      }
    }
  }

  const pages = await cf(fetchFn, token, `/zones/${zone}/pagerules?status=active`);
  if (!pages.body?.success) {
    problems.push(`cannot read the zone's Page Rules (HTTP ${pages.status})`);
  } else {
    for (const rule of pages.body.result || []) {
      const action = (rule.actions || []).find((a) => a.id === "ssl");
      if (!action || VERIFYING_MODES.has(action.value)) continue;
      const targets = (rule.targets || []).map((t) => t.constraint?.value);
      if (targets.some((t) => pageTargetMayMatchHost(t, hostname))) {
        problems.push(`Page Rule ${targets.join(", ")} sets SSL to "${action.value}" for ${hostname}`);
      }
    }
  }
  return { ok: problems.length === 0, mode, problems };
}

const invokedDirectly = (() => {
  try { return import.meta.url === new URL(`file://${process.argv[1]}`).href; } catch { return false; }
})();

if (invokedDirectly) {
  const hostname = process.argv[2];
  const result = await checkOriginTls({
    token: process.env.CF_API_TOKEN, zoneId: process.env.CF_ZONE_ID, hostname,
  });
  if (result.ok) {
    console.log(`ok: ${hostname}: SSL/TLS mode "${result.mode}", the origin certificate is verified`);
  } else {
    for (const p of result.problems) console.error(`FAIL: ${p}`);
  }
  process.exit(result.ok ? 0 : 1);
}
