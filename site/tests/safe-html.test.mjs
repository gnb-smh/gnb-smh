// WAL-3: the escaping template and validators.  node --test site/tests/
import { test } from "node:test";
import assert from "node:assert/strict";
import { html, raw, esc, isHex64, isAddress, hex64, address, num, sats, Safe } from "../assets/safe.js";

const EVIL = `"><img src=x onerror=alert(1)><script>alert(2)</script>'\``;

test("html escapes every interpolation unless it is Safe", () => {
  const out = String(html`<a href="#/x/${EVIL}">${EVIL}</a>`);
  assert.ok(!out.includes("<img"));
  assert.ok(!out.includes("<script"));
  assert.ok(!out.includes(`"><`));
  assert.ok(out.includes("&lt;img src=x onerror=alert(1)&gt;"));
  assert.equal(String(html`<b>${html`<i>${"<"}</i>`}</b>`), "<b><i>&lt;</i></b>");
  assert.equal(String(html`${["<a>", html`<b>`]}`), "&lt;a&gt;<b>");
  assert.equal(String(html`${null}${undefined}${false}${0}`), "0");
  assert.ok(raw("<x>") instanceof Safe);
  assert.equal(esc("`'\""), "&#96;&#39;&quot;");
});

test("validators accept only canonical values", () => {
  assert.ok(isHex64("ab".repeat(32)));
  assert.ok(!isHex64("AB".repeat(32)));
  assert.ok(!isHex64("ab".repeat(32) + "\"><x"));
  assert.ok(isAddress("gnb1q" + "0".repeat(48)));
  assert.ok(!isAddress("gnb1q" + "0".repeat(47) + "\""));
  assert.equal(hex64({ toString: () => "x" }), "");
  assert.equal(address("javascript:alert(1)"), "");
  assert.equal(num("12"), 12);
  assert.ok(Number.isNaN(num("12px")));
  assert.ok(Number.isNaN(num("1;background:url(x)")));
  assert.ok(Number.isNaN(num(Infinity)));
  assert.equal(sats("100"), 100n);
  assert.equal(sats("-1"), null);
  assert.equal(sats("1e9"), null);
});
