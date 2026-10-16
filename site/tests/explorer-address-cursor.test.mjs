// B1-T11 (review): the explorer pages an address's history with the cursor
// the node returns (next_cursor); the node and the explorer API refuse
// offsets above max_offset (10,000), so offset links past it were dead ends.
// node --test site/tests/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as V from "../assets/explorer-views.js";

const A = "gnb1q" + "cd".repeat(24);
const C = "0f".repeat(16);
const item = { height: 7, txid: "ab".repeat(32), direction: "in", amount: "1" };
const page = (h, n) => String(V.addressPage(A, { balance: "1", utxo_count: 1, max_offset: 10000, items: [item], ...h }, null, n, 25));

test("Older follows next_cursor, also beyond the offset cap", () => {
  const s = page({ total: 1_000_000, next_cursor: C }, 500);
  assert.ok(s.includes(`href="#/address/${A}/501/${C}"`), s);
  // Newer from a page beyond the cap goes to the newest page, never to an
  // offset the node refuses.
  assert.ok(s.includes(`href="#/address/${A}"`) && !s.includes(`/address/${A}/499"`), s);
  // Within the cap the offset form stays.
  assert.ok(page({ total: 100, next_cursor: C }, 2).includes(`href="#/address/${A}/1"`));
});

test("no cursor on the last page, and a forged cursor is not linked", () => {
  assert.ok(!page({ total: 25, next_cursor: null }, 0).includes(`href="#/address/${A}/1`));
  assert.ok(!page({ total: 1000, next_cursor: `"><x` }, 0).includes(`"><x`));
});

test("the address route passes the cursor to getaddresshistory", () => {
  const src = readFileSync(new URL("../explorer.js", import.meta.url), "utf8");
  assert.match(src, /cursor \? \[addr, per, 0, cursor\] : \[addr, per, page \* per\]/);
  assert.match(src, /viewAddress\(a, pageNo\(b\), \/\^\[0-9a-f\]\{32\}\$\/\.test\(c \|\| ""\) \? c : null\)/);
});
