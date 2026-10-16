// Known-answer tests for the shared client code (open /shared/selftest.html).
import { sha3_256, bytesToHex, scriptToAddress, addressToScript } from "./gnb.js";
const enc = new TextEncoder();
const cases = [
  ["sha3('')", bytesToHex(sha3_256(enc.encode(""))), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"],
  ["sha3('abc')", bytesToHex(sha3_256(enc.encode("abc"))), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"],
  ["sha3('a'*200)", bytesToHex(sha3_256(enc.encode("a".repeat(200)))), "cce34485baf2bf2aca99b94833892a4f52896d3d153f7b840cc4f9fe695f1387"],
  ["key-hash address", scriptToAddress("ea0f0318d222b8a67d068585ca62be563763784b", true), "gnb1tea0f0318d222b8a67d068585ca62be563763784b59305d6b"],
  ["policy address", scriptToAddress("02271c84e79e9ba72eb60a82efe783032d479fe6a20802bb973832ea45555bd4cc", true),
   "gnb1n271c84e79e9ba72eb60a82efe783032d479fe6a20802bb973832ea45555bd4ccd566e13e"],
  ["policy address -> script", addressToScript("gnb1n271c84e79e9ba72eb60a82efe783032d479fe6a20802bb973832ea45555bd4ccd566e13e"),
   "02271c84e79e9ba72eb60a82efe783032d479fe6a20802bb973832ea45555bd4cc"],
  ["key-hash address -> script", addressToScript("gnb1tea0f0318d222b8a67d068585ca62be563763784b59305d6b"), "ea0f0318d222b8a67d068585ca62be563763784b"],
  ["bad checksum rejected", String(addressToScript("gnb1n271c84e79e9ba72eb60a82efe783032d479fe6a20802bb973832ea45555bd4ccd566e13f")), "null"],
];
const lines = cases.map(([n, got, want]) => `${got === want ? "PASS" : "FAIL"} ${n}${got === want ? "" : ` got ${got}`}`);
document.getElementById("out").textContent = lines.join("\n") + `\n${lines.every((l) => l.startsWith("PASS")) ? "ALL PASS" : "FAILURES"}`;
