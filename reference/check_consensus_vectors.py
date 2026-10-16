"""Independent check of the data-driven consensus vectors.

    python3 reference/check_consensus_vectors.py

reference/tx_vectors.json and reference/block_vectors.json are written by a
Rust generator (crates/gnb-crypto/tests/gen_consensus_vectors.rs) and checked
against the node by node/tests/consensus_vectors.rs. This script checks them
against the Python references instead, with no Rust in the loop:

* every recorded derived value (txid, wtxid, sizes, the sighash v2 and v3
  digest of every input, Merkle roots, witness root, parent commitment,
  subsidy, block id, wire and bincode sizes) is recomputed from the bytes
  (gnb_merkle, gnb_sighash, gnb_validity);
* every expected verdict is re-derived by gnb_validity, which implements every
  rule except the signature mathematics (the GnB-SMH proof of the `pow: full`
  blocks included, with reference/gnb_smh.py). A case whose expected class is
  `bad-signature` (or that is valid) must pass every other rule here; any
  other class must be exactly the first rule gnb_validity sees fail;
* every mempool verdict is re-derived by gnb_validity.admission the same way:
  accepted, or refused with exactly the recorded class of the first refusing
  admission rule (`bad-signature`: every other admission rule passes);
* a case whose `activation_source` is `schedule` records its network's
  activation height from docs/CONSENSUS.md.

Exit status 0 iff every check passes. Format: docs/testing/VECTORS.md.
"""

from __future__ import annotations

import json
import pathlib
import sys

import gnb_merkle as mk
import gnb_sighash as sh
import gnb_validity as gv

HERE = pathlib.Path(__file__).resolve().parent
CHAINS = {"mainnet": sh.CHAIN_MAINNET, "testnet": sh.CHAIN_TESTNET}


class Checker:
    def __init__(self):
        self.failures = []
        self.checks = 0

    def eq(self, case: str, what: str, want, got) -> None:
        self.checks += 1
        if want != got:
            self.failures.append(f"{case}: {what}: expected {want!r}, got {got!r}")


def to_sh(tx: mk.Tx) -> sh.Tx:
    return sh.Tx(tx.version, [sh.TxIn(i.prev_txid, i.prev_index, i.script_sig, i.sequence) for i in tx.inputs],
                 [sh.TxOut(o.value, o.script_pubkey) for o in tx.outputs], tx.locktime)


def view_of(prevouts: list) -> gv.View:
    v = gv.View()
    for p in prevouts:
        if p["source"] == "block-coinbase":
            continue
        txid = bytes.fromhex(p["txid"])
        v.utxos[(txid, p["vout"])] = mk.TxOut(int(p["amount"]), bytes.fromhex(p["script_pubkey"]))
        v.confirmed_txids.add(txid)
        if p["coinbase_height"] is not None:
            v.coinbase_heights[txid] = int(p["coinbase_height"])
        if p.get("coinbase_dag_height") is not None:
            v.coinbase_dag_heights[txid] = int(p["coinbase_dag_height"])
    return v


def verdict_of(fn) -> tuple[str, gv.Outcome]:
    out = gv.Outcome()
    try:
        fn(out)
        return "valid", out
    except gv.Invalid as e:
        return e.cls, out


def judge(chk: Checker, case: str, what: str, expected: str, got: str) -> None:
    """`got` is the first non-signature rule that fails, or "valid" when
    every rule but the signature mathematics holds."""
    if got == "valid":
        chk.eq(case, what, True, expected in ("valid", "bad-signature"))
    else:
        chk.eq(case, what, expected, got)


def check_activation_source(chk: Checker, cid: str, network: str, act: int, source: str) -> None:
    """`schedule`: the recorded height is the network's own schedule (the
    runners take it from the schedule); `explicit`: anything else."""
    schedule = gv.HARDENING_ACTIVATION_HEIGHT[network]
    chk.eq(cid, "activation_source", "schedule" if act == schedule else "explicit", source)


def check_constants(chk: Checker, c: dict) -> None:
    chk.eq("constants", "mainnet chain id", sh.CHAIN_MAINNET, c["chain_id_mainnet"])
    chk.eq("constants", "testnet chain id", sh.CHAIN_TESTNET, c["chain_id_testnet"])
    chk.eq("constants", "maturity", gv.COINBASE_MATURITY, c["coinbase_maturity"])
    chk.eq("constants", "dust", gv.DUST_THRESHOLD, c["dust_threshold"])
    chk.eq("constants", "max supply", gv.MAX_SUPPLY_SAT, int(c["max_supply_sat"]))
    chk.eq("constants", "min fee", gv.MIN_TX_FEE_SAT, c["min_tx_fee_sat"])
    chk.eq("constants", "min fee rate", gv.MIN_FEE_RATE_SAT_PER_KB, c["min_fee_rate_sat_per_kb"])
    chk.eq("constants", "initial subsidy", gv.INITIAL_SUBSIDY_SAT, c["initial_subsidy_sat"])
    chk.eq("constants", "halving interval", gv.HALVING_INTERVAL, c["halving_interval"])
    chk.eq("constants", "max block size", gv.MAX_BLOCK_SIZE, c["max_block_size"])
    chk.eq("constants", "max script", gv.MAX_SCRIPT_LEN, c["max_script_len"])
    chk.eq("constants", "pow limit", gv.POW_LIMIT_BITS, c["pow_limit_bits"])
    chk.eq("constants", "hardened pow limit", gv.HARDENED_POW_LIMIT_BITS, c["hardened_pow_limit_bits"])


def wrapper_block(tx: mk.Tx, height: int, prevouts: list, script_sig: bytes) -> gv.Block:
    cbp = [p for p in prevouts if p["source"] == "block-coinbase"]
    out = mk.TxOut(int(cbp[0]["amount"]), bytes.fromhex(cbp[0]["script_pubkey"])) if cbp else mk.TxOut(0, bytes(20))
    cb = mk.Tx(1, [mk.TxIn(bytes(32), 0xFFFFFFFF, script_sig, 0xFFFFFFFF)], [out], 0)
    if cbp:
        assert cb.txid().hex() == cbp[0]["txid"], "block-coinbase prevout is the wrapper coinbase's output 0"
    return gv.Block(gv.Header(1, [b"\x11" * 32], bytes(32), 0, 0, 0), [cb, tx], height, height)


def check_tx_vectors(chk: Checker) -> int:
    doc = json.loads((HERE / "tx_vectors.json").read_text())
    chk.eq("tx", "format", "gnb-consensus-tx-vectors/1", doc["format"])
    check_constants(chk, doc["constants"])
    wrapper_ss = bytes.fromhex(doc["constants"]["wrapper_coinbase_script_sig"])
    ids = set()
    for case in doc["cases"]:
        cid = case["id"]
        chk.eq(cid, "unique id", False, cid in ids)
        ids.add(cid)
        height, act = int(case["height"]), int(case["activation_height"])
        chk.eq(cid, "regime", "post-activation" if height >= act else "pre-activation", case["regime"])
        check_activation_source(chk, cid, case["network"], act, case["activation_source"])
        chain = CHAINS[case["network"]]
        expected = case["expected"]["error_class"] or "valid"
        chk.eq(cid, "verdict/class", case["expected"]["verdict"] == "valid", expected == "valid")
        policy, policy_class = case["policy"]["verdict"], case["policy"]["error_class"]
        chk.eq(cid, "policy verdict/class", policy == "accept", policy_class is None)
        raw = bytes.fromhex(case["tx"])
        try:
            tx = gv.decode_tx_strict(raw)
        except gv.DecodeError:
            chk.eq(cid, "consensus", expected, "decode")
            chk.eq(cid, "derived", None, case["derived"])
            chk.eq(cid, "policy class", "decode", policy_class)
            continue

        # Derived values.
        d = case["derived"]
        chk.eq(cid, "txid", d["txid"], tx.txid().hex())
        chk.eq(cid, "wtxid", d["wtxid"], tx.wtxid().hex())
        chk.eq(cid, "wire_size", d["wire_size"], len(tx.wire(True)))
        chk.eq(cid, "txid_preimage_size", d["txid_preimage_size"], len(tx.txid_preimage()))
        prev = {(bytes.fromhex(p["txid"]), p["vout"]): p for p in case["prevouts"]}
        spent = [prev.get((i.prev_txid, i.prev_index)) for i in tx.inputs]
        stx = to_sh(tx)
        chk.eq(cid, "digest count", len(tx.inputs), len(d["digests"]))
        for i, dg in enumerate(d["digests"]):
            chk.eq(cid, f"sighash_v2[{i}]", dg["sighash_v2"], sh.sighash_v2(stx, i, chain).hex())
            suite = gv.signature_suite(tx.inputs[i].script_sig)
            chk.eq(cid, f"sighash_v3_suite[{i}]", dg["sighash_v3_suite"], suite)
            if all(s is not None for s in spent):
                outs = [sh.TxOut(int(s["amount"]), bytes.fromhex(s["script_pubkey"])) for s in spent]
                chk.eq(cid, f"sighash_v3[{i}]", dg["sighash_v3"], sh.sighash_v3(stx, outs, i, suite, chain).hex())
            else:
                chk.eq(cid, f"sighash_v3[{i}]", None, dg["sighash_v3"])

        # Consensus.
        view = view_of(case["prevouts"])
        if case.get("dag_height") is not None:
            view.dag_height = int(case["dag_height"])
        block = wrapper_block(tx, height, case["prevouts"], wrapper_ss)

        def consensus(out):
            gv.tx_context_free(block, act)
            gv.connect_block(block, view, act, out)

        got, out = verdict_of(consensus)
        judge(chk, cid, "consensus", expected, got)
        if got == "valid":
            # Every input's signature was required under the digest the
            # version rule selects at this height.
            rule = sh.version_rule(tx.version, height, act)
            chk.eq(cid, "signatures required", [(i, rule) for i in range(len(tx.inputs))],
                   [(i, r) for (t, i, r, _) in out.signatures if t is tx])

        # Mempool admission: accepted, or refused with exactly the recorded
        # class (a consensus-invalid case is always refused).
        adm, _ = verdict_of(lambda out: gv.admission(tx, view, height, act, out))
        if expected != "valid":
            chk.eq(cid, "policy", "reject", policy)
        judge(chk, cid, "policy class", policy_class or "valid", adm)
    return len(doc["cases"])


def block_bytes(case: dict) -> bytes:
    if "block" in case:
        return bytes.fromhex(case["block"])
    return b"".join(bytes.fromhex(p["hex"]) * p["repeat"] for p in case["block_parts"])


def check_block_vectors(chk: Checker) -> int:
    doc = json.loads((HERE / "block_vectors.json").read_text())
    chk.eq("block", "format", "gnb-consensus-block-vectors/1", doc["format"])
    check_constants(chk, doc["constants"])
    for case in doc["cases"]:
        cid = case["id"]
        height, act = int(case["height"]), int(case["activation_height"])
        chk.eq(cid, "regime", "post-activation" if height >= act else "pre-activation", case["regime"])
        check_activation_source(chk, cid, case["network"], act, case["activation_source"])
        expected = case["expected"]["error_class"] or "valid"
        raw = block_bytes(case)
        try:
            b = gv.decode_block(raw)
        except gv.DecodeError:
            chk.eq(cid, "block", expected, "decode")
            chk.eq(cid, "derived", None, case["derived"])
            continue
        chk.eq(cid, "height", height, b.height)
        chk.eq(cid, "canonical encoding", True, b.wire() == raw)
        d = case["derived"]
        ids = [t.txid() for t in b.txs]
        chk.eq(cid, "block_hash", d["block_hash"], b.block_hash().hex())
        chk.eq(cid, "txids", d["txids"], [i.hex() for i in ids])
        chk.eq(cid, "legacy_merkle_root", d["legacy_merkle_root"], mk.legacy_merkle_root(ids).hex())
        chk.eq(cid, "tagged_merkle_root", d["tagged_merkle_root"], mk.tagged_merkle_root(ids).hex())
        chk.eq(cid, "witness_root", d["witness_root"], mk.witness_root(b.txs).hex() if b.txs else bytes(32).hex())
        chk.eq(cid, "parents_commitment", d["parents_commitment"], mk.parents_commitment(b.header.parents).hex())
        chk.eq(cid, "subsidy", int(d["subsidy"]), gv.subsidy(b.height))
        chk.eq(cid, "wire_size", d["wire_size"], len(raw))
        chk.eq(cid, "bincode_size", d["bincode_size"], gv.block_bincode_size(b))
        chk.eq(cid, "legacy_size", d["legacy_size"], gv.legacy_block_size(b))

        view = view_of(case["prevouts"])
        got, _ = verdict_of(lambda out: gv.validate_block(b, view, act, case["scope"], case["pow"], out))
        judge(chk, cid, "block", expected, got)
    return len(doc["cases"])


def main() -> int:
    chk = Checker()
    ntx = check_tx_vectors(chk)
    nblk = check_block_vectors(chk)
    print(f"consensus vectors: {ntx} tx cases, {nblk} block cases, {chk.checks} checks, {len(chk.failures)} failures")
    for f in chk.failures:
        print("  " + f)
    return 1 if chk.failures else 0


if __name__ == "__main__":
    sys.exit(main())
