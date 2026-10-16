#!/usr/bin/env python3
"""Production-only reversals; final tests/instrumentation remain unchanged."""
import argparse, difflib, hashlib, json, os, pathlib, subprocess
ROOT=pathlib.Path('/Users/tiagobulhoes/worktrees/gnb-technology-pqpsbt')
OUT=pathlib.Path('/private/tmp/gnb-pqpsbt-evidence')
CORE='crates/gnb-crypto/src/wallet/pqpsbt.rs'
POLICY='crates/gnb-crypto/src/wallet/policy_spend.rs'
WASM='crates/gnb-wallet-wasm/src/lib.rs'
CASES=[
 ('policy-shape',POLICY,'        self.check_signing_shape()?;\n        let idx =','        let idx =','gnb-crypto','pqpsbt_policy_signer_checks_all_amounts_before_the_signing_callback'),
 ('wasm-public',WASM,'        "pqpsbt" => gnb_crypto::wallet::pqpsbt::public_request(req),','        "pqpsbt" => Err("unknown op pqpsbt".into()),','gnb-wallet-wasm','pqpsbt_public_decode_reaches_the_format_parser'),
 ('fee-ceiling',CORE,'if fee > context.max_fee {','if false {','gnb-crypto','pqpsbt_signer_rejects_bad_public_data_before_callback_and_honors_activation'),
 ('verification-budget',CORE,'    limit(&p, max_inputs, max_signatures)?;','    // Reversal: omit initial transport budget.','gnb-crypto','pqpsbt_max_transport_budget_measures_48_verifications_and_zero_when_over'),
 ('request-fields',CORE,'    check_request_fields(request, fields)?;','    let _ = fields;','gnb-crypto','pqpsbt_public_request_rejects_unknown_and_secret_fields'),
 ('json-cap',CORE,'pub const MAX_JSON_BYTES: usize = 2 * MAX_BYTES + 256 * 1024;','pub const MAX_JSON_BYTES: usize = 16 * 1024 * 1024;','gnb-crypto','pqpsbt_binary_limit_preserves_equivalent_bounded_json'),
 ('wasm-session-network',WASM,'                Address::parse_for_network(&kp.address, context.network).map_err(|e| e.to_string())?;','                // Reversal: omit independently selected session network.','gnb-wallet-wasm','pqpsbt_wasm_roles_sign_in_session_and_reject_bad_context'),
]
# Subsequent independent-review fixes, preserving the final test source.
core_text=(ROOT/CORE).read_text()
money_start=core_text.index('        let total_outputs = core::limits::check_tx_money_range(&self.spend.tx)?;')
money_end=core_text.index('        let fee = total_inputs',money_start)
old_money=core_text[money_start:money_end]
new_money='        let total_outputs = self.spend.tx.outputs.iter().try_fold(0u64, |s,o| s.checked_add(o.value)).ok_or("output total overflows")?;\n        let total_inputs = self.inputs.iter().try_fold(0u64, |s,i| s.checked_add(i.prevout.value)).ok_or("input total overflows")?;\n'
CASES.extend([
 ('money-range',CORE,old_money,new_money,'gnb-crypto','pqpsbt_review_rejects_'),
 ('fee-floor',CORE,'if fee < core::tokenomics::MIN_TX_FEE_SAT {','if false {','gnb-crypto','pqpsbt_review_rejects_fee_below_absolute_minimum_before_callback'),
 ('final-fee',CORE,'        core::check_min_fee(&tx, review.fee)?;','        let _ = review;','gnb-crypto','pqpsbt_finalizer_rechecks_exact_consensus_minimum_with_real_witness'),
 ('candidate-size',CORE,'        candidate.validate()?;','        // Reversal: commit signed candidate without validation.','gnb-crypto','pqpsbt_signing_at_binary_limit_fails_atomically'),
])
ENV=dict(os.environ,CARGO_PROFILE_DEV_CODEGEN_UNITS='53',CARGO_PROFILE_TEST_CODEGEN_UNITS='53',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0',CARGO_TARGET_DIR='/private/tmp/gnb-technology-target-pqpsbt',CARGO_BUILD_JOBS='2')
def sha(data):return hashlib.sha256(data).hexdigest()
p=argparse.ArgumentParser();p.add_argument('--case');args=p.parse_args()
manifest=[]
for name,relative,old,new,crate,test in CASES:
 if args.case and name!=args.case:continue
 path=ROOT/relative;before=path.read_bytes();text=before.decode()
 if old not in text:raise RuntimeError(f'{name}: production anchor missing')
 mutated=text.replace(old,new,1).encode()
 # Each mutation is before the test module; test suffix must be byte-identical.
 split='\n#[cfg(test)]\nmod tests {'
 if split in text:assert text.split(split,1)[1]==mutated.decode().split(split,1)[1]
 (OUT/f'reversal-{name}.patch').write_text(''.join(difflib.unified_diff(text.splitlines(True),mutated.decode().splitlines(True),fromfile=relative,tofile=relative)))
 command=['cargo','test','--locked','-p',crate,'--lib',test,'--','--nocapture']
 path.write_bytes(mutated)
 try:
  with (OUT/f'reversal-{name}.log').open('w') as log:
   result=subprocess.run(command,cwd=ROOT,env=ENV,stdout=log,stderr=subprocess.STDOUT)
 finally:path.write_bytes(before)
 restored=path.read_bytes();assert restored==before
 log=(OUT/f'reversal-{name}.log').read_text()
 row=dict(case=name,path=relative,command=command,before_sha256=sha(before),mutated_sha256=sha(mutated),restored_sha256=sha(restored),exit=result.returncode,assertion_failed='panicked at' in log,log=f'reversal-{name}.log')
 manifest.append(row)
 (OUT/f'reversal-{name}.json').write_text(json.dumps(row,indent=2)+'\n')
 print(json.dumps(row),flush=True)
 assert result.returncode!=0 and 'panicked at' in log and 'error[E' not in log, f'{name}: expected runtime regression failure'
(OUT/'reversal-final-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
