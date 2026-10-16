from pathlib import Path
import os, subprocess, hashlib, json
root=Path('/private/tmp/gnb-pqpsbt-miri-source'); out=Path('/private/tmp/gnb-pqpsbt-evidence'); path=root/'crates/gnb-wallet-wasm/src/lib.rs'
before=path.read_bytes(); text=before.decode(); attr='    #[cfg_attr(miri, ignore = "key generation, signing and verification run the PQClean ML-DSA-65 and Falcon-1024 C code, which Miri cannot execute")]\n    fn pqpsbt_wasm_roles_sign_in_session_and_reject_bad_context() {'
assert attr in text
mutated=text.replace(attr,'    fn pqpsbt_wasm_roles_sign_in_session_and_reject_bad_context() {',1).encode()
env=dict(os.environ,MIRIFLAGS='-Zmiri-permissive-provenance',CARGO_TARGET_DIR='/private/tmp/gnb-technology-pqpsbt-miri-native',CARGO_BUILD_JOBS='1',CARGO_PROFILE_DEV_CODEGEN_UNITS='53',CARGO_PROFILE_TEST_CODEGEN_UNITS='53',CARGO_PROFILE_DEV_DEBUG='0',CARGO_PROFILE_TEST_DEBUG='0',CARGO_INCREMENTAL='0')
command=['cargo','+nightly','miri','test','--locked','-p','gnb-wallet-wasm','--lib']
path.write_bytes(mutated)
try:
 with (out/'miri-final-reversal.log').open('w') as log:result=subprocess.run(command+['pqpsbt_wasm_roles_sign_in_session_and_reject_bad_context','--','--nocapture'],cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
finally:path.write_bytes(before)
assert path.read_bytes()==before
log=(out/'miri-final-reversal.log').read_text();assert result.returncode!=0 and "can't call foreign function `PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair`" in log
with (out/'miri-restored-green.log').open('w') as log:green=subprocess.run(command+['--','--nocapture'],cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
assert green.returncode==0
row=dict(source=str(path),before_sha256=hashlib.sha256(before).hexdigest(),mutated_sha256=hashlib.sha256(mutated).hexdigest(),restored_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),reversal_exit=result.returncode,restored_exit=green.returncode)
(out/'miri-reversal-manifest.json').write_text(json.dumps(row,indent=2)+'\n');print(json.dumps(row))
