# Round 5 integration brief

Base: `2848dcf6bd89a85afe4828042227c9a2c2b433f0`; contract: `35ccd62`.
Native integration CGU: 157. Isolated target:
`/private/tmp/gnb-r5-target-integration`.

The new live functional test must fail against the unchanged R4 test-only
binaries at the missing `getdescriptorinfo` RPC, after a successful legacy
`getbalance` control. Compile errors or node setup failures do not count.
The expected pkh descriptor checksum and script are pinned from the independent
Python package's synthetic public-key fixture, not the new Rust implementation.

Acceptance: CLI creation and inspection match RPC, export/import preserves a
public pool and its funded identity, the node observes the same test coins,
and wrong-network restoration and overwriting an existing file are refused.
This is public identity restoration, not proof of possession, spending-key
recovery, historical scanning or persistent watch-only indexing.

After package integration: rebuild the actual WASM using the repository script,
check the independent differential, run node and crypto in separate invocations,
site/deploy/reference and functional suites, and obtain the three independent
review lenses. Keep all negative runs and inherited findings in the evidence.
No consensus or activation change is intended. No numerical reassessment is
assigned by this implementer.
