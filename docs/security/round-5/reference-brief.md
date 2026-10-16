# Independent descriptor reference

Owner: reference package; base `35ccd62`; native codegen-units 149 reserved,
no Rust build. Source contract: `descriptor-contract.md`, existing policy
encoding and key-shape predicate, existing address reference, and BIP380.
The new Rust descriptor implementation is not an input to this implementation.

Deliver a standard-library Python descriptor codec, public pool codec, tests,
deterministic vectors, JSON-lines oracle and differential driver. Compare both
networks, three descriptor kinds, exact raw/enveloped key identities, BIP380
checksum, canonical grammar, explicit limits and strict pool JSON. Fixtures
are public synthetic byte strings satisfying the existing shape predicate;
they do not establish cryptographic possession or spendability.

The test-only commit states the reference contract. Missing Python APIs are
not a reproduction of a product defect. Root/core owns the required runtime
feature-gap reproduction through the existing dispatcher before production.
This package changes no node, frontend, CI, WASM or consensus code.

Acceptance: Python tests pass, vector regeneration is identical, official
BIP380 checksum example matches, and the prebuilt Rust oracle compares equal
to the independently derived full public responses. Error text is not part
of the differential contract. Record actual counts and failures, not a score.

Partial technology item 4.2 only: no public derivation, wildcard, new spending
language, balances, private-key restoration or persistent wallet index.
