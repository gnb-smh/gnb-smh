"""Compare complete public descriptor responses with a prebuilt Rust oracle.

No Rust source, compiler, signatures, live node or network is used. The fixed
vectors pin generated request/response bytes before the two implementations
are compared. Error strings are deliberately excluded from the contract.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

import descriptor as d
import descriptor_vectors as v
import descriptor_generated as g


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rust_oracle", type=Path)
    parser.add_argument("--generated", type=int, default=g.DEFAULT_REQUESTS, help="deterministic generated requests, 0..4096 (default 128)")
    parser.add_argument("--seed", type=lambda text: int(text, 0), default=g.DEFAULT_SEED, help="generated campaign PRNG seed (decimal or 0x-prefixed)")
    args = parser.parse_args()
    binary = args.rust_oracle.resolve(strict=True)
    corpus = json.loads(v.VECTOR_FILE.read_text())
    pinned_cases = list(v.cases())
    generated = list(g.cases(args.generated, args.seed))
    if len(pinned_cases) != len(corpus["cases"]):
        raise SystemExit("vector case count mismatch")
    expected = []
    for (name, line, accepted), pinned in zip(pinned_cases, corpus["cases"]):
        answer = d.oracle_line(line)
        if pinned["name"] != name or pinned["accepted"] != accepted or answer["ok"] != accepted:
            raise SystemExit("vector acceptance mismatch: " + name)
        if hashlib.sha256(line.encode()).hexdigest() != pinned["request_sha256"] or hashlib.sha256(d.compact(answer).encode()).hexdigest() != pinned["response_sha256"]:
            raise SystemExit("vector byte mismatch: " + name)
        expected.append(answer)
    for name, line, accepted in generated:
        answer = d.oracle_line(line)
        if answer["ok"] != accepted:
            raise SystemExit("generated acceptance mismatch: " + name)
        expected.append(answer)
    all_cases = pinned_cases + generated
    serialized = "\n".join(line for _, line, _ in all_cases) + "\n"
    process = subprocess.run([str(binary)], input=serialized, text=True, capture_output=True, timeout=180, check=True)
    replies = process.stdout.splitlines()
    if len(replies) != len(all_cases):
        raise SystemExit(f"oracle emitted {len(replies)} lines for {len(all_cases)} requests")
    for (name, _, _), want, line in zip(all_cases, expected, replies):
        got = d.strict_json(line)
        if got != want:
            # Avoid dumping huge public descriptors into CI logs.
            raise SystemExit(f"divergence: {name}; Python ok={want.get('ok')}; Rust ok={got.get('ok')}; full response equality failed")
    print(json.dumps({"requests": len(all_cases), "pinned_requests": len(pinned_cases), "generated_requests": len(generated), "generated_seed": args.seed, "generated_sha256": hashlib.sha256(("\n".join(line for _, line, _ in generated) + "\n").encode()).hexdigest(), "accepted": sum(item[2] for item in all_cases), "rejected": sum(not item[2] for item in all_cases), "divergences": 0, "corpus_sha256": hashlib.sha256(v.VECTOR_FILE.read_bytes()).hexdigest(), "python_oracle_sha256": hashlib.sha256(Path(d.__file__).read_bytes()).hexdigest(), "rust_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}, sort_keys=True))


if __name__ == "__main__":
    main()
