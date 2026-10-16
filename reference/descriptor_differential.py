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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rust_oracle", type=Path)
    args = parser.parse_args()
    binary = args.rust_oracle.resolve(strict=True)
    corpus = json.loads(v.VECTOR_FILE.read_text())
    generated = list(v.cases())
    if len(generated) != len(corpus["cases"]):
        raise SystemExit("vector case count mismatch")
    expected = []
    for (name, line, accepted), pinned in zip(generated, corpus["cases"]):
        answer = d.oracle_line(line)
        if pinned["name"] != name or pinned["accepted"] != accepted or answer["ok"] != accepted:
            raise SystemExit("vector acceptance mismatch: " + name)
        if hashlib.sha256(line.encode()).hexdigest() != pinned["request_sha256"] or hashlib.sha256(d.compact(answer).encode()).hexdigest() != pinned["response_sha256"]:
            raise SystemExit("vector byte mismatch: " + name)
        expected.append(answer)
    process = subprocess.run([str(binary)], input="\n".join(line for _, line, _ in generated) + "\n", text=True, capture_output=True, timeout=180, check=True)
    replies = process.stdout.splitlines()
    if len(replies) != len(generated):
        raise SystemExit(f"oracle emitted {len(replies)} lines for {len(generated)} requests")
    for (name, _, _), want, line in zip(generated, expected, replies):
        got = d.strict_json(line)
        if got != want:
            # Avoid dumping huge public descriptors into CI logs.
            raise SystemExit(f"divergence: {name}; Python ok={want.get('ok')}; Rust ok={got.get('ok')}; full response equality failed")
    print(json.dumps({"requests": len(generated), "accepted": sum(item[2] for item in generated), "rejected": sum(not item[2] for item in generated), "divergences": 0, "corpus_sha256": hashlib.sha256(v.VECTOR_FILE.read_bytes()).hexdigest(), "python_oracle_sha256": hashlib.sha256(Path(d.__file__).read_bytes()).hexdigest(), "rust_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}, sort_keys=True))


if __name__ == "__main__":
    main()
