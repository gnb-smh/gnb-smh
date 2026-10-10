"""Sanity statistics for GnB-SMH (not a security proof).

1. Progress-freeness: attempts-until-success at p = 2^-6 must be geometric.
2. Output bit balance over many evaluations (reference implementation, small N).
"""
import csv, math, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "reference"))
import gnb_smh as ref

def chi2_sf(x, k):
    # survival function of chi-square via regularized upper incomplete gamma (series/continued fraction)
    a, x2 = k / 2.0, x / 2.0
    if x2 < a + 1:
        s, term, n = 1.0 / a, 1.0 / a, 0
        while abs(term) > 1e-15 * abs(s):
            n += 1; term *= x2 / (a + n); s += term
        return 1.0 - s * math.exp(-x2 + a * math.log(x2) - math.lgamma(a))
    b, c, d = x2 + 1 - a, 1e300, 1 / (x2 + 1 - a); h = d
    for i in range(1, 500):
        an = -i * (i - a); b += 2
        d = an * d + b; d = 1 / d if d else 1e300
        c = b + an / c if c else 1e300
        h *= d * c
    return math.exp(-x2 + a * math.log(x2) - math.lgamma(a)) * h

# --- 1. geometric fit -------------------------------------------------------
p = 2.0 ** -6
rows = [r for r in csv.reader(open(os.path.join(os.path.dirname(__file__), "mine_log2n8_bits6.csv")))]
att = [int(r[1]) for r in rows]
for r in rows:  # single-thread run: attempts == winning nonce + 1
    assert int(r[1]) == int(r[2]) + 1
n = len(att)
mean = sum(att) / n
var = sum((a - mean) ** 2 for a in att) / (n - 1)
# bins by quantiles of the geometric law
edges = [1, 9, 19, 30, 45, 64, 90, 130, 200, 10**9]
obs = [sum(1 for a in att if lo <= a < hi) for lo, hi in zip(edges, edges[1:])]
cdf = lambda k: 1 - (1 - p) ** (k - 1)  # P(A < k)
exp = [n * (cdf(hi) - cdf(lo)) for lo, hi in zip(edges, edges[1:])]
chi2 = sum((o - e) ** 2 / e for o, e in zip(obs, exp))
dof = len(obs) - 1
print(f"[geometric] blocks={n} mean={mean:.2f} (expect {1/p:.0f}) var={var:.0f} (expect {(1-p)/p**2:.0f})")
print(f"[geometric] chi2={chi2:.2f} dof={dof} p-value={chi2_sf(chi2, dof):.3f}")
# memorylessness: P(A > 128 | A > 64) vs P(A > 64)
gt64 = [a for a in att if a > 64]
print(f"[memoryless] P(A>64)={len(gt64)/n:.3f}  P(A>128|A>64)={sum(1 for a in gt64 if a > 128)/len(gt64):.3f}  (both expect {(1-p)**64:.3f})")

# --- 2. bit balance ------------------------------------------------------
M = 20000
ones = [0] * 256
for nonce in range(M):
    out = ref.gnb_smh(b"bit-balance", nonce, 6)
    v = int.from_bytes(out, "big")
    for b in range(256):
        ones[b] += (v >> b) & 1
z = [(o - M / 2) / math.sqrt(M / 4) for o in ones]
chi2b = sum(t * t for t in z)
print(f"[bits] evaluations={M} max|z|={max(abs(t) for t in z):.2f} chi2={chi2b:.1f} dof=256 p-value={chi2_sf(chi2b, 256):.3f}")
