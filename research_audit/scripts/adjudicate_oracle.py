#!/usr/bin/env python3
"""Independent third-party adjudication of dbt-oracle FAILs.

For every single-instruction FAIL block (s_<hex>_cN / t_<hex>_cN) in a sweep log,
re-compute the architecturally correct result from the corpus seed using exact
rational arithmetic (fractions.Fraction) written directly from the ARM ARM
pseudocode, independent of BOTH the AETHER DBT and the oracle's reference.

Families covered: vector + scalar FRINT{N,M,P,Z,A}, vector FMLA/FMLS (three-same,
fused single rounding, FPCR=0: RNE, no FZ, no DN), REV (32/64).
For each FAIL the verdict is DBT-correct, REF-correct, both-wrong, or unmodelled.

Usage: python3 -I adjudicate_oracle.py <sweep_log_dir> <corpus_dir>
"""
import collections
import math
import os
import re
import struct
import sys
from fractions import Fraction

LINE = re.compile(r"^\[FAIL  \] ([st])_([0-9a-f]{8})_c(\d)\s+(\S+)\s+DBT=0x([0-9a-f]+)\s+REF=0x([0-9a-f]+)")

# ---------------------------------------------------------------- IEEE helpers
FMT = {32: (8, 23), 64: (11, 52)}


def is_nan(b, w):
    e, m = FMT[w]
    return ((b >> m) & ((1 << e) - 1)) == (1 << e) - 1 and (b & ((1 << m) - 1)) != 0


def is_inf(b, w):
    e, m = FMT[w]
    return ((b >> m) & ((1 << e) - 1)) == (1 << e) - 1 and (b & ((1 << m) - 1)) == 0


def sign(b, w):
    return (b >> (w - 1)) & 1


def to_frac(b, w):
    e, m = FMT[w]
    ex = (b >> m) & ((1 << e) - 1)
    man = b & ((1 << m) - 1)
    bias = (1 << (e - 1)) - 1
    if ex == 0:
        v = Fraction(man, 1 << m) * Fraction(2) ** (1 - bias)
    else:
        v = (1 + Fraction(man, 1 << m)) * Fraction(2) ** (ex - bias)
    return -v if sign(b, w) else v


def from_frac(q, w, neg_zero=False):
    """Round rational q to nearest-even binary32/64 bits."""
    e, m = FMT[w]
    bias = (1 << (e - 1)) - 1
    if q == 0:
        return (1 << (w - 1)) if neg_zero else 0
    s = 1 if q < 0 else 0
    a = -q if s else q
    ex = math.floor(math.log2(a.numerator) - math.log2(a.denominator))
    while Fraction(2) ** ex > a:
        ex -= 1
    while Fraction(2) ** (ex + 1) <= a:
        ex += 1
    ex = max(ex, 1 - bias)
    unit = Fraction(2) ** (ex - m)
    n = a / unit
    fl = math.floor(n)
    r = n - fl
    if r > Fraction(1, 2) or (r == Fraction(1, 2) and fl % 2 == 1):
        fl += 1
    if fl >= (1 << (m + 1)):
        fl >>= 1
        ex += 1
    if ex - (1 - bias) + 1 >= (1 << e) - 1 and fl >= (1 << m):
        return (s << (w - 1)) | (((1 << e) - 1) << m)  # overflow -> inf
    if fl < (1 << m):
        return (s << (w - 1)) | fl  # subnormal
    return (s << (w - 1)) | ((ex + bias) << m) | (fl - (1 << m))


def quiet(b, w):
    return b | (1 << (FMT[w][1] - 1))


def frint(b, w, mode):
    if is_nan(b, w):
        return quiet(b, w)
    if is_inf(b, w):
        return b
    v = to_frac(b, w)
    if mode == "N":
        fl = math.floor(v)
        r = v - fl
        i = fl + 1 if (r > Fraction(1, 2) or (r == Fraction(1, 2) and fl % 2)) else fl
    elif mode == "M":
        i = math.floor(v)
    elif mode == "P":
        i = math.ceil(v)
    elif mode == "Z":
        i = math.trunc(v)
    elif mode == "A":
        i = math.floor(abs(v) + Fraction(1, 2)) * (1 if v >= 0 else -1)
    return from_frac(Fraction(i), w, neg_zero=bool(sign(b, w)))


def fma(a, n, m_, w, neg_prod):
    """ARM FPMulAdd(addend=a, op1=n (negated if FMLS), op2=m), FPCR=0."""
    if neg_prod:
        n ^= 1 << (w - 1)
    # NaN propagation: FPProcessNaNs3(a, op1, op2): first SNaN, then first QNaN.
    ops = (a, n, m_)
    qbit = 1 << (FMT[w][1] - 1)
    for x in ops:
        if is_nan(x, w) and not (x & qbit):
            return quiet(x, w)
    for x in ops:
        if is_nan(x, w):
            return x
    if is_inf(n, w) or is_inf(m_, w) or is_inf(a, w):
        return None  # inf arithmetic: not modelled here
    prod = to_frac(n, w) * to_frac(m_, w)
    s = to_frac(a, w) + prod
    if s == 0:
        sp = sign(n, w) ^ sign(m_, w)
        return from_frac(Fraction(0), w, neg_zero=(sp and sign(a, w)))
    return from_frac(s, w)


# ------------------------------------------------------------- seed parsing
def load_seeds(path, wanted):
    seeds, cur = {}, None
    with open(path, errors="replace") as f:
        for ln in f:
            t = ln.split("#", 1)[0].split()
            if not t:
                continue
            if t[0] == "block":
                cur = t[1] if t[1] in wanted else None
                if cur:
                    seeds[cur] = {}
            elif cur and t[0] != "end":
                seeds[cur][t[0]] = t[1:]
            elif t[0] == "end":
                cur = None
    return seeds


def lanes(v, w, n):
    return [(v >> (i * w)) & ((1 << w) - 1) for i in range(n)]


def pack(ls, w):
    return sum(x << (i * w) for i, x in enumerate(ls))


def truth(word, seed):
    """Return (family, regname, value) or None if unmodelled."""
    V = lambda i: int(seed.get(f"v{i}", ["0"])[0], 16)
    X = lambda i: int(seed.get(f"x{i}", ["0"])[0], 16)
    rd, rn, rm = word & 31, (word >> 5) & 31, (word >> 16) & 31
    # vector FRINT: 0 Q U 01110 o2 sz 10000 1 opcode(5) 10 Rn Rd
    if (word & 0x9F3E0C00) == 0x0E200800 and ((word >> 12) & 0x1F) in (0b11000, 0b11001):
        q, u, o2, sz, op = (word >> 30) & 1, (word >> 29) & 1, (word >> 23) & 1, (word >> 22) & 1, (word >> 12) & 1
        mode = {(0, 0, 0): "N", (0, 0, 1): "M", (0, 1, 0): "P", (0, 1, 1): "Z", (1, 0, 0): "A"}.get((u, o2, op))
        if mode is None or (sz == 1 and q == 0):
            return None
        w = 64 if sz else 32
        n = (128 if q else 64) // w
        res = pack([frint(x, w, mode) for x in lanes(V(rn), w, n)], w)
        return (f"vec FRINT{mode}", f"v{rd}", res)
    # scalar FRINT: 0 0 0 11110 ftype 1 001 rmode 10000 Rn Rd  (opcode6 = 0b001xxx)
    if (word & 0xFF3C7C00) == 0x1E244000:
        ftype, op3 = (word >> 22) & 3, (word >> 15) & 7
        mode = {0: "N", 1: "P", 2: "M", 3: "Z", 4: "A"}.get(op3)
        if mode is None or ftype not in (0, 1):
            return None
        w = 32 if ftype == 0 else 64
        return (f"scalar FRINT{mode}", f"v{rd}", frint(V(rn) & ((1 << w) - 1), w, mode))
    # vector FMLA/FMLS three-same: 0 Q 0 01110 op sz 1 Rm 11001 1 Rn Rd
    if (word & 0xBF20FC00) == 0x0E20CC00:
        q, neg, sz = (word >> 30) & 1, (word >> 23) & 1, (word >> 22) & 1
        if sz == 1 and q == 0:
            return None
        w = 64 if sz else 32
        k = (128 if q else 64) // w
        A, N, M = lanes(V(rd), w, k), lanes(V(rn), w, k), lanes(V(rm), w, k)
        out = [fma(a, n, m, w, neg) for a, n, m in zip(A, N, M)]
        if any(o is None for o in out):
            return None
        return ("vec FMLS" if neg else "vec FMLA", f"v{rd}", pack(out, w))
    # REV Wd,Wn = 0x5AC00800 | REV Xd,Xn = 0xDAC00C00
    if (word & 0xFFFFFC00) == 0x5AC00800:
        x = X(rn) & 0xFFFFFFFF
        return ("REV (32)", f"x{rd}", int.from_bytes(x.to_bytes(4, "little"), "big"))
    if (word & 0xFFFFFC00) == 0xDAC00C00:
        return ("REV (64)", f"x{rd}", int.from_bytes(X(rn).to_bytes(8, "little"), "big"))
    return None


def main():
    logdir, corpdir = sys.argv[1], sys.argv[2]
    fails = []
    for fn, corp in (("simd_from_framework.log", "simd_from_framework.txt"),
                     ("trace_insns.log", "trace_insns.txt")):
        p = os.path.join(logdir, fn)
        if not os.path.exists(p):
            continue
        with open(p, errors="replace") as f:
            for ln in f:
                m = LINE.match(ln)
                if m:
                    fails.append((corp, f"{m.group(1)}_{m.group(2)}_c{m.group(3)}",
                                  int(m.group(2), 16), m.group(4), int(m.group(5), 16), int(m.group(6), 16)))
    seeds = {}
    for corp in {c for c, *_ in fails}:
        seeds.update(load_seeds(os.path.join(corpdir, corp), {n for c, n, *_ in fails if c == corp}))
    tally = collections.defaultdict(collections.Counter)
    words = collections.defaultdict(lambda: collections.defaultdict(set))
    examples = {}
    for corp, name, word, reg, dbt, ref in fails:
        t = truth(word, seeds.get(name, {}))
        if t is None:
            fam, verdict = "unmodelled", "unmodelled"
        else:
            fam, treg, val = t
            # compare only the bits the oracle reported (it prints the full reg)
            if treg != reg:
                verdict = "reg-mismatch"
            elif val == dbt and val != ref:
                verdict = "DBT correct (reference bug)"
            elif val == ref and val != dbt:
                verdict = "REF correct (DBT miscompile)"
            elif val != ref and val != dbt:
                verdict = "both differ from ground truth"
            else:
                verdict = "agree?"
        tally[fam][verdict] += 1
        words[fam][verdict].add(word)
        examples.setdefault((fam, verdict), (name, reg, dbt, ref, t[2] if t else None))
    print("# Independent adjudication of single-instruction oracle FAILs\n")
    print("Ground truth computed with exact rational arithmetic from ARM ARM pseudocode "
          "(FPCR=0: round-to-nearest-even, no flush-to-zero, no default-NaN).\n")
    print("| family | verdict | FAIL blocks | distinct words | example (block, reg, DBT, REF, TRUTH) |")
    print("|---|---|---:|---:|---|")
    for fam in sorted(tally):
        for v, c in tally[fam].most_common():
            ex = examples[(fam, v)]
            tr = f"0x{ex[4]:x}" if ex[4] is not None else "-"
            print(f"| {fam} | {v} | {c} | {len(words[fam][v])} | `{ex[0]}` {ex[1]} DBT=0x{ex[2]:x} REF=0x{ex[3]:x} TRUTH={tr} |")


if __name__ == "__main__":
    main()
