#!/usr/bin/env python3
"""extract.py — AETHER DBT differential-oracle corpus extractor.

Feeds REAL Android ARM64 code to the dbt-oracle so it can surface silent
miscompiles WITHOUT booting QEMU.

Two extractors:

  A (distinct-insn)  — from the boot trace (qemu/com1.log '[dbt] pc=.. insn=..'
                       lines). Dedup the userspace instruction words, and for each
                       distinct word emit a 1-instruction `block` under 3
                       deterministic pseudo-random seed contexts (X0..X30, V0..V31,
                       NZCV) so the oracle exercises the op over varied operands
                       (dirty-upper-32, negatives, small ints, alternating bits).
                       LOAD/STORE words are SKIPPED here (they need valid pointers;
                       the memory corpus + Extractor B cover them).

  B (basic-blocks)   — from objdump'd .text of the hot framework binaries. Split
                       at branches, emit multi-insn blocks (catch spill / flag /
                       interaction bugs). Blocks containing loads/stores/branches/
                       PC-rel ops are still emitted but with the caveat below.

Usage:
  extract.py trace   --in trace_user_raw.txt --out ../dbt-oracle/corpus/trace_insns.txt
  extract.py blocks  --in disasm/libhwui.txt --out ../dbt-oracle/corpus/bb_libhwui.txt

All seeds are deterministic (fixed constants) so the corpus is reproducible.
"""

import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from arm64_decode import is_load_store, is_simd_fp, mnemonic, top_group  # noqa: E402


# ── deterministic seed contexts ───────────────────────────────────────────────
# Three fixed contexts. Each fills X0..X30 (0..30), V0..V31, and NZCV with a
# distinct, varied bit pattern. We want: dirty-upper-32 (W-form corner),
# negatives (sign bit set), small ints, alternating bit patterns, and values that
# make signed-vs-unsigned differ. The values are functions of the register index
# so different registers hold different operands within one context.

def ctx_gprs(ctx):
    """Return list of 31 u64 GPR seed values for context `ctx` (0,1,2)."""
    out = []
    for n in range(31):
        if ctx == 0:
            # Mix: small ints in low regs, dirty-upper + alternating higher up.
            v = (0xDEADBEEF_00000000 ^ (n * 0x0101010101010101)) & 0xFFFFFFFFFFFFFFFF
            if n < 4:
                v = n + 1                     # tiny operands 1,2,3,4
            elif n % 3 == 0:
                v = 0xFFFFFFFF_80000000 | (n & 0xFF)   # dirty upper, W = 0x8000_00xx
        elif ctx == 1:
            # Negatives / sign-bit-set and boundary values.
            v = (0x8000000000000000 | (n * 0x1111111111111111)) & 0xFFFFFFFFFFFFFFFF
            if n % 5 == 0:
                v = 0xFFFFFFFFFFFFFFFF        # all-ones (−1 signed)
            if n % 7 == 0:
                v = 0x0000000000000001
        else:  # ctx == 2
            # Alternating bit patterns + values where signed<->unsigned diverge.
            v = 0xA5A5A5A5_5A5A5A5A if (n & 1) else 0x5A5A5A5A_A5A5A5A5
            if n % 4 == 0:
                v = 0x7FFFFFFF_FFFFFFFF        # max positive signed
            if n % 6 == 0:
                v = 0x00000000_FFFFFFFF        # clean W all-ones, X positive
        out.append(v & 0xFFFFFFFFFFFFFFFF)
    return out


def ctx_vecs(ctx):
    """Return list of 32 u128 V seed values for context `ctx`."""
    out = []
    for n in range(32):
        if ctx == 0:
            base = 0x00000000000000010000000000000002  # lane pattern
            v = base ^ ((n * 0x03030303030303030303030303030303) & ((1 << 128) - 1))
        elif ctx == 1:
            # sign bits set per-lane (top bit of each 64-bit lane), for CMxx tests
            v = 0x80000000000000008000000000000000
            v ^= (n * 0x01010101010101010101010101010101) & ((1 << 128) - 1)
        else:
            v = 0xA5A5A5A5A5A5A5A55A5A5A5A5A5A5A5A if (n & 1) \
                else 0x5A5A5A5A5A5A5A5AA5A5A5A5A5A5A5A5
            if n % 4 == 0:
                v = 0x7FFFFFFFFFFFFFFF0000000000000001
        out.append(v & ((1 << 128) - 1))
    return out


def ctx_nzcv(ctx):
    # bits[31:28] = NZCV
    return {0: 0x60000000,   # Z,C set
            1: 0x90000000,   # N,V set
            2: 0x00000000}[ctx]   # all clear


def emit_seed_lines(ctx):
    """Emit the seed directive lines (x0.., v0.., nzcv) for a context."""
    lines = []
    for n, v in enumerate(ctx_gprs(ctx)):
        lines.append(f"  x{n} 0x{v:016x}")
    for n, v in enumerate(ctx_vecs(ctx)):
        lines.append(f"  v{n} 0x{v:032x}")
    lines.append(f"  nzcv 0x{ctx_nzcv(ctx):08x}")
    return lines


# ── Extractor A: distinct-insn corpus from the boot trace ─────────────────────

def extract_trace(in_path, out_path, include_ldst=False):
    # in_path lines: "<pc_hex> <insn_hex>" (already-lowercased, no 0x)
    seen = {}   # insn_word -> first_seen_pc
    total_lines = 0
    with open(in_path) as f:
        for line in f:
            parts = line.split()
            if len(parts) != 2:
                continue
            total_lines += 1
            pc = int(parts[0], 16)
            w = int(parts[1], 16) & 0xFFFFFFFF
            if w not in seen:
                seen[w] = pc

    # Decide which distinct insns go into Extractor A.
    kept = []
    skipped_ldst = []
    for w, pc in sorted(seen.items(), key=lambda kv: kv[0]):
        if is_load_store(w) and not include_ldst:
            skipped_ldst.append((w, pc))
            continue
        kept.append((w, pc))

    n_blocks = 0
    with open(out_path, "w", encoding="ascii", errors="replace") as out:
        out.write("# dbt-oracle Extractor A corpus -- distinct USERSPACE insns from\n")
        out.write("# the boot trace (qemu/com1.log). Each distinct instruction word is\n")
        out.write("# emitted as a 1-insn block under 3 deterministic seed contexts.\n")
        out.write("# LOAD/STORE words are excluded (need valid pointers; see memory.txt\n")
        out.write("# + Extractor B). Regenerate with tools/corpus-extract/extract.py.\n")
        out.write(f"# distinct userspace insns seen: {len(seen)}"
                  f"  kept(non-ldst): {len(kept)}  ldst-skipped: {len(skipped_ldst)}\n\n")
        for w, pc in kept:
            mn = mnemonic(w)
            for ctx in range(3):
                name = f"t_{w:08x}_c{ctx}"
                out.write(f"block {name}\n")
                out.write(f"  # {mn}  (first-seen pc=0x{pc:x})\n")
                out.write(f"  pc 0x{pc & 0xFFFFFFFFFFFF:x}\n")
                for l in emit_seed_lines(ctx):
                    out.write(l + "\n")
                out.write(f"  insn 0x{w:08x}\n")
                out.write("end\n\n")
                n_blocks += 1

    # sidecar: distinct-insn -> mnemonic map for the report
    with open(out_path + ".insns.tsv", "w", encoding="ascii", errors="replace") as m:
        m.write("insn\tgroup\tmnemonic\tis_ldst\tfirst_pc\n")
        for w, pc in sorted(seen.items(), key=lambda kv: kv[0]):
            m.write(f"0x{w:08x}\t{top_group(w)}\t{mnemonic(w)}\t"
                    f"{int(is_load_store(w))}\t0x{pc:x}\n")

    print(f"[trace] total trace lines: {total_lines}")
    print(f"[trace] distinct insn words: {len(seen)}")
    print(f"[trace] kept (non-ldst): {len(kept)}   ldst-skipped: {len(skipped_ldst)}")
    print(f"[trace] blocks emitted: {n_blocks}  ->  {out_path}")
    print(f"[trace] insn map: {out_path}.insns.tsv")


# ── Extractor B: basic blocks from objdump ────────────────────────────────────
# objdump -d output lines look like:
#   "   1234:\t8b010000 \tadd\tx0, x0, x1"
# We collect (addr, word) sequences, split at any control-flow instruction
# (branch / ret / branch-with-link / cbz / tbz / exceptions), and emit blocks
# up to MAX_BLK insns. A block ends *after* including the terminator only if it's
# a straight-line-friendly op; we terminate BEFORE branches so blocks are
# straight-line (the oracle runs words in sequence with no control flow).

OBJDUMP_RE = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)$")

# Terminator mnemonics (control flow) — block ends before these.
TERMINATORS = ("b", "b.", "bl", "blr", "br", "ret", "cbz", "cbnz",
               "tbz", "tbnz", "svc", "hvc", "brk", "eret", "smc", "hlt", "yield")

def is_terminator_text(dis):
    m = dis.split()[0] if dis.split() else ""
    m = m.lower()
    if m in ("ret", "br", "blr", "bl", "svc", "hvc", "brk", "eret", "smc", "hlt"):
        return True
    if m == "b" or m.startswith("b.") or m in ("cbz", "cbnz", "tbz", "tbnz"):
        return True
    return False


def extract_blocks(in_path, out_path, max_blk=8, want=400, skip_mem=True,
                   simd_only=False):
    words = []   # list of (addr, word, dis)
    with open(in_path, errors="replace") as f:
        for line in f:
            mm = OBJDUMP_RE.match(line)
            if not mm:
                continue
            addr = int(mm.group(1), 16)
            w = int(mm.group(2), 16) & 0xFFFFFFFF
            dis = mm.group(3).strip()
            words.append((addr, w, dis))

    # Build straight-line blocks: break at terminators.
    blocks = []
    cur = []
    cur_pc = None
    for addr, w, dis in words:
        if not cur:
            cur_pc = addr
        if is_terminator_text(dis):
            if cur:
                blocks.append((cur_pc, list(cur)))
                cur = []
            continue
        cur.append((w, dis))
        if len(cur) >= max_blk:
            blocks.append((cur_pc, list(cur)))
            cur = []
            cur_pc = None
    if cur:
        blocks.append((cur_pc, list(cur)))

    # Filter: prefer blocks that are pure register data-processing (no mem, no
    # PC-rel) so the oracle can run them without pointer setup. Keep length >=2.
    # When simd_only, additionally require the block to carry at least one
    # Advanced-SIMD / scalar-FP instruction (the whole point of the framework
    # rendering/runtime sweep — exercise the DBT's NEON/FP lowering on real code).
    def block_ok(insns):
        if len(insns) < 2:
            return False
        has_simd = False
        for w, dis in insns:
            if skip_mem and is_load_store(w):
                return False
            mn = dis.split()[0].lower() if dis.split() else ""
            if mn in ("adr", "adrp"):   # PC-rel — reference can't model (SKIP)
                return False
            if is_simd_fp(w):
                has_simd = True
        if simd_only and not has_simd:
            return False
        return True

    chosen = [b for b in blocks if block_ok(b[1])]
    # Dedup by the tuple of words (many blocks are identical prologue/epilogue).
    seen_sig = set()
    uniq = []
    for pc, insns in chosen:
        sig = tuple(w for w, _ in insns)
        if sig in seen_sig:
            continue
        seen_sig.add(sig)
        uniq.append((pc, insns))
    uniq = uniq[:want]

    # Histogram of the distinct SIMD/FP mnemonics that survive into the corpus —
    # written as a sidecar for the framework-SIMD report.
    simd_hist = {}
    for _pc, insns in uniq:
        for w, _dis in insns:
            if is_simd_fp(w):
                mn = mnemonic(w)
                simd_hist[mn] = simd_hist.get(mn, 0) + 1

    tag = os.path.splitext(os.path.basename(out_path))[0]
    kind = "SIMD/FP-bearing" if simd_only else "register data-processing"
    with open(out_path, "w", encoding="ascii", errors="replace") as out:
        out.write(f"# dbt-oracle Extractor B corpus -- straight-line basic blocks from\n")
        out.write(f"# {os.path.basename(in_path)} .text (objdump). {kind}\n")
        out.write(f"# blocks (no loads/stores/branches/PC-rel). 3 seed contexts each.\n")
        if simd_only:
            out.write(f"# Each block carries >=1 Advanced-SIMD / scalar-FP instruction.\n")
        out.write(f"# unique blocks kept: {len(uniq)} (cap want={want}).\n\n")
        n = 0
        for pc, insns in uniq:
            for ctx in range(3):
                out.write(f"block {tag}_{pc:x}_c{ctx}\n")
                dis0 = insns[0][1].encode("ascii", "replace").decode("ascii")
                out.write(f"  # {len(insns)} insns starting @ 0x{pc:x}: {dis0}\n")
                out.write(f"  pc 0x{pc:x}\n")
                for l in emit_seed_lines(ctx):
                    out.write(l + "\n")
                words_hex = " ".join(f"0x{w:08x}" for w, _ in insns)
                out.write(f"  insn {words_hex}\n")
                out.write("end\n\n")
                n += 1

    # sidecar: SIMD/FP mnemonic histogram for the report
    with open(out_path + ".simdhist.tsv", "w", encoding="ascii", errors="replace") as h:
        h.write("mnemonic\tcount\n")
        for mn, c in sorted(simd_hist.items(), key=lambda kv: -kv[1]):
            h.write(f"{mn}\t{c}\n")

    print(f"[blocks] {in_path}: parsed {len(words)} insns, {len(blocks)} raw blocks, "
          f"{len(chosen)} kept-filter, {len(uniq)} unique -> {n} blocks in {out_path}"
          + (f"  (simd-only)" if simd_only else ""))


# ── Extractor A': distinct SIMD/FP insns across many framework disasms ─────────
# Collect every distinct Advanced-SIMD / scalar-FP instruction WORD seen across
# the given objdump disasms, plus a handful of synthetic seeds, and emit each as
# a 1-insn block under the 3 deterministic seed contexts (like Extractor A). Lets
# the next sweep quickly enumerate exactly which NEON/FP ops zygote->SF exercises.

# A few synthetic SIMD/FP seeds so families the static scan under-samples are still
# probed at least once (common lowering-risk ops). (word, comment)
SIMD_SYNTH_SEEDS = [
    (0x4EA01C00, "MOV Vd.16b, Vn.16b (ORR)"),
    (0x4E205800, "CNT Vd.16b"),
    (0x0E205800, "CNT Vd.8b"),
    (0x6E60F400, "FADD Vd.2d"),
    (0x4E20D400, "FADD Vd.4s"),
    (0x6EE0F400, "FDIV Vd.2d"),
    (0x4E21F400, "FMUL Vd.4s"),
    (0x0E000400, "TBL Vd.8b {Vn.16b}"),
    (0x4E000400, "TBL Vd.16b {Vn.16b}"),
    (0x4E183C00, "UMOV Xd, Vn.d[1]"),
    (0x4E080C00, "DUP Vd.2d, Xn"),
    (0x5E180400, "DUP Dd, Vn.d[1]"),
    (0x4E31B800, "ADDV Bd, Vn.16b"),
    (0x2E205800, "MVN / NOT Vd.8b"),
    (0x1E202800, "FADD Sd, Sn, Sm (scalar)"),
    (0x1E602800, "FADD Dd, Dn, Dm (scalar)"),
    (0x1E204000, "FMOV Sd, Sn"),
    (0x1E624000, "FMOV Dd, Dn (fneg?)"),
    (0x1E22C000, "FCVT Dd, Sn"),
    (0x9E670000, "FMOV Xd, Dn"),
]

def extract_simd_framework(in_paths, out_path):
    seen = {}   # word -> (first_pc, source_basename)
    per_lib = {}   # basename -> distinct-count
    for p in in_paths:
        base = os.path.basename(p)
        cnt = 0
        try:
            f = open(p, errors="replace")
        except OSError:
            print(f"[simd] WARN cannot open {p}")
            continue
        with f:
            for line in f:
                mm = OBJDUMP_RE.match(line)
                if not mm:
                    continue
                addr = int(mm.group(1), 16)
                w = int(mm.group(2), 16) & 0xFFFFFFFF
                if not is_simd_fp(w):
                    continue
                if w not in seen:
                    seen[w] = (addr, base)
                    cnt += 1
        per_lib[base] = cnt

    # merge synthetic seeds (only add if not already present from real code)
    n_synth = 0
    for w, _c in SIMD_SYNTH_SEEDS:
        w &= 0xFFFFFFFF
        if w not in seen:
            seen[w] = (0, "synthetic")
            n_synth += 1

    n_blocks = 0
    with open(out_path, "w", encoding="ascii", errors="replace") as out:
        out.write("# dbt-oracle framework-SIMD corpus -- distinct Advanced-SIMD /\n")
        out.write("# scalar-FP instruction words seen across the zygote->SurfaceFlinger\n")
        out.write("# framework + ART libraries (objdump .text), plus a few synthetic\n")
        out.write("# seeds. Each distinct word is a 1-insn block under 3 seed contexts\n")
        out.write("# (Extractor A style). Regenerate with extract.py simd.\n")
        out.write(f"# sources: {', '.join(os.path.basename(p) for p in in_paths)}\n")
        out.write(f"# distinct SIMD/FP words: {len(seen)}  (of which synthetic: {n_synth})\n\n")
        for w, (pc, src) in sorted(seen.items(), key=lambda kv: kv[0]):
            mn = mnemonic(w)
            for ctx in range(3):
                out.write(f"block s_{w:08x}_c{ctx}\n")
                out.write(f"  # {mn}  (first-seen in {src} @ pc=0x{pc:x})\n")
                out.write(f"  pc 0x{pc & 0xFFFFFFFFFFFF:x}\n")
                for l in emit_seed_lines(ctx):
                    out.write(l + "\n")
                out.write(f"  insn 0x{w:08x}\n")
                out.write("end\n\n")
                n_blocks += 1

    # sidecar: histogram of SIMD/FP mnemonics across the framework libs
    hist = {}
    for w, _ in seen.items():
        mn = mnemonic(w)
        hist[mn] = hist.get(mn, 0) + 1
    with open(out_path + ".simdhist.tsv", "w", encoding="ascii", errors="replace") as h:
        h.write("mnemonic\tdistinct_words\n")
        for mn, c in sorted(hist.items(), key=lambda kv: -kv[1]):
            h.write(f"{mn}\t{c}\n")

    # sidecar: per-library distinct SIMD/FP word counts
    with open(out_path + ".perlib.tsv", "w", encoding="ascii", errors="replace") as pl:
        pl.write("source\tdistinct_simd_fp_words\n")
        for base, c in sorted(per_lib.items(), key=lambda kv: -kv[1]):
            pl.write(f"{base}\t{c}\n")

    print(f"[simd] distinct SIMD/FP words: {len(seen)} (synthetic {n_synth}) "
          f"-> {n_blocks} blocks in {out_path}")
    for base, c in sorted(per_lib.items(), key=lambda kv: -kv[1]):
        print(f"[simd]   {base}: {c} distinct SIMD/FP words")


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("trace")
    a.add_argument("--in", dest="inp", required=True)
    a.add_argument("--out", dest="out", required=True)
    a.add_argument("--include-ldst", action="store_true")

    b = sub.add_parser("blocks")
    b.add_argument("--in", dest="inp", required=True)
    b.add_argument("--out", dest="out", required=True)
    b.add_argument("--max-blk", type=int, default=8)
    b.add_argument("--want", type=int, default=400)
    b.add_argument("--simd-only", action="store_true",
                   help="keep only blocks that carry >=1 Advanced-SIMD / scalar-FP insn")

    s = sub.add_parser("simd")
    s.add_argument("--in", dest="inp", nargs="+", required=True,
                   help="one or more objdump .text disasm files")
    s.add_argument("--out", dest="out", required=True)

    args = ap.parse_args()
    if args.cmd == "trace":
        extract_trace(args.inp, args.out, include_ldst=args.include_ldst)
    elif args.cmd == "blocks":
        extract_blocks(args.inp, args.out, max_blk=args.max_blk, want=args.want,
                       simd_only=args.simd_only)
    elif args.cmd == "simd":
        extract_simd_framework(args.inp, args.out)


if __name__ == "__main__":
    main()
