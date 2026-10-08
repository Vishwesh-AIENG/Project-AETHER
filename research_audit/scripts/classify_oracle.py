#!/usr/bin/env python3
"""Classify dbt-oracle FAIL / DBTERR results by instruction word and mnemonic.

Usage:
  python3 -I classify_oracle.py <sweep_log_dir> <corpus_dir> > out.md

For single-instruction corpora (block names s_<hex>_cN / t_<hex>_cN) the word is
taken from the block name. For multi-instruction bb_* blocks the block's words are
read from the corpus file and listed (the diverging instruction is not isolated
automatically). Mnemonics come from `aarch64-linux-gnu-objdump` (independent of
the AETHER decoder).
"""
import collections
import os
import re
import subprocess
import sys
import tempfile

LINE = re.compile(r"^\[(FAIL  |DBTERR)\] (\S+)\s+(.*)$")
SINGLE = re.compile(r"^[st]_([0-9a-f]{8})_c(\d)$")


def objdump_words(words):
    words = sorted(set(words))
    if not words:
        return {}
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        for w in words:
            f.write(w.to_bytes(4, "little"))
        path = f.name
    out = subprocess.run(
        ["aarch64-linux-gnu-objdump", "-D", "-b", "binary", "-m", "aarch64", path],
        capture_output=True, text=True, check=True).stdout
    os.unlink(path)
    res = {}
    for ln in out.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)$", ln)
        if m:
            res[int(m.group(2), 16)] = m.group(3).strip()
    return res


def corpus_blocks(path):
    blocks, cur, words = {}, None, []
    with open(path, errors="replace") as f:
        for ln in f:
            ln = ln.split("#", 1)[0].strip()
            if ln.startswith("block "):
                cur, words = ln.split()[1], []
            elif ln.startswith("insn ") and cur:
                words += [int(t, 16) for t in ln.split()[1:]]
            elif ln == "end" and cur:
                blocks[cur] = words
                cur = None
    return blocks


def main():
    logdir, corpdir = sys.argv[1], sys.argv[2]
    single = collections.defaultdict(lambda: collections.defaultdict(set))  # kind->word->{files}
    single_ctx = collections.Counter()
    multi = collections.defaultdict(list)  # (kind,file) -> [block]
    detail = {}
    for fn in sorted(os.listdir(logdir)):
        if not fn.endswith(".log"):
            continue
        base = fn[:-4]
        with open(os.path.join(logdir, fn), errors="replace") as f:
            for ln in f:
                m = LINE.match(ln.rstrip("\n"))
                if not m:
                    continue
                kind = m.group(1).strip()
                name = m.group(2)
                s = SINGLE.match(name)
                if s:
                    w = int(s.group(1), 16)
                    single[kind][w].add(base)
                    single_ctx[(kind, w)] += 1
                    detail.setdefault((kind, w), m.group(3)[:160])
                else:
                    multi[(kind, base)].append((name, m.group(3)[:160]))
    allw = set()
    for k in single:
        allw |= set(single[k])
    blocks_by_file = {}
    for (kind, base) in multi:
        p = os.path.join(corpdir, base + ".txt")
        if base not in blocks_by_file and os.path.exists(p):
            blocks_by_file[base] = corpus_blocks(p)
        for name, _ in multi[(kind, base)]:
            allw |= set(blocks_by_file.get(base, {}).get(name, []))
    mn = objdump_words(allw)

    def mnem(w):
        return mn.get(w, "?").split()[0] if mn.get(w) else "?"

    print("# Oracle FAIL/DBTERR classification\n")
    for kind in ("FAIL", "DBTERR"):
        ws = single.get(kind, {})
        print(f"## Single-instruction {kind}: {len(ws)} distinct words, "
              f"{sum(single_ctx[(kind, w)] for w in ws)} blocks\n")
        fam = collections.Counter()
        famw = collections.defaultdict(list)
        for w in ws:
            fam[mnem(w)] += 1
            famw[mnem(w)].append(w)
        print("| mnemonic | distinct words | example word | example decode | example divergence |")
        print("|---|---:|---|---|---|")
        for m_, c in fam.most_common():
            w = sorted(famw[m_])[0]
            print(f"| {m_} | {c} | 0x{w:08x} | {mn.get(w,'?')} | `{detail.get((kind,w),'')[:110]}` |")
        print()
    print("## Multi-instruction (bb_*) blocks\n")
    for (kind, base), lst in sorted(multi.items()):
        print(f"### {base}: {len(lst)} {kind} blocks\n")
        c = collections.Counter()
        for name, _ in lst:
            for w in set(blocks_by_file.get(base, {}).get(name, [])):
                c[mnem(w)] += 1
        print("mnemonics present in failing blocks (count of blocks): " +
              ", ".join(f"{k}={v}" for k, v in c.most_common(25)) + "\n")
        for name, d in lst[:6]:
            ws = blocks_by_file.get(base, {}).get(name, [])
            print(f"- `{name}` `{d[:100]}` words: " +
                  "; ".join(f"{mn.get(w,'?')}" for w in ws))
        print()


if __name__ == "__main__":
    main()
