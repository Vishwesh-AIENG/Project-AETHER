#!/usr/bin/env python3
"""Group DBT-only coverage gaps (aether-dbt-bench coverage output) by mnemonic.
Usage: python3 -I classify_coverage.py <coverage.log>   (single-insn corpus log)"""
import collections, re, subprocess, sys, tempfile, os
rows = [l.split() for l in open(sys.argv[1]) if l.startswith(("FAIL", "UD2", "PARTIAL"))]
words = {int(r[2], 16): r[0] for r in rows}  # single-insn: word = r[2]
with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
    for w in words: f.write(w.to_bytes(4, "little"))
out = subprocess.run(["aarch64-linux-gnu-objdump", "-D", "-b", "binary", "-m", "aarch64", f.name],
                     capture_output=True, text=True).stdout
os.unlink(f.name)
dec = [l.split("\t") for l in out.splitlines() if re.match(r"\s+[0-9a-f]+:\s", l)]
c = collections.defaultdict(collections.Counter); ex = {}
for d, w in zip(dec, words):
    asm = d[2].strip() if len(d) > 2 else "?"
    m = asm.split()[0]
    # crude arrangement tag for vector forms
    arr = re.search(r"\.(\d+[bhsd])", asm)
    key = m + ("." + arr.group(1) if arr else "")
    c[words[w]][key] += 1; ex.setdefault((words[w], key), f"0x{w:08x} {asm}")
for st in ("FAIL", "UD2"):
    tot = sum(c[st].values())
    print(f"\n### {st} ({'decoder rejects word' if st=='FAIL' else 'lowering emits fail-loud UD2'}): {tot} distinct words\n")
    print("| mnemonic.arrangement | words | example |\n|---|---:|---|")
    for k, v in c[st].most_common(40):
        print(f"| {k} | {v} | `{ex[(st,k)]}` |")
