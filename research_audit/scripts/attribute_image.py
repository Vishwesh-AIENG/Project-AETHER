#!/usr/bin/env python3
"""Attribute every machine-code byte of a linked EFI image to its source file.

Uses the image's PDB line tables (build with RUSTFLAGS="-C debuginfo=line-tables-only",
same release/LTO profile otherwise). Every instruction address from
`llvm-objdump -d` is symbolized with `llvm-symbolizer --inlining`; the bytes are
credited to the INNERMOST inlined frame (where the code was written). Modules of
the given source roots that receive 0 bytes are absent from the final image, i.e.
not reachable from that image's entry point after LTO dead-code elimination.

Usage: python3 -I attribute_image.py <image.efi> <objdump> <symbolizer> <src-root>...
Output: markdown table on stdout.
"""
import collections
import os
import re
import subprocess
import sys


def main():
    efi, objdump, symb = sys.argv[1:4]
    roots = sys.argv[4:]
    dis = subprocess.run([objdump, "-d", "--no-show-raw-insn", efi], capture_output=True,
                         text=True).stdout
    addrs = []
    for ln in dis.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s", ln)
        if m:
            addrs.append(int(m.group(1), 16))
    addrs.sort()
    sizes = [b - a for a, b in zip(addrs, addrs[1:])] + [4]
    inp = "\n".join(hex(a) for a in addrs) + "\n"
    out = subprocess.run([symb, "--obj", efi, "--inlining", "--output-style=JSON"],
                         input=inp, capture_output=True, text=True).stdout
    import json
    per_file = collections.Counter()
    any_frame = set()  # files appearing in ANY inlined frame (reachability)
    unknown = 0
    for (a, sz), ln in zip(zip(addrs, sizes), out.splitlines()):
        try:
            j = json.loads(ln)
            fr = j["Symbol"][0]["FileName"] if j.get("Symbol") else ""
            for fm in j.get("Symbol", []):
                any_frame.add(fm.get("FileName", "").replace("\\", "/"))
        except Exception:
            fr = ""
        if not fr:
            unknown += sz
        per_file[fr.replace("\\", "/")] += sz
    total = sum(per_file.values())
    # roots: first is the repo root, rest are sub-dirs (relative) to report on
    repo = os.path.abspath(roots[0]).rstrip("/") + "/"
    subs = [r.strip("/") + "/" for r in roots[1:]]
    rows, other = collections.Counter(), collections.Counter()
    for f, b in per_file.items():
        rel = f[len(repo):] if f.startswith(repo) else None
        if rel and any(rel.startswith(sd) for sd in subs):
            rows[rel] += b
        elif "/rustlib/" in f or "/library/" in f or "compiler-builtins" in f:
            other["rust std/core/alloc/compiler_builtins"] += b
        else:
            other[f or "(no line info)"] += b
    print(f"image={os.path.basename(efi)} instructions={len(addrs)} code_bytes={total}\n")
    print("| source file | bytes in image | share |\n|---|---:|---:|")
    for f, b in rows.most_common():
        print(f"| {f} | {b} | {100*b/total:.1f}% |")
    for f, b in other.most_common(6):
        print(f"| _{f}_ | {b} | {100*b/total:.1f}% |")
    print("\n### Source files under the reported dirs with ZERO bytes in this image\n")
    for sd in subs:
        allf = []
        for dp, _, fns in os.walk(repo + sd):
            allf += [os.path.relpath(os.path.join(dp, fn), repo) for fn in fns if fn.endswith(".rs")]
        anyrel = {f[len(repo):] for f in any_frame if f.startswith(repo)}
        absent = sorted(x for x in allf if x not in rows and x not in anyrel)
        inl_only = sorted(x for x in allf if x not in rows and x in anyrel)
        print(f"- `{sd}`: present only as an outer inlined frame ({len(inl_only)}): " + ", ".join(x[len(sd):] for x in inl_only) + "\n")
        print(f"- `{sd}`: {len(allf) - len(absent)}/{len(allf)} files present; absent ({len(absent)}): "
              + ", ".join(x[len(sd):] for x in absent) + "\n")


if __name__ == "__main__":
    main()
