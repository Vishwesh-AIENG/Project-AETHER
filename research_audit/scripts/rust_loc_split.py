#!/usr/bin/env python3
"""Rust LOC split: production vs inline #[cfg(test)] modules vs tests/ dirs.

Counts *code* lines (non-blank, not a pure // or /* */ comment line) per
component directory. Lines inside a `#[cfg(test)]`-annotated `mod` block (brace
matched) are counted as test code. Files under a `tests/` directory are test
code. Usage: python3 -I rust_loc_split.py <tree-root> <dir>...
"""
import os
import re
import sys


def code_lines(lines):
    out, in_block = [], False
    for ln in lines:
        s = ln.strip()
        if in_block:
            if "*/" in s:
                in_block = False
            out.append(False)
            continue
        if s.startswith("/*"):
            in_block = "*/" not in s
            out.append(False)
            continue
        out.append(bool(s) and not s.startswith("//"))
    return out


def split_file(path):
    lines = open(path, errors="replace").read().split("\n")
    is_code = code_lines(lines)
    test = [False] * len(lines)
    i = 0
    while i < len(lines):
        if re.match(r"\s*#\[cfg\((all\()?test", lines[i]):
            j = i + 1
            while j < len(lines) and not re.search(r"\bmod\s+\w+\s*\{", lines[j]) and j - i < 4:
                j += 1
            if j < len(lines) and re.search(r"\bmod\s+\w+\s*\{", lines[j]):
                depth = 0
                k = j
                while k < len(lines):
                    depth += lines[k].count("{") - lines[k].count("}")
                    test[k] = True
                    if depth <= 0 and k > j:
                        break
                    k += 1
                for t in range(i, j):
                    test[t] = True
                i = k
        i += 1
    prod = sum(1 for c, t in zip(is_code, test) if c and not t)
    tst = sum(1 for c, t in zip(is_code, test) if c and t)
    return prod, tst


def main():
    root = sys.argv[1]
    print("| component | files | production code | inline #[cfg(test)] | tests/ dir | total code |")
    print("|---|---:|---:|---:|---:|---:|")
    tot = [0, 0, 0, 0]
    for d in sys.argv[2:]:
        files = prod = inl = tdir = 0
        for dp, _, fns in os.walk(os.path.join(root, d)):
            if "/target" in dp:
                continue
            for fn in fns:
                if not fn.endswith(".rs"):
                    continue
                files += 1
                p, t = split_file(os.path.join(dp, fn))
                if "/tests" in dp.replace(root, "") or "/tests/" in dp:
                    tdir += p + t
                else:
                    prod += p
                    inl += t
        print(f"| {d} | {files} | {prod} | {inl} | {tdir} | {prod + inl + tdir} |")
        for i, v in enumerate((files, prod, inl, tdir)):
            tot[i] += v
    print(f"| **total** | {tot[0]} | {tot[1]} | {tot[2]} | {tot[3]} | {tot[1] + tot[2] + tot[3]} |")


if __name__ == "__main__":
    main()
