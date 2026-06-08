"""
Extract kallsyms from a raw ARM64 Linux Image (no ELF).

Strategy:
  1. Locate the kallsyms_token_table by scanning for the 256-entry token
     index pattern (256 little-endian u16s pointing into the token table).
  2. Walk BACKWARD to find kallsyms_markers, kallsyms_names,
     kallsyms_num_syms, and kallsyms_offsets (CONFIG_KALLSYMS_BASE_RELATIVE).
  3. Decode every symbol; locate the requested ones.

Address formula (CONFIG_KALLSYMS_BASE_RELATIVE=y, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y):
  if offset >= 0:
      addr = relative_base + offset
  else:
      addr = -offset - 1     # absolute address

For ARM64 GKI kernels typically:
  relative_base = _text (the kernel text base, e.g. 0xFFFFFFC0_08000000).
"""

import struct
import sys


def find_kallsyms(data: bytes):
    # Look for the kallsyms_token_table area: 256 NUL-terminated short
    # strings. Then look for the kallsyms_token_index: 256 u16 offsets
    # into the token table, starting at offset 0 and monotonically
    # increasing. The token_index is what's easiest to fingerprint.
    n = len(data)
    # Scan in 4-byte-aligned positions for a 512-byte block whose first
    # u16 is 0 and which is monotonically non-decreasing for 256 entries
    # AND whose final entry is < 0x1000 (token table small).
    print("[scan] looking for kallsyms_token_index ...")
    candidates = []
    for off in range(0, n - 512, 4):
        first = struct.unpack_from('<H', data, off)[0]
        if first != 0:
            continue
        toks = struct.unpack_from('<256H', data, off)
        if toks[0] != 0:
            continue
        # Strictly monotonically increasing (every token is a unique
        # NUL-terminated string so each entry > previous).
        if any(toks[i + 1] <= toks[i] for i in range(255)):
            continue
        # Token table is small but non-trivial: 256 short strings,
        # typical total 0x300..0x600.
        if not (0x200 <= toks[255] <= 0x800):
            continue
        # Plausible. Verify: at off - token_table_size, we should see
        # printable / NUL bytes.
        tt_size = toks[255]
        tt_start = off - tt_size
        if tt_start < 0:
            continue
        tt = data[tt_start:tt_start + tt_size]
        # token table is many short NUL-terminated strings made of mostly
        # printable ASCII (function-name fragments).
        printable = sum(1 for b in tt if 0x20 <= b < 0x7f or b == 0)
        if printable < tt_size * 0.95:
            continue
        candidates.append((off, tt_start, tt_size))
        if len(candidates) >= 4:
            break
    print(f"[scan] {len(candidates)} candidate token_index positions")
    for c in candidates:
        print(f"  token_index @ {c[0]:#x}  token_table @ {c[1]:#x}  size {c[2]}")
    return candidates


def decode_kallsyms(data: bytes, token_index_off: int):
    """Given the file offset of kallsyms_token_index, decode all syms."""
    # token_index: 256 u16
    token_index = struct.unpack_from('<256H', data, token_index_off)
    # token_table is right before
    tt_size = token_index[255]
    tt_start = token_index_off - tt_size
    # Find end of token table: scan from tt_start until we see the last NUL
    # before the index. tt_size is the offset of the LAST entry, plus its
    # length, so we extend until we hit a NUL.
    tt_end = tt_start + tt_size
    while tt_end < token_index_off and data[tt_end] != 0:
        tt_end += 1
    tt_end += 1  # include the NUL
    token_table = data[tt_start:tt_end]

    def get_token(idx):
        off = token_index[idx]
        end = token_table.index(b'\x00', off)
        return token_table[off:end]

    # kallsyms_markers is right before token_table.
    # markers is an array of (num_syms / 256) u32 entries (or u64 on
    # CONFIG_64BIT in older kernels? Actually it's `unsigned int` per
    # kernel/kallsyms.c — u32). Each entry = byte-offset into
    # kallsyms_names of the symbol with index (i*256).
    #
    # We don't know num_syms yet, but the markers + names + num_syms +
    # offsets all live just before the token_table. The cleanest way to
    # find num_syms: scan backward from tt_start, find a u32 N such
    # that:
    #   - markers takes ceil(N/256)*4 bytes immediately before tt_start
    #   - num_syms (u32) is right before markers
    #   - names table sits before that
    #
    # The simplest heuristic: num_syms is the value at some 4-aligned
    # offset before tt_start, plausible range 30000..500000.
    #
    # Walk backward scanning u32s for a candidate.
    print(f"[decode] token_table {tt_start:#x}..{tt_end:#x} ({tt_end - tt_start} B)")

    # ARM64 GKI's kallsyms has names before markers before num_syms before
    # token_table. names is variable length; markers is fixed at
    # ceil(N/256)*4. So work backward:
    #   end_of_markers = tt_start (aligned)
    # try every plausible N starting from a guess.
    # We pick N by scanning every 4-aligned u32 in the 4KB before tt_start
    # and finding one that fits: markers ends just before tt_start, has
    # ceil(N/256) entries; num_syms is right before markers; and the last
    # marker should be < (some reasonable names size).
    # NOTE: markers may use either u32 or "unsigned long" (u64 on 64-bit
    # kernels). On ARM64 they're u64 ("kallsyms_offset_t" was widened).
    # Try BOTH widths.
    best = None
    for width in (4, 8):
        for n_off in range(tt_start - width, tt_start - 0x80000, -4):
            if n_off < 0:
                break
            N = struct.unpack_from('<I', data, n_off)[0]
            if not (10000 <= N <= 2_000_000):
                continue
            nmarkers = (N + 255) // 256
            markers_off = n_off + 4
            markers_end = markers_off + nmarkers * width
            if markers_end > tt_start:
                continue
            # Accept padding up to 16 bytes
            if tt_start - markers_end > 16:
                continue
            fmt = 'I' if width == 4 else 'Q'
            markers = struct.unpack_from(f'<{nmarkers}{fmt}', data, markers_off)
            if markers[0] != 0:
                continue
            if any(markers[i + 1] < markers[i] for i in range(nmarkers - 1)):
                continue
            if not (nmarkers * 2 <= markers[-1] <= N * 200):
                continue
            best = (n_off, N, markers_off, markers, width)
            break
        if best is not None:
            break
    if best is None:
        print("[decode] could not locate num_syms; giving up")
        return None
    n_off, N, markers_off, markers, marker_width = best
    print(f"[decode] num_syms = {N}  @ {n_off:#x}")
    print(f"[decode] markers @ {markers_off:#x} ({len(markers)} entries, width {marker_width})")

    # Names table ends at n_off. Start = ?
    # The total names byte-length we can compute by decoding from the
    # markers[-1] offset upward — but easier: start = markers_off - names_size
    # where names_size is unknown. Approach: parse names backward not
    # easy; instead scan from n_off backward until we find the start by
    # decoding forward from various offsets. Or just: read backward to
    # find the offsets table (kallsyms_offsets is just before names).
    #
    # CONFIG_KALLSYMS_BASE_RELATIVE: kallsyms_offsets is an i32[N] array.
    # Followed by alignment, then kallsyms_relative_base (u64), then
    # kallsyms_num_syms, then markers, then token_table, token_index.
    #
    # So between kallsyms_offsets and num_syms there's kallsyms_relative_base
    # (an u64, 8-byte aligned).
    #
    # relative_base is at n_off - 8 (most common ARM64 layout).
    rel_base = struct.unpack_from('<Q', data, n_off - 8)[0]
    print(f"[decode] relative_base = {rel_base:#x}  @ {n_off - 8:#x}")

    # offsets array is i32[N] before relative_base. names is before offsets.
    offsets_end = n_off - 8
    offsets_start = offsets_end - N * 4
    offsets = struct.unpack_from(f'<{N}i', data, offsets_start)
    print(f"[decode] offsets @ {offsets_start:#x} .. {offsets_end:#x}")

    # names table sits before offsets, but we need to find its start
    # because there may be alignment padding. We decode by walking
    # FORWARD from where we expect names to start.
    #
    # names_total_bytes: the last marker tells us the byte-offset of
    # symbol (N - N%256) within names. We need to decode forward from
    # there (or from any marker boundary) to find names_total_bytes.
    #
    # Actually we don't need names_start to look up symbols — we need
    # it to decode them. names_start is somewhere before offsets_start.
    #
    # For ARM64 GKI, names sits IMMEDIATELY after the (sometimes-padded)
    # area. Walk forward in 1-byte steps from (offsets_start - 0x800000)
    # ... that's expensive. Better: probe a known marker.
    #
    # Total bytes of names = sum of (1 + length_byte) for all N syms.
    # We can compute that by walking from each markers[i] forward 256
    # symbols and seeing where we land. Then names_size = end of last
    # block + bytes for syms in the partial last block.
    #
    # Simpler: just try names_start = offsets_start - X for various X
    # and pick one where decoding the first marker yields a sensible
    # symbol (first char in [Tt_a-zA-Z]).
    #
    # The kallsyms_names format is per-symbol:
    #   byte len
    #   len bytes of "data" — each byte is either an index into
    #     token_table (giving a token) OR if >= 0x80 some indexing detail.
    # Actually: each byte IS a token_index (0..255). The first byte of
    # each decoded symbol's expansion is the symbol type letter
    # (T, t, D, d, etc); the rest is the name.
    #
    # We will probe by attempting decode from candidate starts.

    def decode_symbol(off):
        n_bytes = data[off]
        sym_data = data[off + 1:off + 1 + n_bytes]
        out = b''
        for b in sym_data:
            tok = get_token(b)
            out += tok
        return out, n_bytes + 1

    # Try several names_start candidates by aligning down from
    # offsets_start by 0..2048 and decoding 16 syms forward looking for
    # plausible type letters in the first byte of expansion.
    names_start = None
    for slack in range(0, 4096):
        cand = offsets_start - markers[-1] - 0x10000  # too low typically
        # try aligned starts: offsets_start - K where K covers names size
        pass

    # Try the marker-anchored approach: names_start = offsets_start - names_total
    # where names_total is bounded by the data we read. We know markers[i]
    # is the byte offset within names of symbol i*256. Decoding from
    # any candidate start C, the byte at (C + markers[i]) is the length
    # byte of symbol i*256. So check that for several candidate starts.
    def is_plausible(cand):
        bad = 0
        for i, m in enumerate(markers):
            if i >= 32:  # only check first 32 markers, enough
                break
            off = cand + m
            if off < 0 or off >= n_off:
                return False
            ln = data[off]
            # name lengths in kallsyms are 1..255 but rarely > 200
            if not (1 <= ln <= 250):
                bad += 1
                if bad > 0:
                    return False
            # decode first byte (type letter expansion first char)
            tt_off = token_index[data[off + 1]]
            if not (0x20 <= token_table[tt_off] < 0x7f):
                bad += 1
                if bad > 0:
                    return False
        return True

    # Probe candidate start positions
    for start in range(offsets_start - 1, max(0, offsets_start - 0x800000), -1):
        if is_plausible(start):
            names_start = start
            break
    if names_start is None:
        print("[decode] could not find names_start")
        return None
    print(f"[decode] names_start = {names_start:#x}")

    # Decode all symbols
    syms = []
    off = names_start
    cur = 0
    while cur < N:
        n_bytes = data[off]
        sym_bytes = data[off + 1:off + 1 + n_bytes]
        decoded = b''
        for b in sym_bytes:
            decoded += get_token(b)
        if len(decoded) == 0:
            break
        type_letter = chr(decoded[0])
        name = decoded[1:].decode('utf-8', errors='replace')
        # Address resolution
        raw = offsets[cur]
        if raw >= 0:
            addr = rel_base + raw
        else:
            addr = (-raw) - 1
        syms.append((addr, type_letter, name))
        off += 1 + n_bytes
        cur += 1
    print(f"[decode] decoded {len(syms)}/{N} symbols")
    return syms


def main():
    image_path = sys.argv[1] if len(sys.argv) > 1 else 'D:/AETHER/Image'
    data = open(image_path, 'rb').read()
    print(f"[main] Image size = {len(data)}")
    cands = find_kallsyms(data)
    if not cands:
        print("[main] no candidates")
        return 1
    for cand in cands:
        token_index_off = cand[0]
        syms = decode_kallsyms(data, token_index_off)
        if syms is None:
            continue
        # Look up the targets
        targets = [
            'pcpu_build_alloc_info',
            'pcpu_alloc_alloc_info',
            'pcpu_setup_first_chunk',
            'pcpu_embed_first_chunk',
            'setup_per_cpu_areas',
        ]
        by_name = {n: (a, t) for a, t, n in syms}
        for tgt in targets:
            if tgt in by_name:
                a, t = by_name[tgt]
                print(f"  {tgt:30s} = {a:#018x} ({t})")
            else:
                print(f"  {tgt:30s} = NOT FOUND")
        # Save out a System.map-style file
        out = 'D:/AETHER/qemu/kallsyms.map'
        with open(out, 'w', encoding='utf-8') as fh:
            for a, t, n in sorted(syms):
                fh.write(f'{a:016x} {t} {n}\n')
        print(f"[main] wrote {out} ({len(syms)} syms)")
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
