//! Minimal `no_std`, allocation-free gzip (RFC 1952) + DEFLATE (RFC 1951)
//! decompressor.
//!
//! AETHER is the bootloader on the x86 tier (No-Boundary, Ch. 3): there is no
//! host firmware to decompress the kernel for us, and arm64 has no
//! self-extracting kernel image. Android boot.img kernels are almost always
//! shipped gzip-compressed (`Image.gz`, sometimes `Image.gz-dtb` with an
//! appended DTB). The DBT dispatch loop fetches the kernel entry as raw bytes,
//! so a compressed payload makes the very first block lift the gzip magic
//! (`1f 8b 08 00`) instead of ARM64 code and fail-loud. This module turns the
//! compressed payload into the real `Image` before the dispatcher ever sees it.
//!
//! The implementation is a faithful port of Mark Adler's reference `puff.c`
//! (zlib `contrib/puff`), the canonical minimal inflate. It is deliberately
//! dependency-free and fully auditable: no `unsafe`, no heap. Output is written
//! straight into a caller-provided slice (the guest-RAM kernel region), which
//! also serves as the LZ77 history window — back-references read from the bytes
//! already produced. Trailing bytes after the final DEFLATE block (e.g. the
//! gzip CRC32/ISIZE trailer, or an appended DTB on `Image.gz-dtb`) are ignored,
//! so the same code handles both `Image.gz` and `Image.gz-dtb`.

const MAXBITS: usize = 15; // max bits in a Huffman code
const MAXLCODES: usize = 286; // max number of literal/length codes
const MAXDCODES: usize = 30; // max number of distance codes
const MAXCODES: usize = MAXLCODES + MAXDCODES; // max codes lengths to read
const FIXLCODES: usize = 288; // number of fixed literal/length codes

/// Failure modes. Every one is a fail-loud reject — a corrupt or unsupported
/// stream never silently produces partial/garbage output the kernel would then
/// try to execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflateError {
    /// Not a gzip stream (missing `1f 8b` magic) or unsupported compression
    /// method (only DEFLATE, CM=8, is defined).
    BadGzipHeader,
    /// Ran off the end of the input before the stream completed.
    Truncated,
    /// Reserved DEFLATE block type (BTYPE=3).
    BadBlockType,
    /// Stored block length check (`NLEN != ~LEN`) failed.
    BadStoredLength,
    /// Over- or under-subscribed Huffman code, or an invalid symbol.
    BadHuffman,
    /// Distance back-reference points before the start of the output.
    BadDistance,
    /// Decompressed data exceeds the caller-provided output buffer.
    OutputOverflow,
}

/// Decode state: the input bit-stream plus the output buffer that doubles as
/// the LZ77 window.
struct State<'a> {
    input: &'a [u8],
    incnt: usize, // bytes consumed from input
    bitbuf: u32,  // bit accumulator (LSB-first)
    bitcnt: u32,  // number of valid bits in `bitbuf`
    out: &'a mut [u8],
    outcnt: usize, // bytes written to output
}

impl<'a> State<'a> {
    /// Return `need` bits from the stream (LSB-first), refilling from `input`.
    fn bits(&mut self, need: u32) -> Result<u32, InflateError> {
        let mut val = self.bitbuf;
        while self.bitcnt < need {
            if self.incnt >= self.input.len() {
                return Err(InflateError::Truncated);
            }
            val |= (self.input[self.incnt] as u32) << self.bitcnt;
            self.incnt += 1;
            self.bitcnt += 8;
        }
        self.bitbuf = val >> need;
        self.bitcnt -= need;
        Ok(val & ((1u32 << need) - 1))
    }
}

/// Decode one symbol using the canonical Huffman code described by `count`
/// (number of codes of each length) and `symbol` (symbols in canonical order).
/// Direct port of puff's `decode()`.
fn decode(
    s: &mut State,
    count: &[u16; MAXBITS + 1],
    symbol: &[u16],
) -> Result<i32, InflateError> {
    let mut code: i32 = 0;
    let mut first: i32 = 0;
    let mut index: i32 = 0;
    for len in 1..=MAXBITS {
        code |= s.bits(1)? as i32; // one bit at a time, LSB-first
        let cnt = count[len] as i32;
        if code - cnt < first {
            return Ok(symbol[(index + (code - first)) as usize] as i32);
        }
        index += cnt;
        first += cnt;
        first <<= 1;
        code <<= 1;
    }
    Err(InflateError::BadHuffman)
}

/// Build a canonical Huffman code from a list of code `length`s. Fills `count`
/// and `symbol`. Returns 0 for a complete code, >0 for incomplete, <0 for an
/// over-subscribed (invalid) code. Direct port of puff's `construct()`.
fn construct(
    count: &mut [u16; MAXBITS + 1],
    symbol: &mut [u16],
    length: &[u8],
    n: usize,
) -> i32 {
    for c in count.iter_mut() {
        *c = 0;
    }
    for &l in &length[..n] {
        count[l as usize] += 1;
    }
    if count[0] as usize == n {
        return 0; // no codes at all — complete (an empty code)
    }

    // Check for an over-subscribed or incomplete code.
    let mut left: i32 = 1;
    for len in 1..=MAXBITS {
        left <<= 1;
        left -= count[len] as i32;
        if left < 0 {
            return left; // over-subscribed
        }
    }

    // Offsets into the symbol table for each length.
    let mut offs = [0u16; MAXBITS + 1];
    for len in 1..MAXBITS {
        offs[len + 1] = offs[len] + count[len];
    }

    // Put symbols in order.
    for sym in 0..n {
        let l = length[sym] as usize;
        if l != 0 {
            symbol[offs[l] as usize] = sym as u16;
            offs[l] += 1;
        }
    }

    left // 0 = complete, >0 = incomplete
}

// Length base values for symbols 257..285 (RFC 1951 §3.2.5).
const LENS: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
// Extra bits for each length symbol.
const LEXT: [u16; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
// Distance base values for symbols 0..29.
const DISTS: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
// Extra bits for each distance symbol.
const DEXT: [u16; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

/// Decode literal/length + distance symbols for one block. Port of puff's
/// `codes()`.
fn codes(
    s: &mut State,
    lc_count: &[u16; MAXBITS + 1],
    lc_symbol: &[u16],
    dc_count: &[u16; MAXBITS + 1],
    dc_symbol: &[u16],
) -> Result<(), InflateError> {
    loop {
        let sym = decode(s, lc_count, lc_symbol)?;
        if sym == 256 {
            return Ok(()); // end of block
        }
        if sym < 256 {
            // literal byte
            if s.outcnt >= s.out.len() {
                return Err(InflateError::OutputOverflow);
            }
            s.out[s.outcnt] = sym as u8;
            s.outcnt += 1;
        } else {
            // length/distance pair
            let sym = (sym - 257) as usize;
            if sym >= 29 {
                return Err(InflateError::BadHuffman);
            }
            let len = LENS[sym] as usize + s.bits(LEXT[sym] as u32)? as usize;

            let dsym = decode(s, dc_count, dc_symbol)?;
            if dsym < 0 || dsym >= 30 {
                return Err(InflateError::BadDistance);
            }
            let dist = DISTS[dsym as usize] as usize + s.bits(DEXT[dsym as usize] as u32)? as usize;
            if dist > s.outcnt {
                return Err(InflateError::BadDistance); // before start of output
            }
            if s.outcnt + len > s.out.len() {
                return Err(InflateError::OutputOverflow);
            }
            for _ in 0..len {
                // Byte-by-byte copy (overlapping refs are legal in LZ77).
                let v = s.out[s.outcnt - dist];
                s.out[s.outcnt] = v;
                s.outcnt += 1;
            }
        }
    }
}

/// A stored (uncompressed) block. Port of puff's `stored()`.
fn stored(s: &mut State) -> Result<(), InflateError> {
    // Discard any leftover bits — stored blocks are byte-aligned.
    s.bitbuf = 0;
    s.bitcnt = 0;

    if s.incnt + 4 > s.input.len() {
        return Err(InflateError::Truncated);
    }
    let len = s.input[s.incnt] as usize | ((s.input[s.incnt + 1] as usize) << 8);
    let nlen = s.input[s.incnt + 2] as usize | ((s.input[s.incnt + 3] as usize) << 8);
    s.incnt += 4;
    if len != (!nlen & 0xFFFF) {
        return Err(InflateError::BadStoredLength);
    }
    if s.incnt + len > s.input.len() {
        return Err(InflateError::Truncated);
    }
    if s.outcnt + len > s.out.len() {
        return Err(InflateError::OutputOverflow);
    }
    for _ in 0..len {
        s.out[s.outcnt] = s.input[s.incnt];
        s.outcnt += 1;
        s.incnt += 1;
    }
    Ok(())
}

/// Fixed Huffman block. Port of puff's `fixed()`.
fn fixed(s: &mut State) -> Result<(), InflateError> {
    // Literal/length code: 0..143=8, 144..255=9, 256..279=7, 280..287=8.
    let mut lengths = [0u8; FIXLCODES];
    for v in lengths.iter_mut().take(144) {
        *v = 8;
    }
    for v in lengths.iter_mut().take(256).skip(144) {
        *v = 9;
    }
    for v in lengths.iter_mut().take(280).skip(256) {
        *v = 7;
    }
    for v in lengths.iter_mut().take(288).skip(280) {
        *v = 8;
    }
    let mut lc_count = [0u16; MAXBITS + 1];
    let mut lc_symbol = [0u16; FIXLCODES];
    construct(&mut lc_count, &mut lc_symbol, &lengths, FIXLCODES);

    // Distance code: 30 codes all of length 5.
    let dlen = [5u8; MAXDCODES];
    let mut dc_count = [0u16; MAXBITS + 1];
    let mut dc_symbol = [0u16; MAXDCODES];
    construct(&mut dc_count, &mut dc_symbol, &dlen, MAXDCODES);

    codes(s, &lc_count, &lc_symbol, &dc_count, &dc_symbol)
}

/// Dynamic Huffman block. Port of puff's `dynamic()`.
fn dynamic(s: &mut State) -> Result<(), InflateError> {
    // Order in which code-length code lengths are stored (RFC 1951 §3.2.7).
    const ORDER: [usize; 19] = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];

    let hlit = s.bits(5)? as usize + 257;
    let hdist = s.bits(5)? as usize + 1;
    let hclen = s.bits(4)? as usize + 4;
    if hlit > MAXLCODES || hdist > MAXDCODES {
        return Err(InflateError::BadHuffman);
    }

    // Read the code-length code lengths (3 bits each, in ORDER).
    let mut lengths = [0u8; MAXCODES];
    for i in 0..hclen {
        lengths[ORDER[i]] = s.bits(3)? as u8;
    }
    // (ORDER[hclen..] entries stay 0.)

    // Build the code-length Huffman code.
    let mut cl_count = [0u16; MAXBITS + 1];
    let mut cl_symbol = [0u16; 19];
    let err = construct(&mut cl_count, &mut cl_symbol, &lengths, 19);
    if err != 0 {
        // Code-length code must be complete.
        return Err(InflateError::BadHuffman);
    }

    // Read the literal/length and distance code lengths.
    let mut index = 0usize;
    while index < hlit + hdist {
        let sym = decode(s, &cl_count, &cl_symbol)?;
        if sym < 0 {
            return Err(InflateError::BadHuffman);
        }
        if sym < 16 {
            lengths[index] = sym as u8;
            index += 1;
        } else {
            let (repeat, value) = match sym {
                16 => {
                    if index == 0 {
                        return Err(InflateError::BadHuffman); // no previous length
                    }
                    (3 + s.bits(2)? as usize, lengths[index - 1])
                }
                17 => (3 + s.bits(3)? as usize, 0u8),
                18 => (11 + s.bits(7)? as usize, 0u8),
                _ => return Err(InflateError::BadHuffman),
            };
            if index + repeat > hlit + hdist {
                return Err(InflateError::BadHuffman); // too many lengths
            }
            for _ in 0..repeat {
                lengths[index] = value;
                index += 1;
            }
        }
    }

    // A literal/length code with no end-of-block (symbol 256) is invalid.
    if lengths[256] == 0 {
        return Err(InflateError::BadHuffman);
    }

    // Build the literal/length Huffman code. Incomplete is allowed only in the
    // degenerate single-code case (puff's check).
    let mut lc_count = [0u16; MAXBITS + 1];
    let mut lc_symbol = [0u16; MAXLCODES];
    let err = construct(&mut lc_count, &mut lc_symbol, &lengths, hlit);
    if err < 0 || (err > 0 && hlit - lc_count[0] as usize != 1) {
        return Err(InflateError::BadHuffman);
    }

    // Build the distance Huffman code (same incomplete-allowed rule).
    let mut dc_count = [0u16; MAXBITS + 1];
    let mut dc_symbol = [0u16; MAXDCODES];
    let err = construct(&mut dc_count, &mut dc_symbol, &lengths[hlit..], hdist);
    if err < 0 || (err > 0 && hdist - dc_count[0] as usize != 1) {
        return Err(InflateError::BadHuffman);
    }

    codes(s, &lc_count, &lc_symbol, &dc_count, &dc_symbol)
}

/// Inflate a raw DEFLATE stream starting at `input[start..]` into `out`.
/// Returns the number of bytes written. Port of puff's `puff()` driver.
fn inflate_raw(input: &[u8], start: usize, out: &mut [u8]) -> Result<usize, InflateError> {
    let mut s = State {
        input,
        incnt: start,
        bitbuf: 0,
        bitcnt: 0,
        out,
        outcnt: 0,
    };
    loop {
        let last = s.bits(1)?;
        let btype = s.bits(2)?;
        match btype {
            0 => stored(&mut s)?,
            1 => fixed(&mut s)?,
            2 => dynamic(&mut s)?,
            _ => return Err(InflateError::BadBlockType),
        }
        if last != 0 {
            break;
        }
    }
    Ok(s.outcnt)
}

/// The gzip magic bytes (`1f 8b`).
pub const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];

/// `true` if `data` begins with the gzip magic.
pub fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == GZIP_MAGIC[0] && data[1] == GZIP_MAGIC[1]
}

// gzip header flag bits (RFC 1952 §2.3.1).
const FHCRC: u8 = 1 << 1;
const FEXTRA: u8 = 1 << 2;
const FNAME: u8 = 1 << 3;
const FCOMMENT: u8 = 1 << 4;

/// Decompress a gzip stream into `out`, returning the number of bytes written.
///
/// Parses the gzip header (skipping optional FEXTRA / FNAME / FCOMMENT / FHCRC
/// fields), then inflates the embedded DEFLATE stream directly into `out`.
/// Trailing bytes after the final block (the gzip CRC32/ISIZE trailer, or an
/// appended DTB on `Image.gz-dtb`) are ignored.
pub fn gunzip(input: &[u8], out: &mut [u8]) -> Result<usize, InflateError> {
    // ── gzip header ───────────────────────────────────────────────────────
    // ID1 ID2 CM FLG MTIME(4) XFL OS = 10 fixed bytes.
    if input.len() < 10 || !is_gzip(input) {
        return Err(InflateError::BadGzipHeader);
    }
    if input[2] != 8 {
        return Err(InflateError::BadGzipHeader); // CM must be 8 (DEFLATE)
    }
    let flg = input[3];
    let mut pos = 10usize;

    if flg & FEXTRA != 0 {
        if pos + 2 > input.len() {
            return Err(InflateError::Truncated);
        }
        let xlen = input[pos] as usize | ((input[pos + 1] as usize) << 8);
        pos += 2 + xlen;
        if pos > input.len() {
            return Err(InflateError::Truncated);
        }
    }
    if flg & FNAME != 0 {
        pos = skip_cstr(input, pos)?;
    }
    if flg & FCOMMENT != 0 {
        pos = skip_cstr(input, pos)?;
    }
    if flg & FHCRC != 0 {
        pos += 2;
        if pos > input.len() {
            return Err(InflateError::Truncated);
        }
    }

    // ── DEFLATE payload ───────────────────────────────────────────────────
    inflate_raw(input, pos, out)
}

/// Skip a NUL-terminated string starting at `pos`; return the index just past
/// the NUL.
fn skip_cstr(input: &[u8], mut pos: usize) -> Result<usize, InflateError> {
    while pos < input.len() {
        let b = input[pos];
        pos += 1;
        if b == 0 {
            return Ok(pos);
        }
    }
    Err(InflateError::Truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    // A stored-block gzip stream is trivial to hand-build and exercises the
    // header parse + stored() path without needing a compressor.
    #[test]
    fn gunzip_stored_block() {
        let payload = b"AETHER hypervisor kernel payload";
        let len = payload.len() as u16;
        let mut gz: Vec<u8> = Vec::new();
        // header: 1f 8b 08 00 + MTIME(4) + XFL + OS
        gz.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0xFF]);
        // one final stored block: BFINAL=1, BTYPE=00 -> byte 0x01
        gz.push(0x01);
        gz.extend_from_slice(&len.to_le_bytes());
        gz.extend_from_slice(&(!len).to_le_bytes());
        gz.extend_from_slice(payload);
        // trailer (ignored): CRC32 + ISIZE
        gz.extend_from_slice(&[0, 0, 0, 0]);
        gz.extend_from_slice(&len.to_le_bytes());
        gz.extend_from_slice(&[0, 0]);

        let mut out = [0u8; 64];
        let n = gunzip(&gz, &mut out).expect("gunzip stored");
        assert_eq!(n, payload.len());
        assert_eq!(&out[..n], payload);
    }

    // Round-trip: build a valid fixed-Huffman DEFLATE stream by hand for a
    // highly repetitive input (forces a length/distance back-reference), wrap
    // it in a gzip header, and confirm it inflates byte-for-byte.
    #[test]
    fn gunzip_fixed_huffman_backref_roundtrip() {
        // Input: 'A' repeated 100 times. Fixed-Huffman encoding:
        //   literal 'A' (0x41) then a (length=99, distance=1) copy.
        // We encode it with a fixed-Huffman block.
        let mut bw = BitWriter::new();
        bw.write_bits(1, 1); // BFINAL=1
        bw.write_bits(1, 2); // BTYPE=01 (fixed)
        // literal 'A' (0x41=65): fixed code for 0..143 is 8 bits, value
        // 0b00110000 + 65 = 0x30+65=0x71, emitted MSB-first.
        write_fixed_litlen(&mut bw, 65);
        // length 99: symbol 257 + (99-3 base?) length base table: find symbol.
        // 99 falls in symbol 285? No: LENS table — 99 is base for sym index 22
        // (LENS[22]=99, LEXT[22]=4). symbol = 257+22 = 279.
        write_fixed_litlen(&mut bw, 279);
        bw.write_bits(0, 4); // 4 extra length bits, value 0 -> length 99
        // distance 1: dist symbol 0, 0 extra bits. Fixed distance codes are
        // 5 bits, value = symbol, emitted MSB-first.
        bw.write_bits_msb(0, 5);
        // end of block: symbol 256 -> fixed code 7 bits value 0b0000000.
        write_fixed_litlen(&mut bw, 256);
        let deflate = bw.finish();

        let mut gz: Vec<u8> = Vec::new();
        gz.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0xFF]);
        gz.extend_from_slice(&deflate);
        gz.extend_from_slice(&[0, 0, 0, 0, 100, 0, 0, 0]); // trailer (ignored)

        let mut out = [0u8; 128];
        let n = gunzip(&gz, &mut out).expect("gunzip fixed");
        assert_eq!(n, 100);
        assert!(out[..100].iter().all(|&b| b == 65));
    }

    #[test]
    fn rejects_non_gzip() {
        let mut out = [0u8; 16];
        assert_eq!(gunzip(b"not gzip data!!!", &mut out), Err(InflateError::BadGzipHeader));
        assert!(!is_gzip(b"MZ"));
        assert!(is_gzip(&[0x1F, 0x8B, 0x08]));
    }

    #[test]
    fn output_overflow_is_caught() {
        let payload = b"too big for the tiny output buffer";
        let len = payload.len() as u16;
        let mut gz: Vec<u8> = Vec::new();
        gz.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0xFF]);
        gz.push(0x01);
        gz.extend_from_slice(&len.to_le_bytes());
        gz.extend_from_slice(&(!len).to_le_bytes());
        gz.extend_from_slice(payload);
        let mut out = [0u8; 8];
        assert_eq!(gunzip(&gz, &mut out), Err(InflateError::OutputOverflow));
    }

    // ── tiny LSB-first bit writer used only by the round-trip test ──────────
    struct BitWriter {
        bytes: Vec<u8>,
        cur: u32,
        nbits: u32,
    }
    impl BitWriter {
        fn new() -> Self {
            Self { bytes: Vec::new(), cur: 0, nbits: 0 }
        }
        // Write `n` bits, LSB-first (DEFLATE element ordering for headers/extra).
        fn write_bits(&mut self, val: u32, n: u32) {
            self.cur |= (val & ((1 << n) - 1)) << self.nbits;
            self.nbits += n;
            while self.nbits >= 8 {
                self.bytes.push((self.cur & 0xFF) as u8);
                self.cur >>= 8;
                self.nbits -= 8;
            }
        }
        // Write `n` bits MSB-first into the LSB-first stream (Huffman codes are
        // packed MSB-first per RFC 1951 §3.1.1).
        fn write_bits_msb(&mut self, val: u32, n: u32) {
            for i in (0..n).rev() {
                self.write_bits((val >> i) & 1, 1);
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.nbits > 0 {
                self.bytes.push((self.cur & 0xFF) as u8);
            }
            self.bytes
        }
    }

    // Emit a fixed-Huffman literal/length symbol MSB-first.
    fn write_fixed_litlen(bw: &mut BitWriter, sym: u32) {
        let (code, nbits) = if sym <= 143 {
            (0b00110000 + sym, 8)
        } else if sym <= 255 {
            (0b110010000 + (sym - 144), 9)
        } else if sym <= 279 {
            (0b0000000 + (sym - 256), 7)
        } else {
            (0b11000000 + (sym - 280), 8)
        };
        bw.write_bits_msb(code, nbits);
    }
}
