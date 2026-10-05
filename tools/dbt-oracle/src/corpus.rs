//! Corpus input format.
//!
//! A corpus is a list of blocks. Each block seeds an input state, lists the
//! ARM64 instruction words, and (optionally) declares a scratch-memory region.
//! The format is a tiny line-based text format (no serde dependency) so the
//! separate corpus-extractor agent can emit it trivially from real Android code.
//!
//! ```text
//! # comment line
//! block <name>                 ; start a block
//! pc <hex>                     ; block base PC (default 0x1000)
//! insn <hex> [<hex> ...]       ; one or more little-endian u32 instruction words
//!                              ; (repeatable; all words accumulate in order)
//! x<N> <hex>                   ; seed GPR N (0..30), e.g.  x0 0x2a
//! sp <hex>                     ; seed SP
//! nzcv <hex>                   ; seed NZCV (bits [31:28])
//! v<N> <hex128>                ; seed V reg N as a 128-bit hex (up to 32 hex digits)
//! mem_base <hex>               ; guest VA / host base of scratch region (auto if omitted)
//! mem_size <dec|hex>           ; scratch region length in bytes (enables memory)
//! mem <byteoff> <hexbytes>     ; seed bytes at offset (hex, e.g. mem 0 deadbeef)
//! end                          ; end the block (optional; a new `block` also ends)
//! ```
//!
//! `mem_base` is normally auto-assigned by the harness (it must equal the host
//! pointer of the scratch buffer for the flat path). For a corpus block that
//! wants a specific guest VA, the harness rebases: it allocates the scratch at
//! the real host address and rewrites the seed's address registers by the delta.
//! For simplicity the built-in proof corpus seeds address registers to `0`
//! (base-relative) and lets the harness add the real base — see `apply_membase`.

use crate::ctx::OracleState;

/// One corpus block.
#[derive(Clone)]
pub struct Block {
    pub name: String,
    pub pc: u64,
    pub words: Vec<u32>,
    pub seed: OracleState,
    /// If set, a scratch RAM region of this many bytes is created.
    pub mem_size: Option<usize>,
    /// Initial scratch bytes: (offset, bytes).
    pub mem_init: Vec<(usize, Vec<u8>)>,
    /// GPR indices whose seeded value is a scratch OFFSET to be rebased to the
    /// real host base (so both sides address the same buffer). Empty => the
    /// seeded values are already absolute.
    pub rebase_gprs: Vec<usize>,
    /// Optional expected-known override (for self-checking corpus entries) —
    /// unused by the differential path.
    pub note: String,
}

impl Block {
    pub fn new(name: &str) -> Self {
        Block {
            name: name.to_string(),
            pc: 0x1000,
            words: Vec::new(),
            seed: OracleState::zeroed(),
            mem_size: None,
            mem_init: Vec::new(),
            rebase_gprs: Vec::new(),
            note: String::new(),
        }
    }
}

/// Parse a corpus from text. Returns `Err(msg)` on a malformed line.
pub fn parse(text: &str) -> Result<Vec<Block>, String> {
    let mut blocks = Vec::new();
    let mut cur: Option<Block> = None;
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let kw = it.next().unwrap();
        let rest: Vec<&str> = it.collect();
        let err = |m: &str| Err(format!("line {}: {}", lineno + 1, m));

        match kw {
            "block" => {
                if let Some(b) = cur.take() {
                    blocks.push(b);
                }
                cur = Some(Block::new(rest.first().copied().unwrap_or("block")));
            }
            "end" => {
                if let Some(b) = cur.take() {
                    blocks.push(b);
                }
            }
            _ => {
                let b = match cur.as_mut() {
                    Some(b) => b,
                    None => return err("directive before `block`"),
                };
                match kw {
                    "pc" => b.pc = parse_u64(rest.first().copied().unwrap_or(""))?,
                    "insn" => {
                        for w in &rest {
                            b.words.push(parse_u64(w)? as u32);
                        }
                    }
                    "sp" => b.seed.sp = parse_u64(rest.first().copied().unwrap_or(""))?,
                    "nzcv" => b.seed.nzcv = parse_u64(rest.first().copied().unwrap_or(""))? & 0xF000_0000,
                    "mem_base" => { /* accepted, but harness assigns real base */ }
                    "mem_size" => b.mem_size = Some(parse_u64(rest.first().copied().unwrap_or(""))? as usize),
                    "note" => b.note = rest.join(" "),
                    "rebase" => {
                        for r in &rest {
                            b.rebase_gprs.push(parse_u64(r)? as usize);
                        }
                    }
                    "mem" => {
                        if rest.len() < 2 {
                            return err("mem needs <offset> <hexbytes>");
                        }
                        let off = parse_u64(rest[0])? as usize;
                        let bytes = parse_hex_bytes(rest[1])?;
                        b.mem_init.push((off, bytes));
                    }
                    _ if kw.starts_with('x') => {
                        let n: usize = kw[1..].parse().map_err(|_| format!("line {}: bad reg {}", lineno + 1, kw))?;
                        if n > 30 {
                            return err("x reg index must be 0..30");
                        }
                        b.seed.gpr[n] = parse_u64(rest.first().copied().unwrap_or(""))?;
                    }
                    _ if kw.starts_with('v') => {
                        let n: usize = kw[1..].parse().map_err(|_| format!("line {}: bad vreg {}", lineno + 1, kw))?;
                        if n > 31 {
                            return err("v reg index must be 0..31");
                        }
                        let v = parse_u128(rest.first().copied().unwrap_or(""))?;
                        b.seed.set_vec_u128(n, v);
                    }
                    _ => return err(&format!("unknown directive `{}`", kw)),
                }
            }
        }
    }
    if let Some(b) = cur.take() {
        blocks.push(b);
    }
    Ok(blocks)
}

fn parse_u64(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let r = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16)
    } else {
        s.parse::<u64>()
    };
    r.map_err(|_| format!("bad integer `{}`", s))
}

fn parse_u128(s: &str) -> Result<u128, String> {
    let s = s.trim();
    let r = if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u128::from_str_radix(h, 16)
    } else {
        s.parse::<u128>()
    };
    r.map_err(|_| format!("bad 128-bit integer `{}`", s))
}

fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    let h = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
    if h.len() % 2 != 0 {
        return Err(format!("hex byte string must be even length: `{}`", s));
    }
    let mut out = Vec::with_capacity(h.len() / 2);
    let bytes = h.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nib(bytes[i])?;
        let lo = hex_nib(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nib(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("bad hex nibble `{}`", b as char)),
    }
}
