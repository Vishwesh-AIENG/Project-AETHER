//! Bit-slicing helpers used across decoders.
//!
//! Every helper is `const` + inlinable so the optimizer collapses them down
//! to a couple of shifts and masks.

#[inline]
pub const fn field(word: u32, hi: u32, lo: u32) -> u32 {
    debug_assert!(hi >= lo && hi < 32);
    let width = hi - lo + 1;
    let mask = if width == 32 { u32::MAX } else { (1u32 << width) - 1 };
    (word >> lo) & mask
}

#[inline]
pub const fn bit(word: u32, n: u32) -> bool {
    ((word >> n) & 1) != 0
}

/// Sign-extend `value` from `from_bits` to a full `i64`.
#[inline]
pub const fn sext64(value: u64, from_bits: u32) -> i64 {
    let shift = 64 - from_bits;
    ((value << shift) as i64) >> shift
}

/// Sign-extend an N-bit value into i32. Caller guarantees `from_bits <= 32`.
#[inline]
pub const fn sext32(value: u32, from_bits: u32) -> i32 {
    let shift = 32 - from_bits;
    ((value << shift) as i32) >> shift
}

/// ARM ARM `DecodeBitMasks(N, imms, immr, immediate)` — produces the 64-bit
/// (or 32-bit) immediate value for logical-immediate encodings.
///
/// Returns `None` on the reserved encodings ARM ARM flags as UNALLOCATED.
/// `for_64` distinguishes between the 64-bit form (sf=1, N may be 1) and
/// 32-bit form (sf=0, N must be 0).
///
/// Reference: ARM ARM DDI 0487J, pseudocode `DecodeBitMasks`.
pub fn decode_bit_masks(n: u32, imms: u32, immr: u32, for_64: bool) -> Option<u64> {
    // Combined NImms field for highest-set-bit lookup.
    let combined = ((n & 1) << 6) | ((!imms) & 0x3F);
    if combined == 0 {
        return None;
    }
    // len = highest_set_bit(combined)
    let len = 31u32 - combined.leading_zeros();
    if len == 0 {
        return None;
    }
    if !for_64 && (n & 1) != 0 {
        return None; // 32-bit form requires N==0
    }
    let levels: u32 = (1 << len) - 1; // mask of `len` bits

    // S and R are masked to `len` bits.
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None; // reserved
    }

    let esize: u32 = 1 << len;
    let d = s.wrapping_sub(r) & levels;

    let welem: u64 = if (s + 1) >= 64 {
        u64::MAX
    } else {
        (1u64 << (s + 1)) - 1
    };
    let telem: u64 = if (d + 1) >= 64 {
        u64::MAX
    } else {
        (1u64 << (d + 1)) - 1
    };

    let wmask = rotate_right_64(welem, r, esize);
    let _tmask = replicate_64(telem, esize);

    // Replicate wmask to the full datasize.
    let datasize: u32 = if for_64 { 64 } else { 32 };
    let result = replicate_64(wmask, esize) & mask_low(datasize);
    Some(result)
}

#[inline]
fn rotate_right_64(value: u64, rot: u32, esize: u32) -> u64 {
    let rot = rot % esize;
    let mask = if esize >= 64 {
        u64::MAX
    } else {
        (1u64 << esize) - 1
    };
    let v = value & mask;
    if rot == 0 {
        return v;
    }
    let lo = v >> rot;
    // Left-shift uses (esize - rot); guard the esize == 64 && rot < 64 case
    // by performing the shift only if (esize - rot) < 64.
    let hi_shift = esize - rot;
    let hi = if hi_shift >= 64 { 0 } else { v << hi_shift };
    (lo | hi) & mask
}

#[inline]
fn replicate_64(value: u64, esize: u32) -> u64 {
    if esize >= 64 {
        return value;
    }
    let mask = (1u64 << esize) - 1;
    let v = value & mask;
    let mut r = 0u64;
    let mut shift = 0u32;
    while shift < 64 {
        r |= v << shift;
        shift += esize;
    }
    r
}

#[inline]
const fn mask_low(width: u32) -> u64 {
    if width >= 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}
