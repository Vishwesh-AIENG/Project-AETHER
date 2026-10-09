//! Advanced SIMD runtime helper: executes the long tail of AArch64 Advanced SIMD
//! instructions directly on the guest q-register file, instead of hand-written
//! x86 lowerings.
//!
//! The lowering emits a Win64 CALL to [`aether_simd_exec`] (same discipline as
//! `crypto_rt`) carrying the raw ARM instruction word. Each family below is a
//! direct transcription of the ARM ARM pseudocode, operating on 128-bit register
//! values. [`supports`] accepts exactly the encodings implemented here (reserved
//! encodings are rejected), so the decoder/lifter can route a word here only when
//! the semantics are known to be exact.
//!
//! Covered (2026-10-09, framework-corpus coverage gaps):
//! - 3-different: S/UADDL{2}, S/UADDW{2}, S/USUBL{2}, S/USUBW{2}, ADDHN/RADDHN{2},
//!   SUBHN/RSUBHN{2}, S/UABAL{2}, S/UABDL{2}
//! - 3-same: AND/BIC/ORR/ORN/EOR/BSL/BIT/BIF, S/UQADD, S/UQSUB, SQDMULH, SQRDMULH,
//!   FACGE/FACGT, FMAXP/FMINP
//! - 2-reg misc: CLS/CLZ, XTN/SQXTN/UQXTN/SQXTUN{2}, SHLL{2}, S/UADALP,
//!   SCVTF/UCVTF (integer), FCVTNS/FCVTNU
//! - shift by immediate (vector + scalar D): S/USHR, S/USRA, S/URSHR, S/URSRA,
//!   SCVTF/UCVTF and FCVTZS/FCVTZU (fixed-point)
//! - by element: MLA/MLS, S/UMLAL{2}, S/UMLSL{2}, S/UMULL{2}, SQDMULH, SQRDMULH
//! - scalar 2-reg misc: FCVTZS/FCVTZU, FCVTNS/FCVTNU
//!
//! Not modelled: FPSR.QC (saturation sticky flag) and FP exception flags. FP
//! conversions use the host's current MXCSR rounding for the int->FP direction
//! (the translator's FPCR mapping), which is round-to-nearest-even by default.

#![allow(unsafe_code)] // raw ctx pointer reads/writes, like crypto_rt.rs

use crate::runtime::context::VEC_OFFSET;

// ── bit helpers ──────────────────────────────────────────────────────────────

#[inline]
fn bits(w: u32, hi: u32, lo: u32) -> u32 {
    (w >> lo) & ((1u32 << (hi - lo + 1)) - 1)
}
#[inline]
fn mask(esize: u32) -> u128 {
    if esize >= 128 { u128::MAX } else { (1u128 << esize) - 1 }
}
#[inline]
fn lane(v: u128, esize: u32, i: u32) -> u64 {
    ((v >> (i * esize)) & mask(esize)) as u64
}
#[inline]
fn set_lane(v: &mut u128, esize: u32, i: u32, x: u64) {
    let m = mask(esize) << (i * esize);
    *v = (*v & !m) | (((x as u128) << (i * esize)) & m);
}
#[inline]
fn sext(x: u64, esize: u32) -> i64 {
    if esize >= 64 { x as i64 } else { ((x << (64 - esize)) as i64) >> (64 - esize) }
}
/// Extend an element to i128 (signed or unsigned per `u`).
#[inline]
fn ext(x: u64, esize: u32, unsigned: bool) -> i128 {
    if unsigned { x as i128 } else { sext(x, esize) as i128 }
}
#[inline]
fn sat_s(x: i128, esize: u32) -> u64 {
    let max = (1i128 << (esize - 1)) - 1;
    let min = -(1i128 << (esize - 1));
    (x.clamp(min, max) as u64) & (mask(esize) as u64)
}
#[inline]
fn sat_u(x: i128, esize: u32) -> u64 {
    let max = (1i128 << esize) - 1;
    x.clamp(0, max) as u64
}
#[inline]
fn low64(v: u128) -> u128 { v & (u64::MAX as u128) }
#[inline]
fn high64(v: u128) -> u128 { v >> 64 }

// ── FP helpers (bit-exact, no libm) ──────────────────────────────────────────

#[derive(Clone, Copy)]
struct Fmt { ebits: u32, fbits: u32 }
const F32: Fmt = Fmt { ebits: 8, fbits: 23 };
const F64: Fmt = Fmt { ebits: 11, fbits: 52 };
impl Fmt {
    fn width(self) -> u32 { 1 + self.ebits + self.fbits }
    fn is_nan(self, x: u64) -> bool {
        let e = (x >> self.fbits) & ((1 << self.ebits) - 1);
        e == (1 << self.ebits) - 1 && (x & ((1u64 << self.fbits) - 1)) != 0
    }
    fn is_snan(self, x: u64) -> bool { self.is_nan(x) && (x >> (self.fbits - 1)) & 1 == 0 }
    fn quiet(self, x: u64) -> u64 { x | (1u64 << (self.fbits - 1)) }
    fn abs(self, x: u64) -> u64 { x & !(1u64 << (self.width() - 1)) }
    fn to_f64(self, x: u64) -> f64 {
        if self.width() == 32 { f32::from_bits(x as u32) as f64 } else { f64::from_bits(x) }
    }
}

/// ARM FPMax / FPMin with FPCR.DN=0 (NaN propagation per FPProcessNaNs; +0 > -0).
fn fp_maxmin(f: Fmt, a: u64, b: u64, max: bool) -> u64 {
    if f.is_nan(a) || f.is_nan(b) {
        return if f.is_snan(a) { f.quiet(a) }
        else if f.is_snan(b) { f.quiet(b) }
        else if f.is_nan(a) { a }
        else { b };
    }
    let (x, y) = (f.to_f64(a), f.to_f64(b));
    if x == 0.0 && y == 0.0 {
        let sa = a >> (f.width() - 1);
        // max(+0,-0) = +0 ; min(+0,-0) = -0
        return if max { if sa == 0 { a } else { b } } else if sa == 1 { a } else { b };
    }
    if (x > y) == max { a } else { b }
}

/// Round to nearest, ties to even (integral value), for |x| below 2^fbits.
fn rne_f64(x: f64) -> f64 {
    let t = 4503599627370496.0f64; // 2^52
    let ax = f64::from_bits(x.to_bits() & !(1u64 << 63));
    if !(ax < t) {
        return x; // NaN, inf or already integral
    }
    let r = (ax + t) - t;
    if x.is_sign_negative() { -r } else { r }
}

/// FP lane (single or double) -> integer of the same width, ARM saturation,
/// NaN -> 0. `scale` multiplies first (fixed-point; power of two, exact).
fn fp_to_int(f: Fmt, x: u64, unsigned: bool, round_nearest: bool, scale: f64) -> u64 {
    let mut v = f.to_f64(x) * scale;
    if round_nearest {
        v = rne_f64(v);
    }
    // Rust float->int `as` truncates toward zero, saturates, and maps NaN to 0,
    // which is exactly ARM FPToFixed with the rounding already applied.
    match (f.width(), unsigned) {
        (32, false) => (v as i32) as u32 as u64,
        (32, true) => (v as u32) as u64,
        (_, false) => (v as i64) as u64,
        (_, true) => v as u64,
    }
}

/// Integer lane -> FP lane of the same width (`scale` = 2^-fbits, exact).
fn int_to_fp(width: u32, x: u64, unsigned: bool, scale: f64) -> u64 {
    if width == 32 {
        let f = if unsigned { (x as u32) as f32 } else { (x as u32 as i32) as f32 };
        (f * scale as f32).to_bits() as u64
    } else {
        let f = if unsigned { x as f64 } else { (x as i64) as f64 };
        (f * scale).to_bits()
    }
}

fn pow2(k: i32) -> f64 {
    f64::from_bits(((1023 + k) as u64) << 52)
}

/// ARM FPProcessNaNs (DN=0): signalling NaNs first (op1 before op2), then quiet.
fn process_nans(f: Fmt, a: u64, b: u64) -> Option<u64> {
    if f.is_snan(a) { Some(f.quiet(a)) }
    else if f.is_snan(b) { Some(f.quiet(b)) }
    else if f.is_nan(a) { Some(a) }
    else if f.is_nan(b) { Some(b) }
    else { None }
}

/// Fused multiply-add a*b + c with a single rounding (host FMA; the translator
/// already emits FMA3 for FMLA/FMADD, so the instruction is present).
#[cfg(target_arch = "x86_64")]
fn fma64(a: f64, b: f64, c: f64) -> f64 {
    #[target_feature(enable = "fma")]
    unsafe fn f(a: f64, b: f64, c: f64) -> f64 {
        use core::arch::x86_64::*;
        _mm_cvtsd_f64(_mm_fmadd_sd(_mm_set_sd(a), _mm_set_sd(b), _mm_set_sd(c)))
    }
    unsafe { f(a, b, c) }
}
#[cfg(target_arch = "x86_64")]
fn fma32(a: f32, b: f32, c: f32) -> f32 {
    #[target_feature(enable = "fma")]
    unsafe fn f(a: f32, b: f32, c: f32) -> f32 {
        use core::arch::x86_64::*;
        _mm_cvtss_f32(_mm_fmadd_ss(_mm_set_ss(a), _mm_set_ss(b), _mm_set_ss(c)))
    }
    unsafe { f(a, b, c) }
}
#[cfg(not(target_arch = "x86_64"))]
fn fma64(a: f64, b: f64, c: f64) -> f64 { a * b + c }
#[cfg(not(target_arch = "x86_64"))]
fn fma32(a: f32, b: f32, c: f32) -> f32 { a * b + c }

/// FRECPS (`two`=true: 2 - n*m) / FRSQRTS (`two`=false: (3 - n*m)/2), ARM
/// FPRecipStepFused / FPRSqrtStepFused: op1 is negated BEFORE NaN processing;
/// inf*0 gives exactly 2.0 / 1.5; otherwise one fused rounding.
fn recip_step(f: Fmt, n: u64, m: u64, two: bool) -> u64 {
    let w = f.width();
    let neg_n = n ^ (1u64 << (w - 1));
    if let Some(r) = process_nans(f, neg_n, m) {
        return r;
    }
    let is_inf = |x: u64| f.abs(x) == ((1u64 << f.ebits) - 1) << f.fbits;
    let is_zero = |x: u64| f.abs(x) == 0;
    let enc = |v: f64| if w == 32 { (v as f32).to_bits() as u64 } else { v.to_bits() };
    if (is_inf(neg_n) && is_zero(m)) || (is_zero(neg_n) && is_inf(m)) {
        return enc(if two { 2.0 } else { 1.5 });
    }
    if is_inf(neg_n) || is_inf(m) {
        let sign = ((neg_n ^ m) >> (w - 1)) & 1;
        return (sign << (w - 1)) | (((1u64 << f.ebits) - 1) << f.fbits);
    }
    let c = if two { 2.0 } else { 3.0 };
    if w == 32 {
        let r = fma32(f32::from_bits(neg_n as u32), f32::from_bits(m as u32), c as f32);
        (if two { r } else { r * 0.5 }).to_bits() as u64
    } else {
        let r = fma64(f64::from_bits(neg_n), f64::from_bits(m), c);
        (if two { r } else { r * 0.5 }).to_bits()
    }
}

/// ARM RecipEstimate (ARMv8.0, no FEAT_RPRES): `a` in 256..512.
fn recip_estimate(a: u64) -> u64 {
    let a = a * 2 + 1;
    let b = (1u64 << 19) / a;
    (b + 1) / 2
}

/// ARM RecipSqrtEstimate: `a` in 128..512.
fn rsqrt_estimate(a: u64) -> u64 {
    let a = if a < 256 { a * 2 + 1 } else { (((a >> 1) << 1) + 1) * 2 };
    let mut b = 512u64;
    while a * (b + 1) * (b + 1) < (1u64 << 28) {
        b += 1;
    }
    (b + 1) / 2
}

/// The 52-bit fraction and biased exponent of an S or D value (S fraction is
/// left-aligned into 52 bits, as in the ARM pseudocode).
fn frac52_exp(f: Fmt, x: u64) -> (u64, i64) {
    let frac = (x & ((1u64 << f.fbits) - 1)) << (52 - f.fbits);
    let exp = ((x >> f.fbits) & ((1u64 << f.ebits) - 1)) as i64;
    (frac, exp)
}

/// ARM FPRecipEstimate (FRECPE), FPCR.DN=0, FZ=0, round-to-nearest.
fn frecpe(f: Fmt, x: u64) -> u64 {
    let w = f.width();
    let sign = x & (1u64 << (w - 1));
    let inf = ((1u64 << f.ebits) - 1) << f.fbits;
    if f.is_nan(x) {
        return f.quiet(x);
    }
    let ax = f.abs(x);
    if ax == inf {
        return sign; // ±0
    }
    if ax == 0 {
        return sign | inf; // ±inf (divide by zero)
    }
    // Tiny inputs overflow: |x| < 2^-128 (S) / 2^-1024 (D) -> ±inf under RN.
    let tiny = if w == 32 { 0x0020_0000 } else { 0x0004_0000_0000_0000 };
    if ax < tiny {
        return sign | inf;
    }
    let (mut frac, mut exp) = frac52_exp(f, x);
    if exp == 0 {
        if (frac >> 51) & 1 == 0 {
            exp = -1;
            frac = (frac & ((1u64 << 50) - 1)) << 2;
        } else {
            frac = (frac & ((1u64 << 51) - 1)) << 1;
        }
    }
    let scaled = 256 | ((frac >> 44) & 0xFF);
    let mut rexp = if w == 32 { 253 } else { 2045 } - exp;
    let est = recip_estimate(scaled);
    let mut frac = (est & 0xFF) << 44;
    if rexp == 0 {
        frac = (1u64 << 51) | (frac >> 1);
    } else if rexp == -1 {
        frac = (1u64 << 50) | (frac >> 2);
        rexp = 0;
    }
    sign | ((rexp as u64) << f.fbits) | (frac >> (52 - f.fbits))
}

/// ARM FPRSqrtEstimate (FRSQRTE), FPCR.DN=0, FZ=0.
fn frsqrte(f: Fmt, x: u64) -> u64 {
    let w = f.width();
    let sign = x >> (w - 1) & 1;
    let inf = ((1u64 << f.ebits) - 1) << f.fbits;
    if f.is_nan(x) {
        return f.quiet(x);
    }
    let ax = f.abs(x);
    if ax == 0 {
        return (sign << (w - 1)) | inf; // ±inf
    }
    if sign == 1 {
        // negative non-zero: default NaN (invalid operation)
        return if w == 32 { 0x7FC0_0000 } else { 0x7FF8_0000_0000_0000 };
    }
    if ax == inf {
        return 0;
    }
    let (mut frac, mut exp) = frac52_exp(f, x);
    if exp == 0 {
        while (frac >> 51) & 1 == 0 {
            frac = (frac << 1) & ((1u64 << 52) - 1);
            exp -= 1;
        }
        frac = (frac << 1) & ((1u64 << 52) - 1);
    }
    let scaled = if exp & 1 == 0 { 256 | ((frac >> 44) & 0xFF) } else { 128 | ((frac >> 45) & 0x7F) };
    let rexp = (if w == 32 { 380 } else { 3068 } - exp) / 2;
    let est = rsqrt_estimate(scaled);
    ((rexp as u64) << f.fbits) | ((est & 0xFF) << (f.fbits - 8))
}

/// f16 -> f32/f64 (exact; NaN quieted, sign and top payload kept).
fn half_to(f: Fmt, h: u64) -> u64 {
    let sign = (h >> 15) & 1;
    let e = (h >> 10) & 0x1F;
    let m = h & 0x3FF;
    let w = f.width();
    if e == 0x1F {
        let exp = ((1u64 << f.ebits) - 1) << f.fbits;
        let pay = if m != 0 { (m << (f.fbits - 10)) | (1u64 << (f.fbits - 1)) } else { 0 };
        return (sign << (w - 1)) | exp | pay;
    }
    let mag = if e == 0 { m as f64 * pow2(-24) } else { (1024 + m) as f64 * pow2(e as i32 - 25) };
    let v = if sign == 1 { -mag } else { mag };
    if w == 32 { (v as f32).to_bits() as u64 } else { v.to_bits() }
}

/// f32/f64 -> f16, round to nearest even (overflow -> inf), NaN quieted.
fn to_half(f: Fmt, x: u64) -> u64 {
    let w = f.width();
    let sign = ((x >> (w - 1)) & 1) << 15;
    if f.is_nan(x) {
        let top9 = (x >> (f.fbits - 10)) & 0x1FF;
        return sign | 0x7C00 | 0x200 | top9;
    }
    let ax = f.abs(x);
    if ax == ((1u64 << f.ebits) - 1) << f.fbits {
        return sign | 0x7C00;
    }
    if ax == 0 {
        return sign;
    }
    // Normalize to an integer significand m and unbiased exponent e: |x| = m * 2^(e - fbits).
    let bias = (1i64 << (f.ebits - 1)) - 1;
    let be = (ax >> f.fbits) as i64;
    let (mut m, e) = if be == 0 {
        (ax & ((1u64 << f.fbits) - 1), 1 - bias)
    } else {
        ((ax & ((1u64 << f.fbits) - 1)) | (1u64 << f.fbits), be - bias)
    };
    // Half exponent (clamped to the subnormal floor -14), then RNE to 10+1 bits.
    let he = e.max(-14);
    let shift = (f.fbits as i64 - 10) + (he - e);
    let q = if shift >= 128 {
        0
    } else {
        let mm = m as u128;
        let s = shift as u32;
        let qq = (mm >> s) as u64;
        let rem = mm & ((1u128 << s) - 1);
        let halfp = 1u128 << (s - 1);
        if rem > halfp || (rem == halfp && qq & 1 == 1) { qq + 1 } else { qq }
    };
    m = q;
    let mut he = he;
    if m >= 2048 {
        m >>= 1;
        he += 1;
    }
    if m < 1024 {
        return sign | m; // subnormal (or rounded to zero)
    }
    if he > 15 {
        return sign | 0x7C00; // overflow -> inf (RN)
    }
    sign | (((he + 15) as u64) << 10) | (m - 1024)
}

// ── family classification ────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Family {
    ThreeDiff,
    ThreeSame,
    TwoRegMisc,
    ShiftImm,
    ScalarShiftImm,
    ByElem,
    ScalarTwoRegMisc,
    ScalarThreeSame,
    ScalarFcvtHalf,
}

fn classify(w: u32) -> Option<Family> {
    let q = bits(w, 30, 30);
    let u = bits(w, 29, 29);
    let size = bits(w, 23, 22);
    // Vector 3-different: 0 Q U 01110 size 1 Rm opcode 00 Rn Rd.
    if w & 0x9F20_0C00 == 0x0E20_0000 {
        let op = bits(w, 15, 12);
        return (size != 3 && op <= 0b0111).then_some(Family::ThreeDiff);
    }
    // Vector 3-same: 0 Q U 01110 size 1 Rm opcode 1 Rn Rd.
    if w & 0x9F20_0400 == 0x0E20_0400 {
        let op = bits(w, 15, 11);
        let ok = match op {
            0b00011 => true,                                   // logical
            0b00001 | 0b00101 => !(size == 3 && q == 0),       // S/UQADD, S/UQSUB
            0b10110 => size == 1 || size == 2,                 // SQ(R)DMULH
            0b11101 | 0b11110 => u == 1 && !(size & 1 == 1 && q == 0), // FACGE/GT, FMAXP/FMINP
            0b11111 => u == 0 && !(size & 1 == 1 && q == 0),           // FRECPS/FRSQRTS
            _ => false,
        };
        return ok.then_some(Family::ThreeSame);
    }
    // Vector 2-reg misc: 0 Q U 01110 size 10000 opcode 10 Rn Rd.
    if w & 0x9F3E_0C00 == 0x0E20_0800 {
        let op = bits(w, 16, 12);
        let a = size >> 1;
        let ok = match op {
            0b00100 | 0b10010 | 0b10100 | 0b00110 => size != 3,  // CLS/CLZ, XTN/SQXTUN, SQXTN/UQXTN, S/UADALP
            0b10011 => u == 1 && size != 3,                      // SHLL
            0b11101 => !(size & 1 == 1 && q == 0),           // S/UCVTF (a=0), FRECPE/FRSQRTE (a=1)
            0b11010 => a == 0 && !(size & 1 == 1 && q == 0), // FCVTNS/NU
            0b11011 => a == 1 && !(size & 1 == 1 && q == 0), // FCVTZS/ZU
            _ => false,
        };
        return ok.then_some(Family::TwoRegMisc);
    }
    // Vector shift by immediate: 0 Q U 011110 immh immb opcode 1 Rn Rd (immh != 0).
    if w & 0x9F80_0400 == 0x0F00_0400 {
        let immh = bits(w, 22, 19);
        if immh == 0 || (immh & 0b1000 != 0 && q == 0) {
            return None;
        }
        let op = bits(w, 15, 11);
        let ok = match op {
            0b00000 | 0b00010 | 0b00100 | 0b00110 => true,
            0b11100 | 0b11111 => immh >= 0b0100,       // fixed-point: S or D only
            _ => false,
        };
        return ok.then_some(Family::ShiftImm);
    }
    // Scalar shift by immediate: 01 U 111110 immh immb opcode 1 Rn Rd.
    if w & 0xDF80_0400 == 0x5F00_0400 {
        let immh = bits(w, 22, 19);
        let op = bits(w, 15, 11);
        let ok = match op {
            0b00000 | 0b00010 | 0b00100 | 0b00110 => immh & 0b1000 != 0, // D only
            0b11100 | 0b11111 => immh >= 0b0100,
            _ => false,
        };
        return ok.then_some(Family::ScalarShiftImm);
    }
    // Vector x indexed element (integer): 0 Q U 01111 size L M Rm opcode H 0 Rn Rd.
    if w & 0x9F00_0400 == 0x0F00_0000 {
        if size != 1 && size != 2 {
            return None;
        }
        let op = bits(w, 15, 12);
        let ok = match (u, op) {
            (1, 0b0000) | (1, 0b0100) => true,                    // MLA, MLS
            (_, 0b0010) | (_, 0b0110) | (_, 0b1010) => true,      // S/UMLAL, S/UMLSL, S/UMULL
            (0, 0b1100) | (0, 0b1101) => true,                    // SQDMULH, SQRDMULH
            _ => false,
        };
        return ok.then_some(Family::ByElem);
    }
    // Scalar 2-reg misc: 01 U 11110 size 10000 opcode 10 Rn Rd.
    if w & 0xDF3E_0C00 == 0x5E20_0800 {
        let op = bits(w, 16, 12);
        let a = size >> 1;
        // FCVTZS/ZU, FCVTNS/NU, FRECPE/FRSQRTE
        let ok = matches!((op, a), (0b11011, 1) | (0b11010, 0) | (0b11101, 1));
        return ok.then_some(Family::ScalarTwoRegMisc);
    }
    // Scalar 3-same: 01 U 11110 size 1 Rm opcode 1 Rn Rd — FRECPS/FRSQRTS (U=0).
    if w & 0xDF20_0400 == 0x5E20_0400 {
        return (bits(w, 15, 11) == 0b11111 && u == 0).then_some(Family::ScalarThreeSame);
    }
    // Scalar FCVT (FP data-processing 1-source, opcode 0001 opc) to/from half.
    // The S<->D forms are typed elsewhere; only half-precision ones come here.
    if w & 0xFF20_7C00 == 0x1E20_4000 && bits(w, 20, 17) == 0b0001 {
        let (ft, opc) = (bits(w, 23, 22), bits(w, 16, 15));
        let ok = ft != 2 && opc != 2 && ft != opc && (ft == 3 || opc == 3);
        return ok.then_some(Family::ScalarFcvtHalf);
    }
    None
}

/// True if [`exec`] implements this exact encoding.
pub fn supports(word: u32) -> bool {
    classify(word).is_some()
}

/// Execute `word`: `d` is the current Vd, `read(r)` returns V`r`. Returns the new
/// Vd, or `None` if the word is not supported.
pub fn exec(w: u32, d: u128, read: &dyn Fn(u32) -> u128) -> Option<u128> {
    let fam = classify(w)?;
    let q = bits(w, 30, 30) == 1;
    let u = bits(w, 29, 29) == 1;
    let size = bits(w, 23, 22);
    let rn = bits(w, 9, 5);
    let rm = bits(w, 20, 16);
    let n = read(rn);
    let out = match fam {
        Family::ThreeDiff => three_diff(w, q, u, size, d, n, read(rm)),
        Family::ThreeSame => three_same(w, q, u, size, d, n, read(rm)),
        Family::TwoRegMisc => two_reg_misc(w, q, u, size, d, n),
        Family::ShiftImm => shift_imm(w, q, u, d, n, false),
        Family::ScalarShiftImm => shift_imm(w, true, u, d, n, true),
        Family::ByElem => by_elem(w, q, u, size, d, n, read),
        Family::ScalarTwoRegMisc => scalar_two_reg_misc(w, u, size, n),
        Family::ScalarThreeSame => {
            let f = if size & 1 == 1 { F64 } else { F32 };
            let es = f.width();
            recip_step(f, lane(n, es, 0), lane(read(rm), es, 0), size >> 1 == 0) as u128
        }
        Family::ScalarFcvtHalf => {
            let (ft, opc) = (bits(w, 23, 22), bits(w, 16, 15));
            let fmt = |t: u32| if t == 1 { F64 } else { F32 };
            (if ft == 3 { half_to(fmt(opc), lane(n, 16, 0)) } else { to_half(fmt(ft), lane(n, fmt(ft).width(), 0)) })
                as u128
        }
    };
    Some(out)
}

/// Q=0 forms write only the low 64 bits and zero the rest.
#[inline]
fn fit(v: u128, q: bool) -> u128 { if q { v } else { low64(v) } }

fn three_diff(w: u32, q: bool, u: bool, size: u32, d: u128, n: u128, m: u128) -> u128 {
    let op = bits(w, 15, 12);
    let es = 8 << size; // narrow element size
    let ws = es * 2; // wide element size
    let cnt = 64 / es; // elements per 64-bit half
    let half = |v: u128| if q { high64(v) } else { low64(v) };
    let mut r: u128 = 0;
    match op {
        0b0000 | 0b0010 | 0b0001 | 0b0011 | 0b0101 | 0b0111 => {
            let (nh, mh) = (half(n), half(m));
            for i in 0..cnt {
                let b = ext(lane(mh, es, i), es, u);
                let a = if op == 0b0001 || op == 0b0011 {
                    ext(lane(n, ws, i), ws, u) // wide operand (W forms)
                } else {
                    ext(lane(nh, es, i), es, u)
                };
                let v = match op {
                    0b0000 | 0b0001 => a + b,
                    0b0010 | 0b0011 => a - b,
                    0b0111 => (a - b).abs(),
                    _ => ext(lane(d, ws, i), ws, true) + (a - b).abs(), // ABAL (modular)
                };
                set_lane(&mut r, ws, i, v as u64);
            }
            r
        }
        // ADDHN/RADDHN (0100), SUBHN/RSUBHN (0110): high half of the wide result.
        _ => {
            let round = if u { 1i128 << (es - 1) } else { 0 };
            let mut lo: u128 = 0;
            for i in 0..cnt {
                let a = lane(n, ws, i) as i128;
                let b = lane(m, ws, i) as i128;
                let s = if op == 0b0100 { a + b } else { a - b } + round;
                set_lane(&mut lo, es, i, ((s as u128 >> es) & mask(es)) as u64);
            }
            if q { low64(d) | (lo << 64) } else { lo }
        }
    }
}

fn three_same(w: u32, q: bool, u: bool, size: u32, d: u128, n: u128, m: u128) -> u128 {
    let op = bits(w, 15, 11);
    match op {
        0b00011 => {
            let r = match (u, size) {
                (false, 0) => n & m,
                (false, 1) => n & !m,
                (false, 2) => n | m,
                (false, _) => n | !m,
                (true, 0) => n ^ m,
                (true, 1) => (d & n) | (!d & m),  // BSL
                (true, 2) => (n & m) | (d & !m),  // BIT
                (true, _) => (d & m) | (n & !m),  // BIF
            };
            fit(r, q)
        }
        0b00001 | 0b00101 => {
            let es = 8 << size;
            let cnt = if q { 128 / es } else { 64 / es };
            let mut r = 0u128;
            for i in 0..cnt {
                let a = ext(lane(n, es, i), es, u);
                let b = ext(lane(m, es, i), es, u);
                let s = if op == 0b00001 { a + b } else { a - b };
                set_lane(&mut r, es, i, if u { sat_u(s, es) } else { sat_s(s, es) });
            }
            r
        }
        0b10110 => {
            let es = 8 << size;
            let cnt = if q { 128 / es } else { 64 / es };
            let mut r = 0u128;
            for i in 0..cnt {
                let a = sext(lane(n, es, i), es) as i128;
                let b = sext(lane(m, es, i), es) as i128;
                set_lane(&mut r, es, i, sqdmulh(a, b, es, u));
            }
            r
        }
        _ => {
            // FP (U=1): 11101 FACGE(a=0)/FACGT(a=1); 11110 FMAXP(a=0)/FMINP(a=1).
            let a = size >> 1 == 1;
            let f = if size & 1 == 1 { F64 } else { F32 };
            let es = f.width();
            let cnt = if q { 128 / es } else { 64 / es };
            let mut r = 0u128;
            if op == 0b11111 {
                // FRECPS (a=0) / FRSQRTS (a=1), U=0
                for i in 0..cnt {
                    set_lane(&mut r, es, i, recip_step(f, lane(n, es, i), lane(m, es, i), !a));
                }
            } else if op == 0b11101 {
                for i in 0..cnt {
                    let x = f.to_f64(f.abs(lane(n, es, i)));
                    let y = f.to_f64(f.abs(lane(m, es, i)));
                    let t = if a { x > y } else { x >= y };
                    set_lane(&mut r, es, i, if t { mask(es) as u64 } else { 0 });
                }
            } else {
                // Pairwise over the concatenation Vm:Vn (Vn supplies the low results).
                let src = |j: u32| if j < cnt { lane(n, es, j) } else { lane(m, es, j - cnt) };
                for i in 0..cnt {
                    set_lane(&mut r, es, i, fp_maxmin(f, src(2 * i), src(2 * i + 1), !a));
                }
            }
            r
        }
    }
}

/// SQDMULH / SQRDMULH on one element: sat((2*a*b [+ round]) >> esize).
fn sqdmulh(a: i128, b: i128, es: u32, round: bool) -> u64 {
    let p = 2 * a * b + if round { 1i128 << (es - 1) } else { 0 };
    sat_s(p >> es, es)
}

fn two_reg_misc(w: u32, q: bool, u: bool, size: u32, d: u128, n: u128) -> u128 {
    let op = bits(w, 16, 12);
    let es = 8 << size;
    match op {
        0b00100 => {
            let cnt = if q { 128 / es } else { 64 / es };
            let mut r = 0u128;
            for i in 0..cnt {
                let x = lane(n, es, i);
                let v = if u {
                    // CLZ within esize bits
                    (x << (64 - es)).leading_zeros().min(es) as u64
                } else {
                    // CLS: CLZ of (x[es-1:1] EOR x[es-2:0]) over es-1 bits
                    let y = ((x >> 1) ^ x) & ((1u64 << (es - 1)) - 1);
                    ((y << (64 - (es - 1))).leading_zeros().min(es - 1)) as u64
                };
                set_lane(&mut r, es, i, v);
            }
            r
        }
        0b10010 | 0b10100 => {
            // XTN (U=0,10010) / SQXTUN (U=1,10010) / SQXTN (U=0,10100) / UQXTN (U=1,10100)
            let ws = es * 2;
            let cnt = 64 / es;
            let mut lo = 0u128;
            for i in 0..cnt {
                let x = lane(n, ws, i);
                let v = match (op, u) {
                    (0b10010, false) => x & (mask(es) as u64),
                    (0b10010, true) => sat_u(sext(x, ws) as i128, es),
                    (_, false) => sat_s(sext(x, ws) as i128, es),
                    (_, true) => sat_u(x as i128, es),
                };
                set_lane(&mut lo, es, i, v);
            }
            if q { low64(d) | (lo << 64) } else { lo }
        }
        0b10011 => {
            // SHLL{2}: widen and shift left by esize.
            let ws = es * 2;
            let src = if q { high64(n) } else { low64(n) };
            let mut r = 0u128;
            for i in 0..(64 / es) {
                set_lane(&mut r, ws, i, lane(src, es, i) << es);
            }
            r
        }
        0b00110 => {
            // S/UADALP: Vd.wide[i] += ext(n[2i]) + ext(n[2i+1])
            let ws = es * 2;
            let cnt = if q { 128 / ws } else { 64 / ws };
            let mut r = 0u128;
            for i in 0..cnt {
                let s = ext(lane(n, es, 2 * i), es, u) + ext(lane(n, es, 2 * i + 1), es, u)
                    + lane(d, ws, i) as i128;
                set_lane(&mut r, ws, i, s as u64);
            }
            r
        }
        _ => {
            // 11101 S/UCVTF (a=0) or FRECPE/FRSQRTE (a=1); 11010 FCVTNS/FCVTNU.
            let f = if size & 1 == 1 { F64 } else { F32 };
            let a = size >> 1 == 1;
            let es = f.width();
            let cnt = if q { 128 / es } else { 64 / es };
            let mut r = 0u128;
            for i in 0..cnt {
                let x = lane(n, es, i);
                let v = match (op, a, u) {
                    (0b11101, false, _) => int_to_fp(es, x, u, 1.0),
                    (0b11101, true, false) => frecpe(f, x),
                    (0b11101, true, true) => frsqrte(f, x),
                    (0b11011, _, _) => fp_to_int(f, x, u, false, 1.0), // FCVTZS/ZU
                    _ => fp_to_int(f, x, u, true, 1.0),                 // FCVTNS/NU
                };
                set_lane(&mut r, es, i, v);
            }
            r
        }
    }
}

fn shift_imm(w: u32, q: bool, u: bool, d: u128, n: u128, scalar: bool) -> u128 {
    let immh = bits(w, 22, 19);
    let immhb = bits(w, 22, 16);
    let op = bits(w, 15, 11);
    let es = 8u32 << (31 - immh.leading_zeros()); // 8/16/32/64 from immh's top bit
    let cnt = if scalar { 1 } else if q { 128 / es } else { 64 / es };
    let mut r = 0u128;
    if op == 0b11100 || op == 0b11111 {
        // Fixed-point converts: fbits = 2*esize - immh:immb.
        let fbits = (2 * es - immhb) as i32;
        let f = if es == 64 { F64 } else { F32 };
        for i in 0..cnt {
            let x = lane(n, es, i);
            let v = if op == 0b11100 {
                int_to_fp(es, x, u, pow2(-fbits))
            } else {
                fp_to_int(f, x, u, false, pow2(fbits))
            };
            set_lane(&mut r, es, i, v);
        }
        return r;
    }
    let shift = 2 * es - immhb; // 1..=esize
    let rounding = op == 0b00100 || op == 0b00110;
    let accumulate = op == 0b00010 || op == 0b00110;
    for i in 0..cnt {
        let x = ext(lane(n, es, i), es, u);
        let rc = if rounding { 1i128 << (shift - 1) } else { 0 };
        let mut v = (x + rc) >> shift;
        if accumulate {
            v += lane(d, es, i) as i128;
        }
        set_lane(&mut r, es, i, v as u64);
    }
    r
}

fn by_elem(w: u32, q: bool, u: bool, size: u32, d: u128, n: u128, read: &dyn Fn(u32) -> u128) -> u128 {
    let op = bits(w, 15, 12);
    let (h, l, mbit) = (bits(w, 11, 11), bits(w, 21, 21), bits(w, 20, 20));
    let (rm, idx) = if size == 1 {
        (bits(w, 19, 16), (h << 2) | (l << 1) | mbit)
    } else {
        (bits(w, 20, 16), (h << 1) | l)
    };
    let es = 8 << size;
    let elem_raw = lane(read(rm), es, idx);
    let mut r = 0u128;
    match op {
        0b0000 | 0b0100 if u => {
            // MLA / MLS (modular)
            let cnt = if q { 128 / es } else { 64 / es };
            for i in 0..cnt {
                let p = (lane(n, es, i) as u128).wrapping_mul(elem_raw as u128);
                let acc = lane(d, es, i) as u128;
                let v = if op == 0 { acc.wrapping_add(p) } else { acc.wrapping_sub(p) };
                set_lane(&mut r, es, i, v as u64);
            }
            r
        }
        0b1100 | 0b1101 => {
            let cnt = if q { 128 / es } else { 64 / es };
            let b = sext(elem_raw, es) as i128;
            for i in 0..cnt {
                let a = sext(lane(n, es, i), es) as i128;
                set_lane(&mut r, es, i, sqdmulh(a, b, es, op == 0b1101));
            }
            r
        }
        _ => {
            // S/UMLAL (0010), S/UMLSL (0110), S/UMULL (1010): widening, "2" = Q.
            let ws = es * 2;
            let src = if q { high64(n) } else { low64(n) };
            let b = ext(elem_raw, es, u);
            for i in 0..(64 / es) {
                let p = ext(lane(src, es, i), es, u) * b;
                let acc = lane(d, ws, i) as i128;
                let v = match op {
                    0b0010 => acc + p,
                    0b0110 => acc - p,
                    _ => p,
                };
                set_lane(&mut r, ws, i, v as u64);
            }
            r
        }
    }
}

fn scalar_two_reg_misc(w: u32, u: bool, size: u32, n: u128) -> u128 {
    let op = bits(w, 16, 12);
    let f = if size & 1 == 1 { F64 } else { F32 };
    let x = lane(n, f.width(), 0);
    (match op {
        0b11101 if u => frsqrte(f, x),
        0b11101 => frecpe(f, x),
        _ => fp_to_int(f, x, u, op == 0b11010, 1.0),
    }) as u128
}

// ── Win64 entry point ────────────────────────────────────────────────────────

/// Called from translated code: executes `word` on the q-register file at `ctx`.
/// Unsupported words leave the registers untouched (the lifter only routes
/// supported words here).
///
/// # Safety
/// `ctx` must point at a live guest context (q-registers at `VEC_OFFSET`).
pub unsafe extern "C" fn aether_simd_exec(ctx: *mut u8, word: u32) {
    let reg = |r: u32| -> u128 {
        let mut b = [0u8; 16];
        unsafe { core::ptr::copy_nonoverlapping(ctx.add(VEC_OFFSET + r as usize * 16), b.as_mut_ptr(), 16) };
        u128::from_le_bytes(b)
    };
    let rd = word & 0x1F;
    if let Some(v) = exec(word, reg(rd), &reg) {
        let b = v.to_le_bytes();
        unsafe { core::ptr::copy_nonoverlapping(b.as_ptr(), ctx.add(VEC_OFFSET + rd as usize * 16), 16) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(w: u32, regs: &[(u32, u128)]) -> u128 {
        let get = |r: u32| regs.iter().find(|(i, _)| *i == r).map(|x| x.1).unwrap_or(0);
        exec(w, get(w & 0x1F), &get).expect("supported")
    }
    fn h(x: f32) -> u128 { x.to_bits() as u128 }

    #[test]
    fn rejects_reserved_and_unrelated() {
        assert!(!supports(0xD503_201F)); // NOP
        assert!(!supports(0x0EE0_0000)); // 3-diff size=11 (PMULL .1q handled elsewhere)
        assert!(!supports(0x0F48_0400)); // SSHR .2d with Q=0 (reserved)
    }

    #[test]
    fn widening_add_sub() {
        // UADDW V0.8H, V1.8H, V2.8B = 0x2E221020
        let r = run(0x2E22_1020, &[(1, 0x0001_00FF), (2, 0x0101)]);
        assert_eq!(r & 0xFFFF_FFFF, 0x0002_0100);
        // SADDL V0.4S, V1.4H, V2.4H = 0x0E620020: -1 + -1 = -2
        let r = run(0x0E62_0020, &[(1, 0xFFFF), (2, 0xFFFF)]);
        assert_eq!(r as u32, (-2i32) as u32);
        // USUBL2 V0.4S, V1.8H, V2.8H = 0x6E622020: upper halves 5 - 7 = -2 (mod 2^32)
        let r = run(0x6E62_2020, &[(1, 5u128 << 64), (2, 7u128 << 64)]);
        assert_eq!(r as u32, (-2i32) as u32);
    }

    #[test]
    fn high_narrow() {
        // RADDHN V0.8B, V1.8H, V2.8H = 0x2E224020: (0x0180+0x0000+0x80)>>8 = 2
        let r = run(0x2E22_4020, &[(1, 0x0180), (2, 0)]);
        assert_eq!(r & 0xFF, 2);
        assert_eq!(r >> 64, 0, "Q=0 zeroes the upper half");
        // ADDHN2 keeps the low half
        let r = run(0x4E22_4020, &[(0, 0xAB), (1, 0x0180), (2, 0)]);
        assert_eq!(r & 0xFF, 0xAB);
        assert_eq!((r >> 64) & 0xFF, 1);
    }

    #[test]
    fn logical_bif_orn() {
        // BIF V0.8B, V1.8B, V2.8B = 0x2EE21C20: d = (d & m) | (n & !m)
        let r = run(0x2EE2_1C20, &[(0, 0xF0), (1, 0x0F), (2, 0xCC)]);
        assert_eq!(r, (0xF0 & 0xCC) | (0x0F & !0xCC & 0xFF));
        // ORN V0.16B, V1.16B, V2.16B = 0x4EE21C20
        let r = run(0x4EE2_1C20, &[(1, 0), (2, u128::MAX)]);
        assert_eq!(r, 0);
    }

    #[test]
    fn rounding_shifts() {
        // URSHR V0.2D, V1.2D, #8 = 0x6F782420: (0x180 + 0x80) >> 8 = 2
        let r = run(0x6F78_2420, &[(1, 0x180 | (0x7Fu128 << 64))]);
        assert_eq!(r as u64, 2);
        assert_eq!((r >> 64) as u64, 0);
        // SRSRA V0.4S, V1.4S, #1 = 0x4F3F3420: d + round(-3/2) = 10 + (-1) = 9
        let r = run(0x4F3F_3420, &[(0, 10), (1, (-3i32) as u32 as u128)]);
        assert_eq!(r as u32, 9);
        // USHR D0, D0, #24 (scalar) = 0x7F680400
        let r = run(0x7F68_0400, &[(0, 0xAB00_0000_0000u128)]);
        assert_eq!(r, 0xAB00_0000_0000u128 >> 24);
    }

    #[test]
    fn saturating_narrow_and_sqdmulh() {
        // SQXTUN V0.8B, V1.8H = 0x2E212820: -5 -> 0, 300 -> 255, 7 -> 7
        let r = run(0x2E21_2820, &[(1, 0xFFFB | (300 << 16) | (7 << 32))]);
        assert_eq!(r & 0xFF_FFFF, 0x07_FF_00);
        // UQXTN V0.4H, V1.4S = 0x2E614820: 70000 -> 65535
        let r = run(0x2E61_4820, &[(1, 70000)]);
        assert_eq!(r & 0xFFFF, 0xFFFF);
        // SQDMULH V0.4S: MIN*MIN saturates to MAX
        let r = run(0x4EA2_B420, &[(1, 0x8000_0000), (2, 0x8000_0000)]);
        assert_eq!(r as u32, 0x7FFF_FFFF);
        // SQRDMULH by element V1.4S, V1.4S, V0.S[0] = 0x4F80D021: 0x40000000^2*2>>32 = 0x20000000
        let r = run(0x4F80_D021, &[(0, 0x4000_0000), (1, 0x4000_0000)]);
        assert_eq!(r as u32, 0x2000_0000);
    }

    #[test]
    fn umull_by_element_and_clz() {
        // UMULL V2.2D, V0.2S, V1.S[0] = 0x2F81A002: 0xFFFFFFFF * 2
        let r = run(0x2F81_A002, &[(0, 0xFFFF_FFFF), (1, 2)]);
        assert_eq!(r as u64, 0x1_FFFF_FFFE);
        // CLZ V0.4S, V0.4S = 0x6EA04800: clz(1) = 31, clz(0) = 32
        let r = run(0x6EA0_4800, &[(0, 1)]);
        assert_eq!(r as u32, 31);
        assert_eq!((r >> 32) as u32, 32);
    }

    #[test]
    fn reciprocal_estimates_match_arm() {
        // Known ARMv8.0 FRECPE/FRSQRTE outputs (from the RecipEstimate tables):
        // FRECPE(1.0f) = 0x3F7F8000 (0.998046875), FRECPE(2.0f) = 0x3EFF8000,
        // FRSQRTE(1.0f) = 0x3F7F8000, FRSQRTE(4.0f) = 0x3EFF8000.
        assert_eq!(frecpe(F32, 1.0f32.to_bits() as u64), 0x3F7F_8000);
        assert_eq!(frecpe(F32, 2.0f32.to_bits() as u64), 0x3EFF_8000);
        assert_eq!(frsqrte(F32, 1.0f32.to_bits() as u64), 0x3F7F_8000);
        assert_eq!(frsqrte(F32, 4.0f32.to_bits() as u64), 0x3EFF_8000);
        // Estimate is within ~1/256 of the true value across a sweep.
        for k in 1..2000u32 {
            let x = 0.37f32 * k as f32;
            let r = f32::from_bits(frecpe(F32, x.to_bits() as u64) as u32);
            assert!((r * x - 1.0).abs() < 1.0 / 200.0, "frecpe({x}) = {r}");
            let s = f32::from_bits(frsqrte(F32, x.to_bits() as u64) as u32);
            assert!((s * s * x - 1.0).abs() < 1.0 / 100.0, "frsqrte({x}) = {s}");
        }
        // Specials: FRECPE(0) = +inf, FRECPE(-inf) = -0, FRSQRTE(-1) = default NaN.
        assert_eq!(frecpe(F32, 0), 0x7F80_0000);
        assert_eq!(frecpe(F32, 0xFF80_0000), 0x8000_0000);
        assert_eq!(frsqrte(F32, (-1.0f32).to_bits() as u64), 0x7FC0_0000);
        // Double precision: FRECPE(1.0) = 0x3FEFF00000000000.
        assert_eq!(frecpe(F64, 1.0f64.to_bits()), 0x3FEF_F000_0000_0000);
    }

    #[test]
    fn recip_steps_fused_and_specials() {
        // FRECPS(n, m) = 2 - n*m ; FRSQRTS = (3 - n*m)/2 ; inf*0 -> 2.0 / 1.5.
        let s = |x: f32| x.to_bits() as u64;
        assert_eq!(recip_step(F32, s(1.5), s(0.5), true), s(1.25));
        assert_eq!(recip_step(F32, s(1.5), s(1.0), false), s(0.75));
        assert_eq!(recip_step(F32, s(f32::INFINITY), s(0.0), true), s(2.0));
        assert_eq!(recip_step(F32, s(0.0), s(f32::INFINITY), false), s(1.5));
        // Vector FRECPS V0.4S, V1.4S, V2.4S = 0x4E22FC20 through exec.
        let r = run(0x4E22_FC20, &[(1, h(3.0)), (2, h(0.25))]);
        assert_eq!(r as u32, 1.25f32.to_bits());
    }

    #[test]
    fn half_precision_fcvt() {
        // FCVT S2, H1 = 0x1EE24022: 0x3C00 (1.0h) -> 1.0f; upper bits zeroed.
        let r = run(0x1EE2_4022, &[(1, 0x3C00), (2, u128::MAX)]);
        assert_eq!(r, 1.0f32.to_bits() as u128);
        // FCVT H0, S1 = 0x1E23C020: 65504 -> 0x7BFF, 65520 -> inf, 1/3 -> 0x3555.
        assert_eq!(run(0x1E23_C020, &[(1, h(65504.0))]), 0x7BFF);
        assert_eq!(run(0x1E23_C020, &[(1, h(65520.0))]), 0x7C00);
        assert_eq!(run(0x1E23_C020, &[(1, h(1.0 / 3.0))]), 0x3555);
        // Subnormal half: 2^-24 -> 0x0001 ; -2^-25 (tie to even) -> 0x8000.
        assert_eq!(run(0x1E23_C020, &[(1, h(5.960_464_5e-8))]), 0x0001);
        assert_eq!(run(0x1E23_C020, &[(1, h(-2.980_232_2e-8))]), 0x8000);
        // FCVT D0, H1 = 0x1EE2C020: smallest subnormal half -> 2^-24 exactly.
        assert_eq!(run(0x1EE2_C020, &[(1, 0x0001)]), pow2(-24).to_bits() as u128);
    }

    #[test]
    fn fp_converts_and_compares() {
        // UCVTF V0.4S, V0.4S = 0x6E21D800: 0xFFFFFFFF -> 4294967296.0
        let r = run(0x6E21_D800, &[(0, 0xFFFF_FFFF)]);
        assert_eq!(r as u32, 4294967296.0f32.to_bits());
        // FCVTZS V0.4S, V0.4S, #8 (fixed) = 0x4F38FC00: 1.5 * 256 = 384
        let r = run(0x4F38_FC00, &[(0, h(1.5))]);
        assert_eq!(r as u32, 384);
        // FCVTNU V0.4S, V0.4S = 0x6E21A800: 2.5 -> 2 (ties to even), -1 -> 0
        let r = run(0x6E21_A800, &[(0, h(2.5) | (h(-1.0) << 32))]);
        assert_eq!(r as u64, 2);
        // FCVTZS S0, S0 (scalar) = 0x5EA1B800: NaN -> 0, 3e9 saturates
        let r = run(0x5EA1_B800, &[(0, h(3.0e9))]);
        assert_eq!(r, 0x7FFF_FFFF);
        // FACGT V0.4S, V1.4S, V2.4S = 0x6EA2EC20: |-3| > |2|
        let r = run(0x6EA2_EC20, &[(1, h(-3.0)), (2, h(2.0))]);
        assert_eq!(r as u32, 0xFFFF_FFFF);
        // FCVTZU V0.4S, V0.4S = 0x6EA1B800: 3e9 -> 3000000000, -1 -> 0, NaN -> 0
        let r = run(0x6EA1_B800, &[(0, h(3.0e9) | (h(-1.0) << 32) | ((0x7FC0_0000u128) << 64))]);
        assert_eq!(r as u32, 3_000_000_000);
        assert_eq!((r >> 32) as u32, 0);
        assert_eq!((r >> 64) as u32, 0);
        // FCVTZS V0.2D, V0.2D = 0x4EE1B800: -2.7 -> -2
        let r = run(0x4EE1_B800, &[(0, (-2.7f64).to_bits() as u128)]);
        assert_eq!(r as u64, (-2i64) as u64);
        // FMAXP V0.2D, V0.2D, V0.2D = 0x6E60F400 over [1.0, 4.0]
        let r = run(0x6E60_F400, &[(0, 1.0f64.to_bits() as u128 | ((4.0f64.to_bits() as u128) << 64))]);
        assert_eq!(r as u64, 4.0f64.to_bits());
    }
}
