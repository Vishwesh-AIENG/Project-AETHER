//! ARMv8 SHA-256 crypto-extension instructions, executed as a runtime helper.
//!
//! Android's libcrypto/BoringSSL emits `sha256su0/su1/h/h2` UNCONDITIONALLY — the
//! ARMv8.2 build treats the crypto extension as architecturally mandatory and does
//! NOT gate on `HWCAP_SHA2` (confirmed live: the guest kernel detects no SHA2 yet
//! /system/bin/init still executed `sha256su0`). So the DBT must run these
//! correctly. The ctx-template lowering emits a Win64 `CALL` to
//! [`aether_crypto_sha256`] with the guest ctx base (R15) + a packed
//! `(kind,d,n,m)`; the helper reads/writes the guest q-register file at
//! `[ctx + VEC_OFFSET + reg*16]` (four little-endian u32 lanes) and applies the
//! exact ARM ARM pseudocode. Correctness is anchored by a self-test that drives
//! all four ops through a full SHA-256 of "abc" and checks the known digest.
#![allow(unsafe_code)] // raw ctx pointer reads/writes, like mmu.rs / psci.rs

use crate::runtime::context::VEC_OFFSET;

#[inline(always)]
fn ror(x: u32, n: u32) -> u32 { x.rotate_right(n) }

// Message-schedule sigmas (lowercase σ).
#[inline(always)]
fn s_sig0(x: u32) -> u32 { ror(x, 7) ^ ror(x, 18) ^ (x >> 3) }
#[inline(always)]
fn s_sig1(x: u32) -> u32 { ror(x, 17) ^ ror(x, 19) ^ (x >> 10) }
// Hash sigmas (uppercase Σ).
#[inline(always)]
fn h_sig0(x: u32) -> u32 { ror(x, 2) ^ ror(x, 13) ^ ror(x, 22) }
#[inline(always)]
fn h_sig1(x: u32) -> u32 { ror(x, 6) ^ ror(x, 11) ^ ror(x, 25) }
#[inline(always)]
fn choose(x: u32, y: u32, z: u32) -> u32 { ((y ^ z) & x) ^ z }
#[inline(always)]
fn majority(x: u32, y: u32, z: u32) -> u32 { (x & y) | ((x | y) & z) }

/// `SHA256SU0 Vd.4S, Vn.4S` — schedule update part 0.
/// `Vd[e] += σ0( e<3 ? Vd[e+1] : Vn[0] )`.
pub fn sha256su0(d: &mut [u32; 4], n: &[u32; 4]) {
    let src = [d[1], d[2], d[3], n[0]];
    for e in 0..4 {
        d[e] = d[e].wrapping_add(s_sig0(src[e]));
    }
}

/// `SHA256SU1 Vd.4S, Vn.4S, Vm.4S` — schedule update part 1 (Vn=W2, Vm=W3).
/// Completes `W[i..i+3]` given the SU0 partial in Vd.
pub fn sha256su1(d: &mut [u32; 4], n: &[u32; 4], m: &[u32; 4]) {
    let t = [n[1], n[2], n[3], m[0]]; // w[j-7]
    let mut r = [0u32; 4];
    r[0] = d[0].wrapping_add(t[0]).wrapping_add(s_sig1(m[2]));
    r[1] = d[1].wrapping_add(t[1]).wrapping_add(s_sig1(m[3]));
    r[2] = d[2].wrapping_add(t[2]).wrapping_add(s_sig1(r[0]));
    r[3] = d[3].wrapping_add(t[3]).wrapping_add(s_sig1(r[1]));
    *d = r;
}

/// Shared 4-round SHA-256 hash update. `X=[a,b,c,d]`, `Y=[e,f,g,h]`,
/// `W=[Wt+Kt]×4`. Returns the updated `X` (part1) or `Y` (!part1). Each iteration
/// reproduces one SHA-256 compression round exactly (verified by the self-test).
fn sha256hash(mut x: [u32; 4], mut y: [u32; 4], w: &[u32; 4], part1: bool) -> [u32; 4] {
    for &wt in w.iter() {
        let t1 = y[3]
            .wrapping_add(h_sig1(y[0]))
            .wrapping_add(choose(y[0], y[1], y[2]))
            .wrapping_add(wt);
        let new_e = t1.wrapping_add(x[3]); // e' = d + T1
        let new_a = t1
            .wrapping_add(h_sig0(x[0]))
            .wrapping_add(majority(x[0], x[1], x[2])); // a' = T1 + T2
        x = [new_a, x[0], x[1], x[2]];
        y = [new_e, y[0], y[1], y[2]];
    }
    if part1 { x } else { y }
}

/// `SHA256H Qd, Qn, Vm.4S` — `V[d] = hash(V[d], V[n], V[m], TRUE)`.
pub fn sha256h(d: &mut [u32; 4], n: &[u32; 4], m: &[u32; 4]) {
    *d = sha256hash(*d, *n, m, true);
}

/// `SHA256H2 Qd, Qn, Vm.4S` — `V[d] = hash(V[n], V[d], V[m], FALSE)` (operands
/// swapped vs SHA256H).
pub fn sha256h2(d: &mut [u32; 4], n: &[u32; 4], m: &[u32; 4]) {
    *d = sha256hash(*n, *d, m, false);
}

/// kind codes packed into the lowering's CALL argument.
pub const SHA256_SU0: u32 = 0;
pub const SHA256_SU1: u32 = 1;
pub const SHA256_H: u32 = 2;
pub const SHA256_H2: u32 = 3;

#[inline(always)]
unsafe fn vec_ptr(ctx: *mut u8, reg: usize) -> *mut u32 {
    unsafe { ctx.add(VEC_OFFSET + reg * 16) as *mut u32 }
}
#[inline(always)]
unsafe fn load4(ctx: *mut u8, reg: usize) -> [u32; 4] {
    let p = unsafe { vec_ptr(ctx, reg) };
    unsafe { [*p, *p.add(1), *p.add(2), *p.add(3)] }
}
#[inline(always)]
unsafe fn store4(ctx: *mut u8, reg: usize, v: [u32; 4]) {
    let p = unsafe { vec_ptr(ctx, reg) };
    unsafe {
        *p = v[0];
        *p.add(1) = v[1];
        *p.add(2) = v[2];
        *p.add(3) = v[3];
    }
}

/// Win64 entry point baked into the ctx-template lowering. `packed` =
/// `kind | (d<<8) | (n<<16) | (m<<24)`. Reads V[d]/V[n]/V[m] from the guest
/// register file at `ctx`, applies the op, and writes V[d] back.
///
/// # Safety
/// `ctx` must be the guest register-file base (R15); the touched vector slots
/// must be within the file.
pub unsafe extern "C" fn aether_crypto_sha256(ctx: *mut u8, packed: u32) {
    let kind = packed & 0xFF;
    let d = ((packed >> 8) & 0xFF) as usize;
    let n = ((packed >> 16) & 0xFF) as usize;
    let m = ((packed >> 24) & 0xFF) as usize;
    unsafe {
        let mut vd = load4(ctx, d);
        let vn = load4(ctx, n);
        match kind {
            SHA256_SU0 => sha256su0(&mut vd, &vn),
            SHA256_SU1 => {
                let vm = load4(ctx, m);
                sha256su1(&mut vd, &vn, &vm);
            }
            SHA256_H => {
                let vm = load4(ctx, m);
                sha256h(&mut vd, &vn, &vm);
            }
            SHA256_H2 => {
                let vm = load4(ctx, m);
                sha256h2(&mut vd, &vn, &vm);
            }
            _ => {}
        }
        store4(ctx, d, vd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    /// Plain reference SHA-256 schedule + compression (no crypto insns).
    fn reference_block(state: &mut [u32; 8], w16: &[u32; 16]) {
        let mut w = [0u32; 64];
        w[..16].copy_from_slice(w16);
        for i in 16..64 {
            w[i] = s_sig1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(s_sig0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }
        let mut s = *state;
        for i in 0..64 {
            let t1 = s[7]
                .wrapping_add(h_sig1(s[4]))
                .wrapping_add(choose(s[4], s[5], s[6]))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = h_sig0(s[0]).wrapping_add(majority(s[0], s[1], s[2]));
            s = [t1.wrapping_add(t2), s[0], s[1], s[2], s[3].wrapping_add(t1), s[4], s[5], s[6]];
        }
        for i in 0..8 {
            state[i] = state[i].wrapping_add(s[i]);
        }
    }

    /// The schedule, computed via SHA256SU0+SU1 the way BoringSSL drives them.
    #[test]
    fn schedule_via_su0_su1_matches_reference() {
        let w16: [u32; 16] = core::array::from_fn(|i| (0x01020304u32).wrapping_mul(i as u32 + 1));
        let mut wref = [0u32; 64];
        wref[..16].copy_from_slice(&w16);
        for i in 16..64 {
            wref[i] = s_sig1(wref[i - 2])
                .wrapping_add(wref[i - 7])
                .wrapping_add(s_sig0(wref[i - 15]))
                .wrapping_add(wref[i - 16]);
        }
        // Sliding window of 4 vectors.
        let mut w0 = [w16[0], w16[1], w16[2], w16[3]];
        let mut w1 = [w16[4], w16[5], w16[6], w16[7]];
        let mut w2 = [w16[8], w16[9], w16[10], w16[11]];
        let mut w3 = [w16[12], w16[13], w16[14], w16[15]];
        let mut i = 16;
        while i < 64 {
            let mut tmp = w0;
            sha256su0(&mut tmp, &w1);
            sha256su1(&mut tmp, &w2, &w3);
            assert_eq!(tmp, [wref[i], wref[i + 1], wref[i + 2], wref[i + 3]], "schedule @ w{i}");
            w0 = w1;
            w1 = w2;
            w2 = w3;
            w3 = tmp;
            i += 4;
        }
    }

    /// A full SHA-256 of "abc" driven entirely through sha256h/h2 (+ su0/su1 for
    /// the schedule), checked against the published digest.
    #[test]
    fn sha256_abc_via_crypto_ops() {
        // Padded single block for "abc".
        let mut block = [0u8; 64];
        block[0] = b'a';
        block[1] = b'b';
        block[2] = b'c';
        block[3] = 0x80;
        block[63] = 24; // bit length = 24
        let mut w16 = [0u32; 16];
        for i in 0..16 {
            w16[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        // Expand the full schedule using su0/su1.
        let mut w = [0u32; 64];
        w[..16].copy_from_slice(&w16);
        {
            let mut w0 = [w16[0], w16[1], w16[2], w16[3]];
            let mut w1 = [w16[4], w16[5], w16[6], w16[7]];
            let mut w2 = [w16[8], w16[9], w16[10], w16[11]];
            let mut w3 = [w16[12], w16[13], w16[14], w16[15]];
            let mut i = 16;
            while i < 64 {
                let mut tmp = w0;
                sha256su0(&mut tmp, &w1);
                sha256su1(&mut tmp, &w2, &w3);
                w[i..i + 4].copy_from_slice(&tmp);
                w0 = w1;
                w1 = w2;
                w2 = w3;
                w3 = tmp;
                i += 4;
            }
        }
        // Compression via sha256h/h2 in quad-rounds.
        let mut abcd = [H0[0], H0[1], H0[2], H0[3]];
        let mut efgh = [H0[4], H0[5], H0[6], H0[7]];
        let mut t = 0;
        while t < 64 {
            let wk = [
                w[t].wrapping_add(K[t]),
                w[t + 1].wrapping_add(K[t + 1]),
                w[t + 2].wrapping_add(K[t + 2]),
                w[t + 3].wrapping_add(K[t + 3]),
            ];
            let saved = abcd;
            sha256h(&mut abcd, &efgh, &wk);
            sha256h2(&mut efgh, &saved, &wk);
            t += 4;
        }
        let digest = [
            H0[0].wrapping_add(abcd[0]),
            H0[1].wrapping_add(abcd[1]),
            H0[2].wrapping_add(abcd[2]),
            H0[3].wrapping_add(abcd[3]),
            H0[4].wrapping_add(efgh[0]),
            H0[5].wrapping_add(efgh[1]),
            H0[6].wrapping_add(efgh[2]),
            H0[7].wrapping_add(efgh[3]),
        ];
        // SHA256("abc")
        let expected = [
            0xba7816bfu32, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
            0xf20015ad,
        ];
        assert_eq!(digest, expected, "SHA256(abc) via crypto ops");

        // Cross-check against the plain reference too.
        let mut st = H0;
        reference_block(&mut st, &w16);
        assert_eq!(st, expected, "reference SHA256(abc)");
    }
}
