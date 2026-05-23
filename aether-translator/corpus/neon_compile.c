// AT-3 corpus generator.
//
// Compile with:
//   aarch64-linux-gnu-gcc -O2 -march=armv8-a+crypto -c neon_compile.c -o neon_compile.o
//
// One function per NEON/FP/crypto intrinsic family. The decoder must produce
// zero `Unknown` and zero `Unimplemented` after lifting every emitted word.
//
// Phase A skeleton: starter set. AT-3 fill expands to full intrinsic coverage.

#include <arm_neon.h>
#include <stdint.h>

// ---- Integer vector add/sub/mul ----
int32x4_t v_add_i32(int32x4_t a, int32x4_t b) { return vaddq_s32(a, b); }
int32x4_t v_sub_i32(int32x4_t a, int32x4_t b) { return vsubq_s32(a, b); }
int32x4_t v_mul_i32(int32x4_t a, int32x4_t b) { return vmulq_s32(a, b); }
int8x16_t v_add_i8 (int8x16_t a, int8x16_t b) { return vaddq_s8(a, b); }
int16x8_t v_add_i16(int16x8_t a, int16x8_t b) { return vaddq_s16(a, b); }
int64x2_t v_add_i64(int64x2_t a, int64x2_t b) { return vaddq_s64(a, b); }

// ---- Bitwise ----
uint32x4_t v_and(uint32x4_t a, uint32x4_t b) { return vandq_u32(a, b); }
uint32x4_t v_or (uint32x4_t a, uint32x4_t b) { return vorrq_u32(a, b); }
uint32x4_t v_xor(uint32x4_t a, uint32x4_t b) { return veorq_u32(a, b); }
uint32x4_t v_not(uint32x4_t a)               { return vmvnq_u32(a); }

// ---- Shifts ----
int32x4_t v_shl_i32(int32x4_t a) { return vshlq_n_s32(a, 5); }
int32x4_t v_shr_i32(int32x4_t a) { return vshrq_n_s32(a, 3); }

// ---- Min/Max ----
int32x4_t v_min_i32(int32x4_t a, int32x4_t b) { return vminq_s32(a, b); }
int32x4_t v_max_i32(int32x4_t a, int32x4_t b) { return vmaxq_s32(a, b); }

// ---- Compare ----
uint32x4_t v_cmpeq_i32(int32x4_t a, int32x4_t b) { return vceqq_s32(a, b); }
uint32x4_t v_cmpgt_i32(int32x4_t a, int32x4_t b) { return vcgtq_s32(a, b); }

// ---- Lane / dup / extract ----
int32x4_t  v_dup_n(int32_t x)                    { return vdupq_n_s32(x); }
int32_t    v_extract_lane(int32x4_t a)           { return vgetq_lane_s32(a, 2); }
int32x4_t  v_insert_lane(int32x4_t a, int32_t x) { return vsetq_lane_s32(x, a, 1); }

// ---- Permute / table ----
uint8x16_t v_tbl(uint8x16_t a, uint8x16_t idx)   { return vqtbl1q_u8(a, idx); }

// ---- FP ----
float32x4_t v_fadd(float32x4_t a, float32x4_t b) { return vaddq_f32(a, b); }
float32x4_t v_fmul(float32x4_t a, float32x4_t b) { return vmulq_f32(a, b); }
float32x4_t v_fma (float32x4_t a, float32x4_t b, float32x4_t c) { return vfmaq_f32(a, b, c); }
float64x2_t v_fadd64(float64x2_t a, float64x2_t b) { return vaddq_f64(a, b); }

// ---- Scalar FP ----
float  s_fadd_f32(float a, float b)   { return a + b; }
double s_fadd_f64(double a, double b) { return a + b; }
float  s_fsqrt   (float a)            { return __builtin_sqrtf(a); }

// ---- Crypto: AES ----
uint8x16_t cry_aese (uint8x16_t a, uint8x16_t k) { return vaeseq_u8 (a, k); }
uint8x16_t cry_aesd (uint8x16_t a, uint8x16_t k) { return vaesdq_u8 (a, k); }
uint8x16_t cry_aesmc(uint8x16_t a)               { return vaesmcq_u8(a); }
uint8x16_t cry_aesimc(uint8x16_t a)              { return vaesimcq_u8(a); }

// ---- Crypto: SHA1 / SHA256 ----
uint32x4_t cry_sha1c (uint32x4_t h, uint32_t e, uint32x4_t w) { return vsha1cq_u32(h, e, w); }
uint32x4_t cry_sha1p (uint32x4_t h, uint32_t e, uint32x4_t w) { return vsha1pq_u32(h, e, w); }
uint32x4_t cry_sha256h (uint32x4_t a, uint32x4_t b, uint32x4_t c) { return vsha256hq_u32(a, b, c); }
uint32x4_t cry_sha256h2(uint32x4_t a, uint32x4_t b, uint32x4_t c) { return vsha256h2q_u32(a, b, c); }
uint32x4_t cry_sha256su0(uint32x4_t a, uint32x4_t b) { return vsha256su0q_u32(a, b); }
uint32x4_t cry_sha256su1(uint32x4_t a, uint32x4_t b, uint32x4_t c) { return vsha256su1q_u32(a, b, c); }

// ---- PMULL / CRC32 ----
poly128_t  cry_pmull (poly64_t a, poly64_t b) { return vmull_p64(a, b); }
uint32_t   cry_crc32b(uint32_t crc, uint8_t  v) { return __builtin_aarch64_crc32b(crc, v); }
uint32_t   cry_crc32w(uint32_t crc, uint32_t v) { return __builtin_aarch64_crc32w(crc, v); }
uint32_t   cry_crc32cw(uint32_t crc, uint32_t v) { return __builtin_aarch64_crc32cw(crc, v); }
