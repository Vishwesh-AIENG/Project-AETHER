/* Phase-0 slowdown-vs-native kernels for the AETHER DBT (ch66).
 *
 * The SAME source is compiled with the SAME clang -O2 twice:
 *   - aarch64 (armv8-a, what the guest's ID registers advertise) -> run through
 *     aether-translator by aether-dbt-bench `kernels` mode;
 *   - x86_64 (baseline x86-64) -> run natively by the same harness.
 * Freestanding: no libc, no globals, no calls outside this file, so the linked
 * flat .text/.rodata blob is position-independent and can be run at any address.
 * Every entry takes <= 4 u64 args and returns u64 (a checksum the harness
 * compares between the two builds: a mismatch means a DBT miscompile).
 */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned char u8;

#if defined(__x86_64__)
#define ENTRY __attribute__((ms_abi, used, noinline))
#else
#define ENTRY __attribute__((used, noinline))
#endif

/* integer ALU + loop-carried dependency */
ENTRY u64 k_intloop(u64 n, u64 seed, u64 a2, u64 a3) {
    u64 x = seed, acc = 0;
    for (u64 i = 0; i < n; i++) {
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
        acc += (x >> 33) ^ (acc << 3);
    }
    return acc;
}

/* byte/word memory copy (stores + loads, streaming) */
ENTRY u64 k_memcpy(u64 dst_, u64 src_, u64 n, u64 reps) {
    u8 *d = (u8 *)dst_; const u8 *s = (const u8 *)src_;
    u64 sum = 0;
    for (u64 r = 0; r < reps; r++) {
        for (u64 i = 0; i < n; i++) d[i] = (u8)(s[i] + r);
        sum += d[n / 2];
    }
    return sum;
}

/* strlen over many NUL-terminated strings (data-dependent branches) */
ENTRY u64 k_strlen(u64 buf_, u64 len, u64 reps, u64 a3) {
    const u8 *b = (const u8 *)buf_;
    u64 total = 0;
    for (u64 r = 0; r < reps; r++) {
        const u8 *p = b, *end = b + len;
        while (p < end) { const u8 *q = p; while (*q) q++; total += (u64)(q - p); p = q + 1; }
    }
    return total;
}

/* insertion sort on u32 (compare + branch heavy, loads/stores) */
ENTRY u64 k_sort(u64 arr_, u64 n, u64 seed, u64 a3) {
    u32 *a = (u32 *)arr_;
    u64 x = seed;
    for (u64 i = 0; i < n; i++) { x = x * 6364136223846793005ULL + 1; a[i] = (u32)(x >> 32); }
    for (u64 i = 1; i < n; i++) {
        u32 v = a[i]; u64 j = i;
        while (j > 0 && a[j - 1] > v) { a[j] = a[j - 1]; j--; }
        a[j] = v;
    }
    u64 h = 0;
    for (u64 i = 0; i < n; i += 7) h = h * 31 + a[i];
    return h;
}

/* bitwise CRC32 (shift/xor/flag-driven) */
ENTRY u64 k_crc32(u64 buf_, u64 n, u64 reps, u64 a3) {
    const u8 *b = (const u8 *)buf_;
    u32 crc = 0xFFFFFFFFu;
    for (u64 r = 0; r < reps; r++)
        for (u64 i = 0; i < n; i++) {
            crc ^= b[i];
            for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1)));
        }
    return ~crc;
}

/* recursive calls: BL/RET-dominated (indirect-branch / return-prediction cost) */
static u64 fib(u64 n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
ENTRY u64 k_fib(u64 n, u64 a1, u64 a2, u64 a3) { return fib(n); }

/* float matrix multiply (FP / auto-vectorised SIMD) */
ENTRY u64 k_matmul(u64 a_, u64 b_, u64 c_, u64 n) {
    float *A = (float *)a_, *B = (float *)b_, *C = (float *)c_;
    for (u64 i = 0; i < n * n; i++) { A[i] = (float)(i % 13) * 0.5f; B[i] = (float)(i % 7) * 0.25f; C[i] = 0; }
    for (u64 i = 0; i < n; i++)
        for (u64 k = 0; k < n; k++) {
            float a = A[i * n + k];
            for (u64 j = 0; j < n; j++) C[i * n + j] += a * B[k * n + j];
        }
    double s = 0;
    for (u64 i = 0; i < n * n; i++) s += C[i];
    return (u64)s;
}

/* interpreter-style switch dispatch (jump table = indirect branch) */
ENTRY u64 k_interp(u64 prog_, u64 len, u64 reps, u64 a3) {
    const u8 *p = (const u8 *)prog_;
    u64 acc = 1, r0 = 3, r1 = 5;
    for (u64 r = 0; r < reps; r++)
        for (u64 i = 0; i < len; i++) {
            switch (p[i] & 7) {
            case 0: acc += r0; break;
            case 1: acc ^= r1 << 1; break;
            case 2: r0 = acc * 3; break;
            case 3: r1 += acc >> 2; break;
            case 4: acc = acc * 7 + r1; break;
            case 5: r0 ^= r1; break;
            case 6: acc -= r0 & 0xff; break;
            default: r1 = r1 * 5 + 1; break;
            }
        }
    return acc ^ r0 ^ r1;
}

/* sieve of Eratosthenes (byte stores, nested loops) */
ENTRY u64 k_sieve(u64 buf_, u64 n, u64 reps, u64 a3) {
    u8 *s = (u8 *)buf_;
    u64 count = 0;
    for (u64 r = 0; r < reps; r++) {
        for (u64 i = 0; i < n; i++) s[i] = 1;
        s[0] = s[1] = 0;
        for (u64 i = 2; i * i < n; i++)
            if (s[i]) for (u64 j = i * i; j < n; j += i) s[j] = 0;
        count = 0;
        for (u64 i = 0; i < n; i++) count += s[i];
    }
    return count;
}
