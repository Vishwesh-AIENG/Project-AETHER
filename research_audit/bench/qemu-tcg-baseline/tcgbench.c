/* Same 8-instruction blocks as aether-dbt-bench exec mode, run under QEMU TCG
 * (qemu-aarch64 user mode). Per outer iteration: init regs once, then 16 non-unrolled
 * inner iterations of the block (one TB per iteration, registers live at TB exit, so
 * TCG cannot dead-code-eliminate the block). net = (with_block - empty_inner)/16.
 * Build: aarch64-linux-gnu-gcc -O2 -static -o tcgbench tcgbench.c */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
static double now(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e9+t.tv_nsec;}
static uint64_t buf[512] __attribute__((aligned(64)));
#define CLOB "x0","x1","x2","x3","x4","x5","v0","v1","v2","v3","v4","v5","v6","v7","memory","cc"
#define INIT "mov x0,#3\n mov x1,#4\n mov x3,#6\n mov x5,#8\n mov x2,%0\n add x4,x2,#192\n fmov v0.4s,#1.0\n fmov v1.4s,#2.0\n fmov v2.4s,#0.5\n fmov v3.4s,#1.5\n fmov v4.4s,#3.0\n fmov v5.4s,#0.25\n fmov v6.4s,#2.5\n fmov v7.4s,#1.25\n"
int main(int argc,char**argv){ long N=argc>1?atol(argv[1]):2000000; int R=5; void*p=buf+8;
 for(int r=0;r<R;r++){ double t0=now(); for(long i=0;i<N;i++){ asm volatile(INIT ::"r"(p):CLOB); _Pragma("GCC unroll 1") for(int j=0;j<16;j++) asm volatile("" ::: "memory");} double e=now()-t0;
  printf("baseline_init_only run=%d ns_per_16=%.2f\n",r,e/N);
  t0=now(); for(long i=0;i<N;i++){ asm volatile(INIT ::"r"(p):CLOB); _Pragma("GCC unroll 1") for(int j=0;j<16;j++) asm volatile(".inst 0x8b010000\n .inst 0xcb020021\n .inst 0x9b030c42\n .inst 0xca040063\n .inst 0x8b010000\n .inst 0xcb020021\n .inst 0x9b030c42\n .inst 0xca040063\n " ::: CLOB);} e=now()-t0;
  printf("family=%s run=%d ns_per_16=%.2f\n","int_arith (add/sub/madd/eor x8)",r,e/N);
  t0=now(); for(long i=0;i<N;i++){ asm volatile(INIT ::"r"(p):CLOB); _Pragma("GCC unroll 1") for(int j=0;j<16;j++) asm volatile(".inst 0xd37ff800\n .inst 0xd341fc21\n .inst 0x9343fc42\n .inst 0xd34c7c63\n .inst 0xb3481c84\n .inst 0xd37ff800\n .inst 0xd341fc21\n .inst 0x9343fc42\n " ::: CLOB);} e=now()-t0;
  printf("family=%s run=%d ns_per_16=%.2f\n","shift_bitfield (lsl/lsr/asr/ubfx/bfi)",r,e/N);
  t0=now(); for(long i=0;i<N;i++){ asm volatile(INIT ::"r"(p):CLOB); _Pragma("GCC unroll 1") for(int j=0;j<16;j++) asm volatile(".inst 0xeb01001f\n .inst 0x9a820020\n .inst 0x9a8304a1\n .inst 0xfa410804\n .inst 0xeb01001f\n .inst 0x9a820020\n .inst 0x9a8304a1\n .inst 0xfa410804\n " ::: CLOB);} e=now()-t0;
  printf("family=%s run=%d ns_per_16=%.2f\n","flags_csel (cmp/csel/csinc/ccmp)",r,e/N);
  t0=now(); for(long i=0;i<N;i++){ asm volatile(INIT ::"r"(p):CLOB); _Pragma("GCC unroll 1") for(int j=0;j<16;j++) asm volatile(".inst 0x1e612800\n .inst 0x1e630841\n .inst 0x1e651882\n .inst 0x1f4310c3\n .inst 0x1e612800\n .inst 0x1e630841\n .inst 0x1e651882\n .inst 0x1f4310c3\n " ::: CLOB);} e=now()-t0;
  printf("family=%s run=%d ns_per_16=%.2f\n","scalar_fp (fadd/fmul/fdiv/fmadd d)",r,e/N);
  t0=now(); for(long i=0;i<N;i++){ asm volatile(INIT ::"r"(p):CLOB); _Pragma("GCC unroll 1") for(int j=0;j<16;j++) asm volatile(".inst 0x9e620000\n .inst 0x9e780021\n .inst 0x1e624042\n .inst 0x1e220063\n .inst 0x9e620000\n .inst 0x9e780021\n .inst 0x1e624042\n .inst 0x1e220063\n " ::: CLOB);} e=now()-t0;
  printf("family=%s run=%d ns_per_16=%.2f\n","fp_convert (scvtf/fcvtzs/fcvt s<-d)",r,e/N);
  t0=now(); for(long i=0;i<N;i++){ asm volatile(INIT ::"r"(p):CLOB); _Pragma("GCC unroll 1") for(int j=0;j<16;j++) asm volatile(".inst 0x4ea18400\n .inst 0x6ee33442\n .inst 0x4e053883\n .inst 0x4e0300a4\n .inst 0x4ea18400\n .inst 0x6ee33442\n .inst 0x4e053883\n .inst 0x4e0300a4\n " ::: CLOB);} e=now()-t0;
  printf("family=%s run=%d ns_per_16=%.2f\n","simd_int (add.4s/cmhi.2d/zip1/tbl)",r,e/N);
  t0=now(); for(long i=0;i<N;i++){ asm volatile(INIT ::"r"(p):CLOB); _Pragma("GCC unroll 1") for(int j=0;j<16;j++) asm volatile(".inst 0x4e22cc20\n .inst 0x4e25d483\n .inst 0x6e27dcc5\n .inst 0x4e22cc20\n .inst 0x4e25d483\n .inst 0x6e27dcc5\n .inst 0x4e22cc20\n .inst 0x4e25d483\n " ::: CLOB);} e=now()-t0;
  printf("family=%s run=%d ns_per_16=%.2f\n","simd_fp (fmla.4s/fadd.4s/fmul.4s)",r,e/N);
  t0=now(); for(long i=0;i<N;i++){ asm volatile(INIT ::"r"(p):CLOB); _Pragma("GCC unroll 1") for(int j=0;j<16;j++) asm volatile(".inst 0xf9400040\n .inst 0xf9000441\n .inst 0xf9400845\n .inst 0xf9000c43\n .inst 0xf9400040\n .inst 0xf9000441\n .inst 0xf9400845\n .inst 0xf9000c43\n " ::: CLOB);} e=now()-t0;
  printf("family=%s run=%d ns_per_16=%.2f\n","load_store (ldr/str x, flat MMU)",r,e/N);
  t0=now(); for(long i=0;i<N;i++){ asm volatile(INIT ::"r"(p):CLOB); _Pragma("GCC unroll 1") for(int j=0;j<16;j++) asm volatile(".inst 0xf8200041\n .inst 0xf8208043\n .inst 0xc8a07c44\n .inst 0xf8200041\n .inst 0xf8208043\n .inst 0xc8a07c44\n .inst 0xf8200041\n .inst 0xf8208043\n " ::: CLOB);} e=now()-t0;
  printf("family=%s run=%d ns_per_16=%.2f\n","atomics (ldadd/swp/cas x)",r,e/N);
  t0=now(); for(long i=0;i<N;i++){ asm volatile(INIT ::"r"(p):CLOB); _Pragma("GCC unroll 1") for(int j=0;j<16;j++) asm volatile(".inst 0xd53b4200\n .inst 0xd51b4200\n .inst 0xd53bd041\n .inst 0xd53b4200\n .inst 0xd51b4200\n .inst 0xd53bd041\n .inst 0xd53b4200\n .inst 0xd51b4200\n " ::: CLOB);} e=now()-t0;
  printf("family=%s run=%d ns_per_16=%.2f\n","system (mrs nzcv/msr nzcv/mrs tpidr_el0)",r,e/N);
 } return 0; }
