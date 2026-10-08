# Oracle FAIL/DBTERR classification

## Single-instruction FAIL: 183 distinct words, 383 blocks

| mnemonic | distinct words | example word | example decode | example divergence |
|---|---:|---|---|---|
| frintm | 97 | 0x0e219800 | frintm	v0.2s, v0.2s | `v0  DBT=0x00000000000000000000000000000000  REF=0x0000000000000000000000003f800000` |
| fmla | 38 | 0x4e22cfec | fmla	v12.4s, v31.4s, v2.4s | `v12 DBT=0x248c041c248c041d248c041c248c041d  REF=0x248c041c248c041c248c041c248c041c` |
| frintp | 21 | 0x0ea18800 | frintp	v0.2s, v0.2s | `v0  DBT=0x0000000000000000000000003f800000  REF=0x00000000000000000000000000000000` |
| fmls | 18 | 0x4ea2ce0f | fmls	v15.4s, v16.4s, v2.4s | `v15 DBT=0x7fffffffffffffff5a5a5a5a5a5a5a5a  REF=0xffffffff7fffffff5a5a5a5a5a5a5a5a` |
| frinta | 7 | 0x1e264042 | frinta	s2, s2 | `v2  DBT=0x00000000000000000000000000000000  REF=0x00000000000000000000000080000000` |
| rev | 2 | 0x5ac00800 | rev	w0, w0 | `x0  DBT=0x0000000001000000  REF=0x0000000000000001` |

## Single-instruction DBTERR: 40 distinct words, 120 blocks

| mnemonic | distinct words | example word | example decode | example divergence |
|---|---:|---|---|---|
| bif | 36 | 0x2ee01c61 | bif	v1.8b, v3.8b, v0.8b | `dbt: decode word[0]=0x2ee01c61 failed: Reserved` |
| orn | 4 | 0x0ee11c41 | orn	v1.8b, v2.8b, v1.8b | `dbt: decode word[0]=0x0ee11c41 failed: Reserved` |

## Multi-instruction (bb_*) blocks

### bb_libhwui: 15 DBTERR blocks

mnemonics present in failing blocks (count of blocks): bif=18, fcmp=18, dup=12, ext=9, shl=9, cmlt=9, csel=9, cset=9, fcmgt=6, csetm=3, cmp=3, tst=3, mov=3, bsl=3

- `bb_libhwui_21c4b0_c0` `dbt: decode word[3]=0x2ee41c60 failed: Reserved` words: tst	w11, #0x1; csetm	w10, ne	// ne = any; dup	v4.2s, w10; bif	v0.8b, v3.8b, v4.8b; bif	v1.8b, v2.8b, v4.8b; cmp	x0, x8
- `bb_libhwui_21c4b0_c1` `dbt: decode word[3]=0x2ee41c60 failed: Reserved` words: tst	w11, #0x1; csetm	w10, ne	// ne = any; dup	v4.2s, w10; bif	v0.8b, v3.8b, v4.8b; bif	v1.8b, v2.8b, v4.8b; cmp	x0, x8
- `bb_libhwui_21c4b0_c2` `dbt: decode word[3]=0x2ee41c60 failed: Reserved` words: tst	w11, #0x1; csetm	w10, ne	// ne = any; dup	v4.2s, w10; bif	v0.8b, v3.8b, v4.8b; bif	v1.8b, v2.8b, v4.8b; cmp	x0, x8
- `bb_libhwui_240634_c0` `dbt: decode word[7]=0x2ee21c24 failed: Reserved` words: ext	v1.16b, v0.16b, v0.16b, #8; fcmgt	v2.4s, v0.4s, v1.4s; fcmgt	v3.4s, v1.4s, v0.4s; ext	v4.16b, v1.16b, v1.16b, #8; ext	v2.16b, v2.16b, v2.16b, #8; mov	v5.8b, v3.8b; bsl	v5.8b, v1.8b, v0.8b; bif	v4.8b, v1.8b, v2.8b
- `bb_libhwui_240634_c1` `dbt: decode word[7]=0x2ee21c24 failed: Reserved` words: ext	v1.16b, v0.16b, v0.16b, #8; fcmgt	v2.4s, v0.4s, v1.4s; fcmgt	v3.4s, v1.4s, v0.4s; ext	v4.16b, v1.16b, v1.16b, #8; ext	v2.16b, v2.16b, v2.16b, #8; mov	v5.8b, v3.8b; bsl	v5.8b, v1.8b, v0.8b; bif	v4.8b, v1.8b, v2.8b
- `bb_libhwui_240634_c2` `dbt: decode word[7]=0x2ee21c24 failed: Reserved` words: ext	v1.16b, v0.16b, v0.16b, #8; fcmgt	v2.4s, v0.4s, v1.4s; fcmgt	v3.4s, v1.4s, v0.4s; ext	v4.16b, v1.16b, v1.16b, #8; ext	v2.16b, v2.16b, v2.16b, #8; mov	v5.8b, v3.8b; bsl	v5.8b, v1.8b, v0.8b; bif	v4.8b, v1.8b, v2.8b

### bb_libsurfaceflinger: 6 DBTERR blocks

mnemonics present in failing blocks (count of blocks): fcmgt=9, ext=9, bif=6, mov=6, fsub=3, shl=3, cmge=3, and=3, fadd=3, bsl=3

- `bb_libsurfaceflinger_1c2280_c0` `dbt: decode word[1]=0x2ee31c41 failed: Reserved` words: fcmgt	v3.2s, v2.2s, v1.2s; bif	v1.8b, v2.8b, v3.8b; shl	v2.2s, v4.2s, #31; cmge	v2.2s, v2.2s, #0; and	v1.8b, v1.8b, v2.8b; mov	v1.d[1], v1.d[0]; fadd	v2.4s, v0.4s, v1.4s; fsub	v0.4s, v0.4s, v1.4s
- `bb_libsurfaceflinger_1c2280_c1` `dbt: decode word[1]=0x2ee31c41 failed: Reserved` words: fcmgt	v3.2s, v2.2s, v1.2s; bif	v1.8b, v2.8b, v3.8b; shl	v2.2s, v4.2s, #31; cmge	v2.2s, v2.2s, #0; and	v1.8b, v1.8b, v2.8b; mov	v1.d[1], v1.d[0]; fadd	v2.4s, v0.4s, v1.4s; fsub	v0.4s, v0.4s, v1.4s
- `bb_libsurfaceflinger_1c2280_c2` `dbt: decode word[1]=0x2ee31c41 failed: Reserved` words: fcmgt	v3.2s, v2.2s, v1.2s; bif	v1.8b, v2.8b, v3.8b; shl	v2.2s, v4.2s, #31; cmge	v2.2s, v2.2s, #0; and	v1.8b, v1.8b, v2.8b; mov	v1.d[1], v1.d[0]; fadd	v2.4s, v0.4s, v1.4s; fsub	v0.4s, v0.4s, v1.4s
- `bb_libsurfaceflinger_251ba8_c0` `dbt: decode word[7]=0x2ee21c24 failed: Reserved` words: ext	v1.16b, v0.16b, v0.16b, #8; fcmgt	v2.4s, v0.4s, v1.4s; fcmgt	v3.4s, v1.4s, v0.4s; ext	v4.16b, v1.16b, v1.16b, #8; ext	v2.16b, v2.16b, v2.16b, #8; mov	v5.8b, v3.8b; bsl	v5.8b, v1.8b, v0.8b; bif	v4.8b, v1.8b, v2.8b
- `bb_libsurfaceflinger_251ba8_c1` `dbt: decode word[7]=0x2ee21c24 failed: Reserved` words: ext	v1.16b, v0.16b, v0.16b, #8; fcmgt	v2.4s, v0.4s, v1.4s; fcmgt	v3.4s, v1.4s, v0.4s; ext	v4.16b, v1.16b, v1.16b, #8; ext	v2.16b, v2.16b, v2.16b, #8; mov	v5.8b, v3.8b; bsl	v5.8b, v1.8b, v0.8b; bif	v4.8b, v1.8b, v2.8b
- `bb_libsurfaceflinger_251ba8_c2` `dbt: decode word[7]=0x2ee21c24 failed: Reserved` words: ext	v1.16b, v0.16b, v0.16b, #8; fcmgt	v2.4s, v0.4s, v1.4s; fcmgt	v3.4s, v1.4s, v0.4s; ext	v4.16b, v1.16b, v1.16b, #8; ext	v2.16b, v2.16b, v2.16b, #8; mov	v5.8b, v3.8b; bsl	v5.8b, v1.8b, v0.8b; bif	v4.8b, v1.8b, v2.8b

### bb_libhwui: 2 FAIL blocks

mnemonics present in failing blocks (count of blocks): fadd=4, fminnm=4, dup=2, frintp=2, frintm=2, mov=2

- `bb_libhwui_2863f4_c0` `v1  DBT=0x00000000000000000000000000000000  REF=0x00000000000000001212121212121210` words: dup	v1.2s, w8; mov	w8, #0x1                   	// #1; fadd	v3.2s, v2.2s, v3.2s; fadd	v1.2s, v0.2s, v1.2s; frintp	v3.2s, v3.2s; frintm	v1.2s, v1.2s; fminnm	v3.2s, v3.2s, v6.2s; fminnm	v1.2s, v1.2s, v6.2s
- `bb_libhwui_2863f4_c1` `v1  DBT=0x0000000000000000bf800000bf800000  REF=0x00000000000000008606060680000000` words: dup	v1.2s, w8; mov	w8, #0x1                   	// #1; fadd	v3.2s, v2.2s, v3.2s; fadd	v1.2s, v0.2s, v1.2s; frintp	v3.2s, v3.2s; frintm	v1.2s, v1.2s; fminnm	v3.2s, v3.2s, v6.2s; fminnm	v1.2s, v1.2s, v6.2s

### bb_libsurfaceflinger: 38 FAIL blocks

mnemonics present in failing blocks (count of blocks): fsub=77, fadd=52, frintm=43, fdiv=38, dup=25, fmul=24, mov=16, fcmeq=7, movk=7, fcvt=4, fminnm=4, fmax=3, frintp=2

- `bb_libsurfaceflinger_253cb0_c0` `v2  DBT=0x00000000000000000000000000000000  REF=0x3ff00000000000003ff0000000000000` words: fadd	d1, d1, d3; fadd	s0, s0, s4; fadd	v2.2d, v2.2d, v5.2d; frintm	d1, d1; fcvt	d0, s0; frintm	v2.2d, v2.2d; mov	w8, #0x4effffff            	// #1325400063; fcvt	s1, d1
- `bb_libsurfaceflinger_253cb0_c1` `v2  DBT=0xbff0000000000000bff0000000000000  REF=0x80000000000000008000000000000000` words: fadd	d1, d1, d3; fadd	s0, s0, s4; fadd	v2.2d, v2.2d, v5.2d; frintm	d1, d1; fcvt	d0, s0; frintm	v2.2d, v2.2d; mov	w8, #0x4effffff            	// #1325400063; fcvt	s1, d1
- `bb_libsurfaceflinger_46a1d0_c0` `v8  DBT=0x0f0f0f0f0f0f0f0e0f0f0f0f0f0f0f0d  REF=0xbf800000bf800000bf800000bf800000` words: fadd	v7.4s, v7.4s, v24.4s; mov	w8, #0x42e80000            	// #1122500608; frintm	v8.4s, v5.4s; fmul	v6.4s, v6.4s, v26.4s; fsub	v17.4s, v20.4s, v17.4s; fcmeq	v30.4s, v1.4s, #0.0; fsub	v8.4s, v5.4s, v8.4s; fsub	v6.4s, v7.4s, v6.4s
- `bb_libsurfaceflinger_46a1d0_c1` `v8  DBT=0x3f800000050505053f80000005050505  REF=0x85050505bf80000085050505bf800000` words: fadd	v7.4s, v7.4s, v24.4s; mov	w8, #0x42e80000            	// #1122500608; frintm	v8.4s, v5.4s; fmul	v6.4s, v6.4s, v26.4s; fsub	v17.4s, v20.4s, v17.4s; fcmeq	v30.4s, v1.4s, #0.0; fsub	v8.4s, v5.4s, v8.4s; fsub	v6.4s, v7.4s, v6.4s
- `bb_libsurfaceflinger_46a1d0_c2` `v8  DBT=0x3f8000003f8000000000000000000000  REF=0xa5a5a5a5a5a5a5a50000000000000000` words: fadd	v7.4s, v7.4s, v24.4s; mov	w8, #0x42e80000            	// #1122500608; frintm	v8.4s, v5.4s; fmul	v6.4s, v6.4s, v26.4s; fsub	v17.4s, v20.4s, v17.4s; fcmeq	v30.4s, v1.4s, #0.0; fsub	v8.4s, v5.4s, v8.4s; fsub	v6.4s, v7.4s, v6.4s
- `bb_libsurfaceflinger_46a86c_c0` `v18 DBT=0x3939393939393938393939393939393b  REF=0xbf7ff46cbf7ff46cbf7ff46cbf7ff46c` words: dup	v25.4s, w8; mov	w8, #0x4eff0000            	// #1325334528; frintm	v24.4s, v19.4s; fadd	v21.4s, v21.4s, v25.4s; fsub	v6.4s, v6.4s, v18.4s; fdiv	v17.4s, v23.4s, v17.4s; fmul	v16.4s, v16.4s, v28.4s; fsub	v18.4s, v19.4s, v24.4s

### bb_libui: 5 FAIL blocks

mnemonics present in failing blocks (count of blocks): frintm=13, fcmp=2, fcsel=2, bsl=2, mov=2, frintp=2, dup=2

- `bb_libui_6e9dc_c0` `v1  DBT=0x00000000000000003f8000003f800000  REF=0x00000000000000000000000000000000` words: fcmp	s3, s1; fcsel	s1, s3, s1, mi	// mi = first; mov	v3.8b, v5.8b; bsl	v3.8b, v2.8b, v0.8b; frintm	s0, s4; frintm	s2, s1; frintp	v1.2s, v3.2s; dup	v3.2s, v1.s[0]
- `bb_libui_6e9dc_c2` `v1  DBT=0x0000000000000000000000003f800000  REF=0x00000000000000000000000000000000` words: fcmp	s3, s1; fcsel	s1, s3, s1, mi	// mi = first; mov	v3.8b, v5.8b; bsl	v3.8b, v2.8b, v0.8b; frintm	s0, s4; frintm	s2, s1; frintp	v1.2s, v3.2s; dup	v3.2s, v1.s[0]
- `bb_libui_6ea64_c0` `v1  DBT=0x00000000000000000000000000000000  REF=0x00000000000000003f8000003f800000` words: frintm	s0, s3; frintm	s2, s1; frintm	v1.2s, v4.2s
- `bb_libui_6ea64_c1` `v1  DBT=0x0000000000000000bf80000000000000  REF=0x0000000000000000800000003f800000` words: frintm	s0, s3; frintm	s2, s1; frintm	v1.2s, v4.2s
- `bb_libui_6ea64_c2` `v1  DBT=0x00000000000000000000000000000000  REF=0x0000000000000000000000003f800000` words: frintm	s0, s3; frintm	s2, s1; frintm	v1.2s, v4.2s

