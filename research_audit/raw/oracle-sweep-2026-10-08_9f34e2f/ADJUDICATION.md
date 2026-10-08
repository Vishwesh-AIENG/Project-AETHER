# Independent adjudication of single-instruction oracle FAILs

Ground truth computed with exact rational arithmetic from ARM ARM pseudocode (FPCR=0: round-to-nearest-even, no flush-to-zero, no default-NaN).

| family | verdict | FAIL blocks | distinct words | example (block, reg, DBT, REF, TRUTH) |
|---|---|---:|---:|---|
| REV (32) | DBT correct (reference bug) | 3 | 1 | `t_5ac00800_c0` x0 DBT=0x1000000 REF=0x1 TRUTH=0x1000000 |
| REV (64) | DBT correct (reference bug) | 3 | 1 | `t_dac00cc6_c0` x6 DBT=0x6000080ffffffff REF=0xffffffff80000006 TRUTH=0x6000080ffffffff |
| scalar FRINTA | REF correct (DBT miscompile) | 2 | 2 | `s_1e264042_c2` v2 DBT=0x0 REF=0x80000000 TRUTH=0x80000000 |
| vec FMLA | DBT correct (reference bug) | 39 | 38 | `s_4e22cfec_c0` v12 DBT=0x248c041c248c041d248c041c248c041d REF=0x248c041c248c041c248c041c248c041c TRUTH=0x248c041c248c041d248c041c248c041d |
| vec FMLS | REF correct (DBT miscompile) | 11 | 11 | `s_4ea2ce0f_c2` v15 DBT=0x7fffffffffffffff5a5a5a5a5a5a5a5a REF=0xffffffff7fffffff5a5a5a5a5a5a5a5a TRUTH=0xffffffff7fffffff5a5a5a5a5a5a5a5a |
| vec FMLS | DBT correct (reference bug) | 11 | 10 | `s_4eabce03_c0` v3 DBT=0x91ddc9f291ddc9f291ddc9f291ddc9f7 REF=0x91ddc9f191ddc9f191ddc9f191ddc9f6 TRUTH=0x91ddc9f291ddc9f291ddc9f291ddc9f7 |
| vec FRINTA | REF correct (DBT miscompile) | 3 | 3 | `s_2e218800_c1` v0 DBT=0x0 REF=0x8000000000000000 TRUTH=0x8000000000000000 |
| vec FRINTA | both differ from ground truth | 2 | 2 | `s_2e218821_c1` v1 DBT=0x0 REF=0xbf80000000000000 TRUTH=0x8000000000000000 |
| vec FRINTM | DBT correct (reference bug) | 264 | 97 | `s_0e219800_c0` v0 DBT=0x0 REF=0x3f800000 TRUTH=0x0 |
| vec FRINTP | DBT correct (reference bug) | 45 | 21 | `s_0ea18800_c0` v0 DBT=0x3f800000 REF=0x0 TRUTH=0x3f800000 |
