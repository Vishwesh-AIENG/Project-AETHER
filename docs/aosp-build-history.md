# AOSP Build History — AETHER `aether_arm64`

Chronological ledger of every `m -j8` build attempt from initial bring-up
through the first successful image production. Each section documents one
build run: how far it got, what failed, and what fix went into the next
attempt.

Build environment: WSL2 Ubuntu-24.04 on Windows 11, AMD Ryzen, 8 cores,
AOSP `android-14.0.0_r74`, target `aether_arm64-ap2a-user`.


## Run 1

**Phase**: process spawn
**Outcome**: died at 3 s on SIGHUP — bash terminated when WSL invocation closed
**Fix for run 2**: wrap launcher with `setsid nohup ... </dev/null >/dev/null 2>&1 & disown`. No repo change; pattern adopted in `wsl-scripts/phase5_build.sh` later.
