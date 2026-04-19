# OVMS app binary size reduction — design

**Date:** 2026-04-19
**Target project:** OVMS.V3 (ESP32, ESP-IDF)
**Branch (planned):** `size-reduction`

## Problem

`build/ovms3.bin` is 4,055,264 B (≈3.87 MB) against a 4 MB app partition
(`factory` / `ota_0` / `ota_1` each 4 MB in
[OVMS.V3/partitions.csv](../../../OVMS.V3/partitions.csv)). Headroom is
~140 KB, insufficient for ongoing feature work (notably the CAN monitor at
[OVMS.V3/components/ovms_webserver/src/web_canmonitor.cpp](../../../OVMS.V3/components/ovms_webserver/src/web_canmonitor.cpp)).

## Scope

**In scope** — public-build-compatible config and build-flag changes only:

- Compiler flags (`-Os`, `-ffunction-sections`, `-fdata-sections`, `-flto`)
- Linker flags (`--gc-sections`)
- libc variant (`CONFIG_NEWLIB_NANO_FORMAT`)
- `CONFIG_LOG_COLORS`
- Webserver static-asset compression (gzip at build, `Content-Encoding: gzip`)
- Assert stripping (`NDEBUG`) scoped to third-party components
  (mongoose, wolfssl, mbedtls, duktape) under a `release` build type

**Out of scope:**

- Disabling any `CONFIG_OVMS_VEHICLE_*`, `CONFIG_OVMS_COMP_*`, or
  `CONFIG_OVMS_SC_*` that ship enabled upstream
- Modifying `CONFIG_LOG_MAXIMUM_LEVEL` (runtime DEBUG/VERBOSE logging must
  remain available for field diagnostics)
- Source-level feature deletion
- RAM/heap reduction, boot-time, image-signing changes

## Success criteria

- **Primary:** `build/ovms3.bin` ≤ 3.50 MB (≥ 512 KB headroom)
- **Stretch:** `build/ovms3.bin` ≤ 3.30 MB
- **Invariant:** all smoke-test items (below) pass on the final build
- **Invariant:** no upstream-shipped feature disabled via `CONFIG_*` changes

## Tactics

Applied in this order (cheapest-first; later levers measure against the
tightest prior state):

| # | Lever | Est. saving | Risk |
|---|---|---|---|
| 1 | `CONFIG_LOG_COLORS=n` | 2–10 KB | None |
| 2 | `CONFIG_COMPILER_OPTIMIZATION_SIZE=y` (from default `-Og` to `-Os`) | 200–500 KB | Low; verify ISR timing (CAN RX, cellular UART) |
| 3 | Force `-ffunction-sections -fdata-sections` + `--gc-sections` in any OVMS component `CMakeLists.txt` that overrides defaults | 20–100 KB | Low |
| 4 | Pre-gzip `.htm/.js/.css` webserver assets, serve with `Content-Encoding: gzip` (skip assets < 256 B) | 80–200 KB | Low |
| 5 | `CONFIG_NEWLIB_NANO_FORMAT=y` | 40–80 KB | Med; audit `%ll`, `%L[efg]`, `%a` usage and convert to `PRI*` macros first |
| 6 | `NDEBUG` for third-party release builds (mongoose, wolfssl, mbedtls, duktape) via component-scoped `target_compile_definitions` | 30–100 KB | Med; OVMS-owned code keeps its asserts |
| 7 | `-flto` (app-level first; extend to IDF components only if it links cleanly and saves meaningfully) | 100–250 KB | Med; interacts with everything prior |

Explicitly **not** in the plan: `CONFIG_LOG_MAXIMUM_LEVEL` reduction, mbedTLS
ciphersuite policy changes, final-`.bin` debug-section stripping (already
handled by `esptool` elf2image).

### Stop condition

If after lever 5 the binary is ≤ 3.30 MB with smoke tests green, levers 6–7
become optional (reserved for future headroom, not applied).

## Measurement plan

**Baseline (one-time, committed as the first commit on the branch):**

- `ls -l build/ovms3.bin` → 4,055,264 B
- `idf.py size-components` and `idf.py size-files` → `baseline-size.txt`
- Hash of `sdkconfig` to catch later drift

**Per-change workflow (one lever = one commit):**

1. Apply change
2. `idf.py fullclean && idf.py build`
3. Diff `.bin` size + `size-files` output vs. prior commit; record delta in
   the commit message
4. Smoke test (below). If it fails, or the delta is below 50% of the low
   estimate, revert the commit and note the reason in a follow-up
   `NOTES.md` entry.

**Smoke test (manual, ~5 min per lever):**

- Boots cleanly to the `OVMS#` prompt on serial console
- Wi-Fi associates; webserver reachable; dashboard loads
- `vehicle module kianiroev` attaches the Kona driver
- `/canmonitor` page streams live CAN frames over the existing
  `/ws/canmonitor` WebSocket
- Runtime `log level verbose` still yields VERBOSE output (guards the
  "we didn't accidentally strip log strings" invariant)

**Acceptance gate:** `build/ovms3.bin` ≤ 3.50 MB **and** all smoke-test
items pass.

## Risk & rollback

- One lever per commit on branch `size-reduction`
- `git revert <sha>` for any regression
- Final `SIZE-REPORT.md` on the branch: per-component baseline vs. final,
  per-commit delta, any reverted levers with rationale

## Deliverables

1. Branch `size-reduction` with up to 7 commits + 1 baseline commit
2. `SIZE-REPORT.md` summarising deltas and any reverts
3. Final `build/ovms3.bin` meeting the acceptance gate
