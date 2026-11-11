# Capability matrix, performance, and honest limits

Everything in the "Verified" column is backed by a script in `scripts/` whose output sits in
`reports/` or `audit/`. "Simulated" means the code path is real but the peer is a deterministic
stand-in; "Absent" means the feature does not exist and the platform says so at runtime.

## 1. Capability matrix

| Area | Capability | Status | Evidence |
| --- | --- | --- | --- |
| Ingest | APK validation, zip-slip / bomb / encrypted entry rejection | Verified | `reports/gate1/acceptance.md`, `tests/unit/test_apk_validation.py` |
| Ingest | Metadata, certificate, signing schemes cross-checked with androguard | Verified | `reports/gate1/acceptance.md` (cert `4b09702f...`, schemes v1/v2/v3) |
| Static | JADX source decode, Apktool resource decode under a worker policy | Verified | `reports/gate1`, `config/worker-policy.yml` |
| Static | Indexed search: classes, methods, fields, strings, resources, components | Verified | units 43 / strings 134 / resources 8 / components 4 on the sample |
| Static | Secret and endpoint findings with verbatim evidence | Verified | 12 evidence rows, traceability 1.0 |
| Static | APK digest cache | Verified | cold 3458 ms vs warm 89 ms (`reports/gate4`) |
| Agent | Model sees platform tools and chooses them itself | Verified | `audit/g1_acceptance.md`: 27 calls, 15 derivations |
| Agent | Reviewer rejects claims without evidence; dispatch back is bounded at 2 | Verified | `reports/gate3`: false_confident_claims=1, third failure -> BLOCKED |
| Agent | Independent review run (new capability, new run row) | Verified | `reports/gate3`, `reports/gate2` (review-run 201) |
| DAG | `depends_on` mirrored to `task_edges`, cycle/self/cross-project refusal | Verified | `reports/gate2` 18/18 |
| DAG | Claim honours parents that are DONE or PASS-checked | Verified | `reports/gate2`, `reports/gate7` |
| Evidence | Typed evidence (8 kinds) with integrity / provenance / assertion levels | Verified | `reports/gate3` 24/24, levels {integrity 11, verified 3, partial 1, failed 7} |
| Evidence | Binary artifacts: size probing for PNG/GIF/WebP/JPEG without Pillow | Verified | `tests/unit/test_p3_evidence_types.py` |
| Sandbox | AST screen + runtime stub + audit hook + process-tree kill | Verified | `reports/gate3` (escape blocked, network denied, timeout) |
| Sandbox | Strong isolation (container / seccomp) | Absent | `isolation: container` returns `strong_isolation_unavailable` |
| Capture | HAR import, flow correlation to static endpoints and UI steps | Verified | `reports/gate4`, correlated 2/3 |
| Capture | Live ProxyPin capture | Absent | `capture_query` -> `NOT_OBSERVED`; `APKPLAT_CAPTURE_DIR` unset |
| Device | Health gate over 7 states, quarantine, transport merge by serialno | Verified | `reports/gate5` 26/26 |
| Device | UI automation: hierarchy dump, dialog handling, screenshots | Verified (sim) / read-only (real) | `reports/gate5`; real probe: 15197 B PNG, nodes=2 |
| Device | Four cleanup modes incl. `PRESERVE_SESSION` | Verified (sim) | `reports/gate5`, `reports/gate6` |
| Device | Destructive action against the physical handset | Not performed | Runs were read-only by design |
| Schedule | Daily window uniqueness, identity leases, reference-only secrets | Verified | `reports/gate6` 24/24, 3 windows -> 3 triggers |
| Schedule | Resource gate returning `RESOURCE_BLOCKED` and retrying the same window | Verified | `reports/gate6` |
| Isolation | Cross-project read/write/evidence/lease refusal | Verified | `reports/gate7` 30/30 |
| UI | Board, drawer, runs, review checks, SSE stream, 21 cards | Verified | `reports/ui/gate7-board.png`, `gate7-drawer.png` |
| UI | Pixel-identical replica of the referenced product | Absent | Layout mirrors it; visual acceptance is explicitly separate (taskbook 13) |

## 2. Performance measured on this host

| Measurement | Value | How |
| --- | --- | --- |
| Static pipeline, sample APK | 3.5 s wall, 7 java files | `reports/gate1` |
| Static pipeline, cache hit | 89 ms vs 3458 ms cold | `reports/gate4` |
| Sandbox script run | 74-88 ms | `reports/gate3` |
| Model call latency | p50 2073 ms, p95 2398 ms, max 2447 ms (30 calls) | `audit/resource_baseline.md` |
| Model calls per agent loop | 4 calls, avg 6666 ms, max 9735 ms | `reports/gate3` |
| Full agent loop wall time | 35-40 s (plan -> evidence -> review -> report) | `reports/gate3` |
| Free memory during work | 1.9 GB of 15.8 GB total | `audit/resource_baseline.md` |
| Test suite | see `reports/README.md` (last recorded run) | `pytest -q` |

## 3. Honest limits

1. **No strong isolation.** The sandbox is cooperative: an audit hook plus import screening.
   A determined script can still reach the network through the model API process; the runner
   therefore also stubs sockets when `network=none`.
2. **Capture is offline.** Without ProxyPin the platform will not claim traffic it has not seen.
   `capture_query` returns `NOT_OBSERVED` with the probe result attached.
3. **One real device, read-only.** The 21-card demo, the UI steps, and the destruction matrix run
   against the simulated transport. On the physical Mi 10 the platform only read properties and
   took one screenshot.
4. **Visual replication is not functional proof.** The board reproduces the referenced layout
   closely (avatars, four columns, metrics strip, drawer with runs and checks), but taskbook 13
   requires separate acceptance for visuals and behaviour, and only behaviour is measured here.
5. **Model quality bounds the agent.** With `model_concurrency=1` and ~2 s per short call, a long
   investigation is budgeted at 24 tool calls and 8 model calls; exceeding that yields an explicit
   `tool_budget_exhausted` rather than a silent stop.
