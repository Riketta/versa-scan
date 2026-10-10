# versa-scan — Design & Implementation Plan

Re-implementation of VirusLocal Worker (C#) in Rust. A distributed sample-scanning
system: one worker per antivirus (VM per scanner), samples dispatched over a message
bus, per-sample scan reports published back. CLI replaces the old backend/frontend
for now.

Status: **design approved pending implementation**. This document is the blueprint;
`AGENTS.md` (written at M0) becomes the rulebook once code lands. Where this doc
and code disagree after implementation starts, fix the doc.

## Locked decisions

| # | Topic | Decision |
|---|-------|----------|
| D1 | Architecture | Hexagonal (ports & adapters), **no** micro-kernel (no plugin cardinality exists here). Core has zero infra deps, enforced by workspace crate split. |
| D2 | Bus | `BusPort` (work-queue semantics: ack/nak/requeue, best-effort priority). Two adapters: RabbitMQ (`lapin`), NATS JetStream (`async-nats`). Plus in-memory for tests. |
| D3 | Scanners v1 | Open & generic first: `clamd` (TCP), `defender` (MpCmdRun), `debug` (deterministic, for tests). Commercial AVs (KES, DrWeb, NOD32, ...) ported incrementally later. |
| D4 | Artifact store | No existing backend. Address fully configurable. `vscli` embeds its own artifact storage + HTTP server (content-addressed by sha256). |
| D5 | Wire contract | Own endpoints/schemas designed fresh (see below), versioned, not backwards compatible with the C# system. |
| D6 | Layout | Cargo workspace: `crates/versa-scan-core`, `crates/versa-scan-infra`, `bins/vsd` (worker daemon), `bins/vscli` (CLI). |
| D7 | Self-updater | Implemented: manifest check, hash-verified staged swap, `vsd update` subcommand + periodic check in openbox role. |
| D8 | NATS mode | JetStream: workqueue stream for requests, limits-retention stream for reports, durable pull consumers, explicit ack, `Nats-Msg-Id` dedupe. |
| D9 | Platforms | Windows-first (AV world) with first-class Linux support (clamd/debug CI, deployments). Cross-platform from day one. |
| D10 | Gates | versa-bot style: pinned toolchain, 2024 edition, `cargo fmt --all -- --check` → `cargo clippy --all-targets --locked` → `cargo test --locked`; `[lints.clippy]` deny `unwrap_used`, `indexing_slicing`. |

## System shape

```
                       ┌────────────┐
   vscli submit ──────▶│  RabbitMQ  │──────┐
   (embedded artifact  │ or NATS JS │      ▼
    server, content-   └────────────┘   vsd worker (VM per scanner)
    addressed store)        ▲              consume → batch → fetch → scan
        │    ▲              │              → validate → report → ack
        │    └── reports ───┴────────────  publish ScanReportV1
        └── vscli --wait prints result table
```

Two worker roles (deployment config, auto-detectable from hostname as fallback):
- **sandbox** — the scan pipeline.
- **openbox** — periodic AV DB update, self-update check, optional Task Scheduler
  registration (`vsd install-task`, explicit — no magic registration on boot).

## Workspace layout

```
versa-scan/
├── Cargo.toml                    # workspace, shared [workspace.lints]
├── crates/
│   ├── versa-scan-core/          # THE hexagon. Deps: std + small facade crates only.
│   │   └── src/
│   │       ├── models/           # sample, batch, verdict, report, av profile,
│   │       │                     #   priority, role, ids, worker info, digest
│   │       ├── ports/            # scanner, bus, fetch, scheduler, self_update
│   │       └── services/         # planner, orchestrator, workspace, retry,
│   │                             #   reporter, validation, update_loop
│   ├── versa-scan-infra/         # Adapters. Depends on core. All blocking work
│   │   └── src/                  #   through tokio; process-spawn via tokio::process.
│   │       ├── bus/              # wire.rs (DTOs), rabbitmq.rs, nats.rs, in_memory.rs
│   │       ├── scanners/         # mod.rs (registry), clamd.rs, defender.rs, debug.rs
│   │       ├── fetch/            # http.rs (reqwest streaming + hash verify)
│   │       ├── process/          # tree-kill (Windows taskkill /T, POSIX group)
│   │       ├── self_update/      # manifest.rs, swap.rs (rename-swap on Windows)
│   │       ├── scheduler.rs      # tokio interval, versa-bot scheduler contract
│   │       ├── config.rs         # TOML + env, loaded once (no hot reload by design)
│   │       └── observability.rs  # tracing setup (+ optional syslog)
│   └── (test-support shared fakes live in infra under #[cfg(test)] + a small
│         dev-friendly `versa-scan-testsupport` crate if bins need it)
├── bins/
│   ├── vsd/                      # worker daemon (composition root #1)
│   └── vscli/                    # CLI (composition root #2)
│       └── src/                  # main.rs, store.rs (CAS), server.rs (axum), wait.rs
├── .github/workflows/ci.yml      # fmt → clippy → test → build; Linux + Windows matrix
├── docker-compose.yaml           # rabbitmq, nats, clamd for local dev/IT
└── versa-scan.example.toml
```

Dependency rule (compile-enforced): `infra → core` only; `bins → core + infra`.
Core never names lapin/async-nats/reqwest/axum/tokio beyond `std`-shaped traits
(`async_trait`, `serde` derive on DTO-shaped models where harmless, `time`,
`thiserror`, `tracing` facades allowed — same exception category as versa-bot).

## Core: models (internal, ACL'd)

- `SampleId`, `CorrelationId`, `ScannerId` — newtypes.
- `Sha256Digest` — hex newtype, parse/validate in core; **computation** stays in infra.
- `Priority` — `High | Normal | Low` (3 bands, not 0–100; adapters map: RMQ
  x-max-priority=2, NATS subject band).
- `SampleRequest` — id, url, digest, declared size, priority, report destination,
  correlation id, extensions hint, created_at.
- `ScanBatch` — the aggregate. Invariants: single priority, ≤ `files_per_batch`,
  unique sample ids. Pure; no I/O.
- `ScanVerdict` — typed enum replacing the C# bool soup:
  `Detected { detections: Vec<Detection> } | Clean | Skipped { reason: SkipReason }`
  where `SkipReason = PasswordProtected | Corrupted | Trusted | Oversized | ...`.
- `ScanReport` — sample id, correlation, verdict, `AvProfile` snapshot, `WorkerInfo`,
  timing, `attempt`, extras (archives/packers/raw log lines — debug only).
- `WorkerInfo` — hostname, os string, role (filled by infra at composition root).
- `AvProfile` — av name/version, bases version/time, components, license state.

Mapping DTO ⇄ model happens in `infra::bus::wire` only. Core models carry no
wire-format knowledge.

## Core: ports

```rust
#[async_trait]
pub trait ScannerPort: Send + Sync {
    fn id(&self) -> ScannerId;
    async fn is_installed(&self) -> Result<bool, ScannerError>;
    async fn profile(&self) -> Result<AvProfile, ScannerError>;
    async fn scan(&self, dir: &Path) -> Result<ScanOutput, ScannerError>; // timeout outside
    async fn update(&self) -> Result<UpdateOutcome, ScannerError>;
}

pub trait BusPort: Send + Sync {
    async fn consume_requests(&self, scanner: ScannerId) -> Result<RequestStream, BusError>;
    async fn publish_report(&self, report: &ScanReport, dest: &ReportDest) -> Result<(), BusError>;
}

// RequestStream yields Delivery { request: SampleRequest, handle: DeliveryHandle }
// DeliveryHandle: ack() | nak_requeue() | drop()   — retry COUNTING lives in core
#[async_trait]
pub trait SampleFetcherPort: Send + Sync {
    async fn fetch(&self, req: &SampleRequest, dest: &Path) -> Result<FetchedFile, FetchError>;
}

pub trait SchedulerPort { /* versa-bot shape: interval jobs, cancel handles */ }
// No ConfigPort: config is deployment-static (loaded once at startup) and
// flows into core as plain value structs (OrchestratorSettings, WorkerInfo).
// versa-bot needed a hot-reload port; versa-scan deliberately does not.
pub trait SelfUpdatePort { async fn check(&self) -> Result<Option<Update>, ...>; async fn apply(&self, &Update) -> ...; }
```

## Core: services (the extracted brains of the C# worker)

- **`BatchPlanner`** (pure) — the original `ProduceAvScanTaskLoop` as a state machine:
  `feed(request) -> Action::{Added, BatchClosed, Preempted, AddedToNewBatch}`.
  Higher priority preempts (park current batch), lower priority closes it, same
  priority fills it. Exhaustively unit-tested decision table.
- **`RetryPolicy`** (pure) — failure → disposition:
  - fetch `HashMismatch`/`TooLarge`/`NotFound` → terminal: error report + ack.
  - fetch `Io`/`Timeout`, bus transient → requeue, max 3 attempts, then error
    report + ack (never silent drop — fixes the C# double-reject drop).
  - scanner crash/timeout → per-sample error report + ack (scanner infrastructure
    failure → requeue batch + cooldown instead).
- **`Validation`** — scanned-file count vs batch size, per-file coverage; missing
  verdict → synthesized error verdict (kept from C#).
- **`WorkspaceManager`** — batch dirs under `workspace_root/<ts>-<batch_id>/`;
  guaranteed cleanup (RAII guard + explicit), manifest.json written on close
  (replaces the C# finalizer `taskinfo.txt` hack — fixes disk-fill bug).
- **`Orchestrator`** — wires it all: consume → plan → fetch (bounded parallel)
  → scan (deadline + process-tree kill) → validate → publish (confirm) → ack
  → cleanup. **Publish-then-ack** ordering (fixes the C# ack-before-publish
  message-loss bug); duplicates prevented/suppressed via broker dedupe keys and
  consumer-side `attempt` filtering.
- **`UpdateLoop`** — openbox role: scheduler-driven `ScannerPort::update` +
  `SelfUpdatePort::check`.

## Wire contract (v1)

JSON everywhere, `schema: 1` field. RFC 3339 UTC timestamps.

**`SampleRequestV1`** (published by vscli):
```json
{
  "schema": 1,
  "sample_id": "uuid",
  "url": "http://host:port/samples/<sha256>",
  "sha256": "<hex>",
  "size": 12345,
  "priority": "high | normal | low",
  "report_dest": "<queue name | nats subject>",
  "correlation_id": "uuid",
  "extensions": ["exe"],
  "created_at": "2026-10-10T00:00:00Z"
}
```

**`ScanReportV1`** (published by vsd):
```json
{
  "schema": 1,
  "sample_id": "uuid",
  "correlation_id": "uuid",
  "scanner": "clamd",
  "worker": { "hostname": "clamd.sandbox", "os": "Linux 6.x", "role": "sandbox" },
  "av": { "name": "...", "version": "...", "bases_version": "...", "bases_time": "...",
          "av_updated_at": "...", "components": {}, "license": { "type": "...", "valid": true, "expires_at": "..." } },
  "outcome": { "type": "detected | clean | skipped | error",
               "detections": [{ "name": "Win.Trojan.X", "link": null }],
               "skip_reason": "password_protected | corrupted | trusted | oversized",
               "error": "..." },
  "extras": { "archives": [], "packers": [], "raw": [] },
  "timing": { "started_at": "...", "finished_at": "...", "duration_ms": 0 },
  "attempt": 1
}
```

### RabbitMQ topology

- Request queue per scanner: `vs.scan.requests.<scanner>` — durable,
  `x-max-priority = 2`, prefetch from config. Work-queue semantics: manual ack.
- Reports: published to the queue named by `report_dest` via default exchange,
  persistent, **publisher confirms**. The requester (vscli) declares its reply
  queue before publishing requests (contract: publishing to an undeclared queue
  is a dropped message — requester owns declaration).
- Redelivery: `nak_requeue` at most once (`attempt` carried in report; terminal
  failure = error report + ack).

### NATS JetStream topology

- Stream `VS_SCAN_REQUESTS`, subject `vs.scan.requests.<scanner>`,
  `WorkQueuePolicy`, `AckExplicit`, duplicates window 2 min,
  `Nats-Msg-Id = <sample_id>` (publish dedupe).
Durable pull consumers `vs-<scanner>`, `MaxDeliver = 3`,
  `AckWait` from config. **Priority is a no-op on NATS** (kept simple per
  review): requests publish to the scanner's single subject regardless of
  priority; the RMQ adapter honors `x-max-priority`. The `BusPort` itself
  stays priority-blind — priority lives only in the request DTO.
- Reports: stream `VS_SCAN_REPORTS`, subjects `vs.scan.reports.<scanner>.<sample_id>`,
  `LimitsPolicy` + `max_age = 7d`, `Nats-Msg-Id = <sample_id>.<scanner>.<attempt>`
  (worker-side republish dedupe). `vscli --wait` uses an ephemeral ordered
  consumer filtered by its sample set; core NATS request-reply NOT used (one
  uniform JetStream path for both CLI and future collectors).

## vsd (worker daemon)

- Config/CLI selects: role, scanner id, bus backend + settings, workspace root,
  batching knobs, timeouts, fetch concurrency.
- Graceful shutdown via `CancellationToken`: stop consuming, finish in-flight
  batch, settle acks, cleanup, exit.
- Scanner selection is explicit at the composition root (`--scanner clamd`);
  optional `--detect` probes `is_installed()` across the registry (replaces C#
  reflection auto-discovery; no reflection in Rust).
- Windows specifics kept out of core: process tree-kill (`taskkill /T /F`),
  Defender paths, registry reads — all inside `infra::scanners::defender` and
  `infra::process`.

## vscli (CLI)

- **Own storage** (D4): content-addressed store, default
  `%LOCALAPPDATA%/vscli` / `~/.local/share/vscli` (overridable):
  `samples/<sha256[0:2]>/<sha256>` + sqlite index (submissions, reports).
- **Embedded server** (`axum`): `GET/HEAD /samples/<sha256>` (+ range requests),
  bind `--bind 0.0.0.0:8080`, advertised base `--advertise http://host:port`
  (NAT scenarios). Stays up for the duration of `submit --wait`, or runs
  standalone via `vscli serve`.
- Subcommands:
  - `vscli submit <files...> [--priority] [--scanner <id|all>]`
    `[-w|--wait] [--timeout <dur>]` — hash → store (dedupe) → serve → publish one
    request per (sample, scanner) → with `--wait`: collect reports, print
    per-scanner table, persist to index.
  - `vscli serve` — long-running artifact server + report listener.
  - `vscli reports <sample_id>` — list collected reports from the index.
  - `vscli status` — storage/bus stats.
- Bus config mirrors vsd (same TOML sections + CLI overrides); vscli is a driving
  adapter reusing the same `BusPort` adapters and wire DTOs from infra.

## Self-updater (D7)

- Manifest endpoint: `GET <update_url>/manifest.txt` → `<semver>;<sha256 of zip>`
  (same shape as the C# `version.txt;md5`, upgraded to sha256).
- Apply: download zip → verify hash → extract to staging dir next to the binary →
  swap. Windows: rename running exe to `.old`, move new into place (rename-swap
  works on a running exe), `.old` cleaned on next start. Linux: plain replace.
- Triggers: `vsd update check|apply` manual + periodic check in openbox role
  (`auto_apply` flag; default notify-only). Managed restart: exit with a code the
  service/scheduler treats as restart, or `--exec-self` child respawn.

## Testing strategy

- **Core**: pure unit tests — planner decision table, retry policy table,
  validation, batch invariants, DTO mapping round-trips (mapping tests in infra).
- **Infra**: in-memory bus for pipeline tests; scanner adapters tested against
  recorded log fixtures (clamd protocol mocked over a fake TCP stream; Defender
  output fixtures).
- **Integration** (docker-compose: rabbitmq, nats, clamd): bus adapter semantics
  (priority order, ack/nak, confirms, JetStream dedupe) — Linux CI only.
- **E2E**: `vscli submit --wait` ↔ `vsd` with `debug` scanner over both real
  buses (Linux CI) and in-memory bus (unit-speed, any OS). Windows CI: build +
  unit + fixture tests (broker containers stay on Linux runners).

## Milestones

- **M0 — Scaffold.** Workspace, CI (both OS matrix), pinned toolchain, lint
  config, `AGENTS.md` (architecture rulebook, versa-bot style), empty crates,
  example TOML, tracing setup, config loading. *Gate: CI green on trivial code.*
- **M1 — Core.** All models, ports, `BatchPlanner`, `RetryPolicy`, `Validation`,
  `WorkspaceManager`, `Orchestrator` against in-memory fakes. *Gate: core unit
  tests comprehensive; `cargo test -p versa-scan-core` is the spec.*
- **M2 — Bus adapters.** `wire.rs` DTOs + RabbitMQ + NATS adapters + in-memory.
  *Gate: integration tests over docker brokers pass (priority, ack semantics,
  dedupe, confirms).*
- **M3 — Worker.** vsd: clamd + defender + debug scanners, http fetcher,
  scan pipeline e2e, graceful shutdown, cleanup. *Gate: e2e submit→report over
  both buses with debug scanner; clamd IT on Linux.*
- **M4 — CLI.** vscli: CAS store, embedded server, submit/--wait/reports/status.
  *Gate: `vscli submit --wait` full round-trip vs vsd on both buses; dedupe and
  range requests tested.*
- **M5 — Ops.** Self-updater (manifest/swap, both OS), openbox role (update loop,
  `vsd install-task`), README, Dockerfile, release packaging.
  *Gate: updater swap tested on Windows + Linux; docs complete.*

## Known risks / open items

- NATS has no priority queues by decision: the NATS adapter ignores request
  priority (single subject, FIFO); RMQ provides real priority. No emulation
  complexity is bought.
- Windows CI has no broker containers → e2e coverage asymmetric by design.
- Commercial AV ports later will need per-AV VMs; adapter template (fixture-driven
  parser tests) established with clamd/defender now.
- Defender `MpCmdRun` output parsing varies by platform build — fixture matrix
  needed; the C# stub was never implemented, so this is new code, not a port.
