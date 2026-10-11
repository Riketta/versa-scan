# versa-scan — System Design

A distributed sample-scanning system: one worker per scanner (VM per
scanner), samples dispatched over a message bus, per-sample scan reports
published back. `vscli` submits samples, serves them over an embedded
artifact server, and collects reports.

`README.md` is the user-facing manual, `AGENTS.md` the contributor
rulebook, this document the design reference. Where docs and code
disagree, fix the doc.

## Design decisions

| # | Topic | Decision |
|---|-------|----------|
| D1 | Architecture | Hexagonal (ports & adapters), **no** micro-kernel (no plugin cardinality exists here). Core has zero infra deps, enforced by the workspace crate split. |
| D2 | Bus | Work-queue bus behind split ports: driving `ScanPipelinePort` (listener → pipeline ingest) + driven `RequestPublisherPort`/`ReportPublisherPort`. Adapters: RabbitMQ (`lapin`), NATS JetStream (`async-nats`), in-memory. |
| D3 | Scanners | Open & generic set: `clamd` (TCP), `yara-x` (embedded engine), `hash-blocklist` (sha256 feeds), `defender` (MpCmdRun), `debug` (deterministic, for tests). Commercial AVs are out of scope; new sources arrive as `ScannerPort` adapters. |
| D4 | Artifact store | `vscli` embeds its own content-addressed storage + HTTP server (address fully configurable). |
| D5 | Wire contract | Own endpoints/schemas, versioned (`schema: 1`), designed fresh (see below). |
| D6 | Layout | Cargo workspace: `crates/versa-scan-core`, `crates/versa-scan-infra`, `bins/vsd` (worker daemon), `bins/vscli` (CLI). |
| D7 | Self-updater | Manifest check, hash-verified staged swap, `vsd update-check`/`update-apply` + periodic check in the openbox role. |
| D8 | NATS mode | JetStream: workqueue stream for requests, limits-retention stream for reports, durable pull consumers, explicit ack, `Nats-Msg-Id` dedupe. |
| D9 | Platforms | Windows-first (AV world) with first-class Linux support (clamd/debug CI, deployments). Cross-platform from day one. |
| D10 | Gates | Pinned toolchain, 2024 edition, `cargo fmt --all -- --check` → `cargo clippy --all-targets --locked` → `cargo test --locked`; `[lints.clippy]` deny `unwrap_used`, `indexing_slicing`, `string_slice`. |
| D11 | Scanner details | `yara-x`: rules dir/file, stat-fingerprint hot-reload, engine-side `set_timeout` bounds pathological rules. `hash-blocklist`: comment/label feed format, stat-skip reload, forced reload in `update()`. `clamd` stays TCP-only (INSTREAM avoids file-permission issues, works remotely), streamed chunks, `concurrent_scans` parallel INSTREAM, per-future name attribution, size-limit ERROR → actionable per-file message. Bad YARA rules are `ScanFailed` (terminal, error reports), never `NotInstalled` (which would requeue forever). |
| D12 | Delivery & security hardening | `SampleId` charset `[A-Za-z0-9._-]` at the wire boundary (no separators, no dot-only values - kills path traversal and NATS subject-token breaks); `ReportDest` validated the same way; sample URLs are `<advertise>/samples/<sha256>` (+ `?token=` when `[artifact].token` is set, 404-not-401, constant-time compare); `[worker].fetch_allowed_hosts` SSRF allowlist (empty = allow all). RMQ requeues are **republish-with-`x-vs-attempt`-header + confirm-then-ack** (the redelivered flag cannot count - the header makes the retry bound enforceable). Scanner-unavailable paths go through the retry policy with their own `scanner_max_attempts` cap (default 10) and terminal error reports. NATS twins `nak(delay)` instead of terminate; `ack_wait` must exceed `scan_timeout + fetch_timeout` (validated at boot). POSIX self-update renames over the running exe (ETXTBSY); auto-apply exits with code 7 (systemd `Restart=on-failure`) and triggers the Windows scheduled task. Defender fails closed on exit-2-with-no-parsed-findings. No scheduler port: one `tokio::time::sleep` interval needs no abstraction. |

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
- **openbox** — periodic scanner database update, self-update check, optional
  autostart registration (`vsd install-task`, explicit - no magic registration
  on boot).

## Workspace layout

```
versa-scan/
├── Cargo.toml                    # workspace, shared [workspace.lints]
├── crates/
│   ├── versa-scan-core/          # THE hexagon. Deps: std + small facade crates only.
│   │   └── src/
│   │       ├── models/           # sample, batch, verdict, report, av profile,
│   │       │                     #   priority, role, ids, worker info, digest
│   │       ├── ports/            # driving: scan_pipeline; driven: scanner,
│   │       │                     #   request/report publishers, fetch, self_update
│   │       └── services/         # planner, orchestrator, workspace, retry,
│   │                             #   validation
│   └── versa-scan-infra/         # Adapters. Depends on core. All blocking work
│       └── src/                  #   through tokio; process-spawn via tokio::process.
│           ├── inbound_adapters/ # DRIVING edge: bus listeners feed ScanPipelinePort;
│           │   ├── bus/          #   rabbitmq.rs, nats.rs, in_memory.rs
│           │   └── reports/      #   report waiters (rabbitmq.rs, nats.rs)
│           ├── outbound_adapters/ # DRIVEN edge: what the core calls out to
│           │   ├── bus/          #   rabbitmq.rs, nats.rs, in_memory.rs (publishers)
│           │   ├── scanners/     #   clamd.rs, yara_x.rs, hash_blocklist.rs,
│           │   │                 #   defender.rs, debug.rs (+ proc.rs helpers)
│           │   ├── fetch/        #   http.rs (reqwest streaming + hash verify)
│           │   └── self_update/  #   manifest.rs, swap.rs
│           ├── wire.rs           # schema-versioned DTOs + topology naming (shared)
│           ├── config.rs         # TOML + env, loaded once (no hot reload by design)
│           └── observability.rs  # tracing setup (+ optional syslog)
├── bins/
│   ├── vsd/                      # worker daemon (composition root #1)
│   └── vscli/                    # CLI (composition root #2)
│       └── src/                  # main.rs, store.rs (CAS), server.rs (axum), ...
├── .github/workflows/ci.yml      # fmt → clippy → test; Linux + Windows matrix
├── docker-compose.yaml           # rabbitmq, nats, clamd for local dev/IT
└── versa-scan.example.toml
```

Dependency rule (compile-enforced): `infra → core` only; `bins → core + infra`.
Core never names lapin/async-nats/reqwest/axum; its allowed facades are
`tokio` (time/sync/rt), `tokio-util` (CancellationToken), `tracing`,
`serde`/`serde_json`, `time`, `thiserror`, `uuid`, `futures-util`,
`async-trait`, `parking_lot`. Anything else needs a deliberate decision.

## Core: models (internal, ACL'd)

- `SampleId`, `CorrelationId`, `ScannerId` — newtypes.
- `Sha256Digest` — hex newtype, parse/validate in core; **computation** stays in infra.
- `Priority` — `High | Normal | Low` (3 bands; adapters map: RMQ
  x-max-priority=2, NATS ignores).
- `SampleRequest` — id, url, digest, declared size, priority, report destination,
  correlation id, extensions hint, created_at.
- `ScanBatch` — the aggregate. Invariants: single priority, ≤ `files_per_batch`,
  unique sample ids. Pure; no I/O.
- `ScanVerdict` — typed enum:
  `Detected { detections: Vec<Detection> } | Clean | Skipped { reason: SkipReason }`
  where `SkipReason = PasswordProtected | Corrupted | Trusted | Oversized | ...`.
- `ScanReport` — sample id, correlation, verdict, `AvProfile` snapshot, `WorkerInfo`,
  timing, `attempt`, extras (archives/packers/raw log lines — debug only).
- `WorkerInfo` — hostname, os string, role (filled by infra at composition root).
- `AvProfile` — av name/version, bases version/time, components, license state.

Mapping DTO ⇄ model happens in `infra::wire` only. Core models carry no
wire-format knowledge.

## Core: ports

Direction split (hexagonal):

**Driving (inbound) - adapters call the core:**

```rust
// ports/driving/scan_pipeline.rs
pub trait ScanPipelinePort: Send + Sync + 'static {
    /// Listener feeds one delivery; settlement happens later via the
    /// delivery handle (publish-then-ack is a core invariant).
    fn ingest(self: Arc<Self>, delivery: Delivery);
    /// The inbound stream ended (broker disconnect); pipeline flushes and
    /// requeues unsettled deliveries.
    fn stream_ended(&self);
}
// Delivery { request, attempt, handle: Arc<dyn DeliveryHandle> }
// DeliveryHandle: ack() | nak_requeue() | discard()
```

**Driven (outbound) - the core calls adapters:**

```rust
// ports/driven/scanner.rs
#[async_trait]
pub trait ScannerPort: Send + Sync {
    fn id(&self) -> ScannerId;
    async fn is_installed(&self) -> Result<bool, ScannerError>;
    async fn profile(&self) -> Result<AvProfile, ScannerError>;
    async fn scan(&self, dir: &Path) -> Result<ScanOutput, ScannerError>; // timeout outside
    async fn update(&self) -> Result<UpdateOutcome, ScannerError>;
}

// ports/driven/request_publisher.rs / report_publisher.rs
#[async_trait]
pub trait RequestPublisherPort: Send + Sync {
    async fn publish_request(&self, scanner: ScannerId, request: &SampleRequest) -> Result<(), PublishError>;
}
#[async_trait]
pub trait ReportPublisherPort: Send + Sync {
    async fn publish_report(&self, report: &ScanReport, dest: &ReportDest) -> Result<(), PublishError>;
}

// ports/driven/fetch.rs
#[async_trait]
pub trait SampleFetcherPort: Send + Sync {
    async fn fetch(&self, request: &SampleRequest, dest: &Path) -> Result<FetchedFile, FetchError>;
}

// ports/driven/self_update.rs
pub trait SelfUpdatePort { async fn check(...) -> Option<Update>; async fn apply(...); }
// No ConfigPort: config is deployment-static (loaded once at startup) and
// flows into core as plain value structs (OrchestratorSettings, WorkerInfo).
// No SchedulerPort: the openbox update loop needs one sleep interval, not a
// scheduling abstraction.
```

## Core: services (the pipeline brain)

- **`BatchPlanner`** (pure) — batching as a state machine:
  `feed(request) -> Action::{Added, BatchClosed, Preempted, AddedToNewBatch}`.
  Higher priority preempts (park current batch), lower priority closes it, same
  priority fills it. Exhaustively unit-tested decision table. A flush grace
  period lets an under-filled batch wait for more work instead of producing
  1-file scans the instant the queue drains.
- **`RetryPolicy`** (pure) — failure → disposition:
  - fetch `HashMismatch`/`TooLarge`/`NotFound` → terminal: error report + ack.
  - fetch `Io`/`Timeout`, bus transient → requeue, max 3 attempts, then error
    report + ack (never a silent drop).
  - scanner unavailable → its own (larger) cap, `scanner_max_attempts`
    (default 10), then error reports; an AV daemon restarting is an
    operational blip worth tolerating longer than a broken fetch.
- **`Validation`** — scanned-file count vs batch size, per-file coverage; missing
  verdict → synthesized error verdict, so the requester always gets exactly one
  report per sample.
- **`WorkspaceManager`** — batch dirs under `workspace_root/<batch_id>/`;
  guaranteed cleanup (RAII guard + explicit), `manifest.json` written when the
  workspace is created; leftovers swept at startup.
- **`Orchestrator`** — wires it all: consume → plan → fetch (bounded parallel)
  → scan (deadline) → validate → publish (confirm) → ack → cleanup.
  **Publish-then-ack** ordering; duplicates suppressed via broker dedupe keys
  and consumer-side `attempt` filtering.
- The openbox update loop (periodic `ScannerPort::update` + `SelfUpdatePort::check`)
  lives in `bins/vsd` - it is deployment logic, not core.

## Wire contract (v1)

JSON everywhere, `schema: 1` field. RFC 3339 UTC timestamps. DTOs live in
`infra::wire`; topology naming (`request_queue_name`, `REPORTS_SUBJECT_ROOT`)
lives there too.

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
  is a dropped message - requester owns declaration).
- Redelivery: `nak_requeue` is implemented as a **republish with the original
  payload plus an `x-vs-attempt` header**, and the worker confirms the publish
  **before** acking the original. A plain nack cannot carry the attempt count,
  and the redelivered flag cannot distinguish first from later redeliveries -
  the header is what makes the retry bound enforceable. Fetch/publish failures
  cap at 3 attempts; terminal failure = error report + ack.
- Listener + publisher each own a connection/channel; both sides declare the
  request queue identically.

### NATS JetStream topology

- Stream `VS_SCAN_REQUESTS`, subject `vs.scan.requests.<scanner>`,
  `WorkQueuePolicy`, `AckExplicit`, duplicates window 2 min,
  `Nats-Msg-Id = <sample_id>.<scanner>` (publish dedupe; the scanner suffix is
  what lets `--scanner all` fan one sample out to every scanner - the bare id
  collapsed the fan-out).
- Durable pull consumer `vs-<scanner>` (filter `vs.scan.requests.<scanner>`),
  `MaxDeliver` from config, `AckWait` from config. **Priority is a no-op on
  NATS** (by decision): requests publish to the scanner's single subject
  regardless of priority; the RMQ adapter honors `x-max-priority`. Redelivery
  is `nak(delay)` - never terminate; workers publish error reports on the
  final attempt. `AckWait` must exceed `scan_timeout + fetch_timeout`;
  validated at boot.
- Reports: stream `VS_SCAN_REPORTS`, subjects `vs.scan.reports.<session>.<sample_id>`,
  `LimitsPolicy` + `max_age = 7d`, `Nats-Msg-Id = <sample_id>.<scanner>.<attempt>`
  (worker-side republish dedupe). `vscli --wait` consumes via an ephemeral pull
  consumer on its session wildcard (`DeliverPolicy::New`, inactive-threshold
  cleanup) - the `>` tail of the session wildcard matches multi-token
  sample ids (ids are file names, dots allowed). Report publishes are ordinary
  JetStream publishes on the report subject; the session waiter consumes from
  the stream - one uniform path for the CLI and future collectors.

## vsd (worker daemon)

- Config/CLI selects: role, scanner id, bus backend + settings, workspace root,
  batching knobs, timeouts, fetch concurrency.
- Graceful shutdown via `CancellationToken`: stop consuming, finish in-flight
  batch, settle acks, cleanup, exit.
- Scanner selection is explicit at the composition root (`--scanner clamd`);
  optional `--detect` probes `is_installed()` across the registry.
- Subcommands: `update-check`, `update-apply`, `install-task`.
- Platform specifics stay out of core: Defender paths and PowerShell status
  inside `infra::scanners::defender`; the Windows/POSIX swap dance inside
  `infra::self_update`.

## vscli (CLI)

- **Own storage** (D4): content-addressed store, default
  `%LOCALAPPDATA%/vscli` / `~/.local/share/vscli` (overridable `--store`):
  `samples/<sha256[0:2]>/<sha256>` + `reports/reports.jsonl` append-only log
  (a sqlite index was considered and dropped - one log is enough).
- **Embedded server** (`axum`): `GET/HEAD /samples/<sha256>` (+ range requests,
  optional `?token=` auth), bind `--bind 0.0.0.0:8080`, advertised base
  `--advertise http://host:port` (NAT scenarios). Stays up for the duration of
  `submit --wait`, or runs standalone via `vscli serve`.
- Subcommands:
  - `vscli submit <files...> [--priority] [--scanner <id|all>]`
    `[-w|--wait] [--timeout <secs>]` — hash → store (dedupe) → serve → publish
    one request per (sample, scanner) → with `--wait`: collect reports, print
    per-scanner table, persist to the log.
  - `vscli serve` — long-running artifact server.
  - `vscli reports <sample_id>` — print collected reports for a sample.
  - `vscli status` — storage/bus stats.
- Bus config mirrors vsd (same TOML sections + CLI overrides); vscli is a
  driving adapter reusing the same bus adapters and wire DTOs from infra.

## Self-updater (D7)

- Manifest endpoint: `GET <update_url>/manifest.txt` → `<semver>;<sha256 of zip>`.
- Apply: download zip → verify hash → extract to staging dir next to the binary →
  swap. Windows: rename running exe to `.old`, move new into place (rename-swap
  works on a running exe), `.old` cleaned on next start. Linux: plain replace
  over the running exe (ETXTBSY-safe rename).
- Triggers: `vsd update-check` / `vsd update-apply` manual + periodic check in
  the openbox role (`auto_apply` flag; default notify-only). Managed restart:
  auto-apply exits with code 7 - systemd `Restart=on-failure` picks it up, and
  the Windows scheduled task is triggered the same way.
- Transport is plain http(s) with sha256 verification; signature enforcement
  (signed manifests) is a known extension point.

## Testing strategy

- **Core**: pure unit tests — planner decision table, retry policy table,
  validation, batch invariants, DTO mapping round-trips (mapping tests in infra).
- **Infra**: in-memory bus for pipeline tests; scanner adapters tested against
  recorded log fixtures (clamd protocol mocked over a fake TCP stream; Defender
  output fixtures).
- **Integration** (docker-compose: rabbitmq, nats, clamd; env-gated by
  `VS_SCAN_TEST_RABBITMQ` / `VS_SCAN_TEST_NATS`): bus adapter semantics
  (priority order, ack/nak, confirms, JetStream dedupe) - Linux CI and WSL.
- **E2E**: `vscli submit --wait` ↔ `vsd` with the `debug` scanner over both
  real buses (scripts/wsl-e2e.sh) and over the in-memory bus (unit-speed,
  any OS). Windows CI: build + lint + unit/fixture tests (broker containers
  stay on Linux runners).

## Known limitations & extension points

- NATS has no priority queues by decision: the NATS adapter ignores request
  priority (single subject, FIFO); RMQ provides real priority.
- Priority starvation: a continuously preempting high-priority stream can park
  a low-priority batch indefinitely (park-age is not capped).
- Defender `MpCmdRun` output parsing varies by platform build - the parser is
  fixture-based and tolerant; refine fixtures against real VM captures.
- Self-update verifies sha256 but does not enforce signatures or https.
- vscli reads whole sample files into memory when hashing/storing (CLI-scale
  fine; workers stream downloads).
- New scanners arrive as `ScannerPort` adapters (see D3); the adapter template
  (fixture-driven parser tests) is established by the existing implementations.
