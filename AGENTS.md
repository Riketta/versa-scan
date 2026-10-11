# AGENTS Instructions

This file is the map and the rulebook for working in this repo: architecture
invariants, conventions, and the development gate. It is deliberately NOT a
feature manual - `docs/DESIGN.md` documents the system design and
milestones, and rustdoc documents module contracts. Where this file and the
code disagree, the code wins; then fix the doc.

## Project overview

versa-scan is the Rust re-implementation of the VirusLocal Worker (C#): a
distributed sample-scanning system. One worker (`vsd`) runs per antivirus,
on its own VM; samples are dispatched over a message bus (RabbitMQ or NATS
JetStream); per-sample scan reports go back to the requester. `vscli` is
the operator-facing CLI (submits samples, embeds an artifact server,
collects reports) and replaces the old backend/frontend for now.

Hexagonal architecture (ports & adapters), NOT a micro-kernel: there is no
plugin cardinality here - the only deployment variables are which scanner
adapter and which bus adapter are wired, both chosen at the composition
root. Scanners and buses are classic driven adapters.

Platform strategy: Windows-first (the AV world) with first-class Linux
support (clamd/debug run anywhere; broker integration tests run on Linux
CI). Scanner adapters that need Windows (Defender, future commercial AVs)
live behind the same `ScannerPort` and use `#[cfg(windows)]` internally.

## Build & CI

Toolchain is pinned by `rust-toolchain.toml` (same compiler in CI and local
dev). The local gate IS the CI gate. Run exactly what CI runs, in this
order, after the LAST edit of a change:

1. `cargo fmt --all -- --check`
2. `cargo clippy --all-targets`
3. `cargo test`

Read the clippy run's exit status and `error:` lines, not the warning
count. Deny lints are declared in `[workspace.lints.clippy]`:
`unwrap_used`, `indexing_slicing`, `string_slice` are denied (test modules
carry local `#![allow(clippy::unwrap_used)]` /
`#![allow(clippy::indexing_slicing)]` where asserts need them). Pedantic
warnings are tolerated - do not chase them at the cost of clarity, but fix
them when touching the code anyway.

`--locked` applies once a lockfile exists and dependencies stabilize;
dependency changes ship with an updated lockfile.

## Hexagonal architecture rules

- `crates/versa-scan-core` is THE hexagon: domain models, ports (traits),
  pure services. It must never depend on infrastructure - no broker
  client, no HTTP client, no axum, no fs paths beyond `std::path` values
  passed in. The workspace split makes this compile-enforced.
- `crates/versa-scan-infra` holds every adapter, split by hexagon edge:
  - `inbound_adapters/` - DRIVING edge, they start the core's work
    (bus listeners feed `ScanPipelinePort`).
  - `outbound_adapters/` - DRIVEN edge, they answer the core's needs
    (bus publishers, scanners, HTTP fetcher, process-tree kill,
    self-update, scheduler).
  - `wire.rs` - the bus wire contract (schema-versioned DTOs + topology
    naming) shared by both bus edges.
  Plus `config.rs`, `observability.rs` at the root. Depends on core,
  never the reverse.
- `bins/vsd` and `bins/vscli` are composition roots: they parse args, load
  config, construct adapters, and wire them into core services. All
  business decisions live in core, never in the bins.
- Facade exceptions in core (same category as versa-bot's
  tracing-is-the-port rule): `tokio` (time/sync/rt), `tokio-util`
  (CancellationToken), `tracing`, `serde`/`serde_json` (workspace
  manifests), `time`, `thiserror`, `uuid`, `futures-util`, `async-trait`,
  `parking_lot` (orchestrator state mutexes). Adding anything else to core
  needs a deliberate decision.

### Port cardinality

- Driving port (`ScanPipelinePort`): implemented by the orchestrator;
  inbound bus listeners ingest deliveries and signal stream ends, never
  settling deliveries themselves (settlement is a core decision).
- Driven ports (`ScannerPort`, `RequestPublisherPort`,
  `ReportPublisherPort`, `SampleFetcherPort`, `SelfUpdatePort`): one
  active adapter per process, chosen and wired at the composition root,
  injected into core services. The bus publisher pair may be one adapter
  object implementing both publisher ports. (A `SchedulerPort` existed and
  was removed: the openbox update loop needs one `tokio::time::sleep`
  interval, not a scheduling abstraction.)
- There is deliberately NO plugin system and no plugin-to-plugin bus.

### ACL / models

- Wire DTOs (`SampleRequestV1`, `ScanReportV1`) live in `infra::wire`
  only. Core models (`SampleRequest`, `ScanReport`, `ScanOutcome`, ...)
  carry no wire-format knowledge; mapping happens at the boundary. The
  wire schema is versioned (`schema: 1`); topology naming
  (`vs.scan.requests.<scanner>`, `vs.scan.reports.>`) lives there too.
- `ReportDest` and `ScannerId` are opaque strings to the core: the RMQ
  adapter reads a queue name, the NATS adapter a subject. Priority rides
  in the request DTO; RMQ enforces it with `x-max-priority`, NATS ignores
  it (design decision - docs/DESIGN.md).

### Pipeline invariants (core services)

- `BatchPlanner` is pure: batches hold one priority, at most
  `files_per_batch` files, unique sample ids. Higher priority preempts
  (parks) the open batch; lower priority closes it.
- Nothing is silently dropped: every delivery ends in exactly one of
  `ack` (report confirmed published), `nak_requeue` (bounded by
  `RetryPolicy`), or `discard` (terminal - an error report went out
  first, whenever publishing was possible).
- Publish-then-ack ordering. The C# system's ack-before-publish loss
  window is a bug class, not a memory.
- Batch workspaces are RAII: created with a `manifest.json`, removed on
  drop, swept at startup. No finalizer hacks, no disk fill.
- Fetchers write samples atomically (temp name -> final name only after
  hash verification) so the scanner never sees half-files.

## Config

TOML file (`versa-scan.toml`, see `versa-scan.example.toml`) plus
`VERSA_SCAN_`-prefixed env overrides. Loaded once at startup - no hot
reload by design (worker connections are deployment-static).

## Testing policy

- Core tests are the spec: `cargo test -p versa-scan-core` must fully
  describe the planner decision table, retry policy, validation, workspace
  lifecycle, and orchestrator settlement behavior (fakes live in the test
  modules).
- Scanner adapters are tested against recorded log/protocol fixtures.
- Bus adapters get integration tests against real brokers via
  `docker-compose.yaml` (rabbitmq, nats, clamd): env-gated by
  `VS_SCAN_TEST_RABBITMQ` / `VS_SCAN_TEST_NATS` - set on Linux CI,
  skipped elsewhere.
- E2E: `vscli submit --wait` <-> `vsd` with the `debug` scanner over both
  real buses.

## Documentation maintenance

`README.md` is user-facing (features, config, setup) and must stay in sync
with reality once it exists (M5). `docs/DESIGN.md` is the blueprint and
decision log; update it when a decision changes, not for every commit.
