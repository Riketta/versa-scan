# versa-scan

A distributed sample-scanning system. One worker (`vsd`) runs per scanner,
typically on its own VM; samples are dispatched over a message bus
(RabbitMQ or NATS JetStream); per-sample scan reports go back to the
requester. `vscli` is the operator-facing CLI: it stores samples in a
local content-addressed store, serves them to workers over an embedded
HTTP artifact server, publishes scan requests, and (with `--wait`)
collects and prints the reports.

Hexagonal architecture (ports & adapters): `versa-scan-core` holds the
domain (models, ports, the scan pipeline's brain) and never depends on
infrastructure; `versa-scan-infra` holds every adapter, split by hexagon
edge (`inbound_adapters` drive the core - bus listeners; `outbound_adapters`
answer the core - scanners, publishers, fetcher, self-update). There is no
plugin system: the only deployment variables are which scanner adapter and
which bus adapter are wired, both chosen at the composition roots.

```
                       ┌────────────┐
   vscli submit ──────▶│  RabbitMQ  │──────┐
   (embedded artifact  │ or NATS JS │      ▼
    server, content-   └────────────┘   vsd worker (VM per scanner)
    addressed store)        ▲              consume → batch → fetch → scan
        │    ▲              │              → validate → report → ack
        │    └── reports ───┴────────────  publish ScanReportV1
        └── vscli submit --wait prints a per-scanner result table
```

## Features

- **Scanners**: ClamAV (clamd TCP), YARA-X (embedded engine), sha256
  hash blocklists, Windows Defender, and a deterministic `debug` scanner
  for demos and tests. New sources arrive as `ScannerPort` adapters.
- **Two real buses**: RabbitMQ (native priority queues) and NATS
  JetStream (dedupe, work-queue semantics); an in-memory pair backs the
  unit-speed tests.
- **Delivery guarantees**: publish-then-ack ordering, bounded retries for
  every failure class, explicit error reports on terminal failure -
  nothing is silently dropped and nothing loops forever.
- **Operator CLI**: content-addressed sample store, embedded artifact
  server (token auth, range requests), fan-out to every scanner,
  report table with `--wait`.
- **Ops**: hash-verified self-updater, autostart installation
  (Task Scheduler / systemd), openbox role for scanner DB + worker
  updates, single TOML config with env overrides.
- **Cross-platform**: Windows-first (the AV world) with first-class
  Linux support; broker integration tests run on Linux CI.

## Layout

```
crates/
├── versa-scan-core/    # hexagon: models, ports (driving/driven), services
└── versa-scan-infra/   # adapters:
    ├── inbound_adapters/   # driving: bus listeners, report waiters
    ├── outbound_adapters/  # driven: bus publishers, scanners, fetch,
    │                       #   self-update
    └── wire.rs             # bus DTOs (schema 1) + topology naming
bins/
├── vsd/                # worker daemon (sandbox + openbox roles)
└── vscli/              # CLI: submit / serve / reports / status
```

Dependency rule (compile-enforced): `infra → core` only; bins wire both.

## Quick start

Prerequisites: Rust (toolchain pinned in `rust-toolchain.toml`), Docker
for the brokers.

```bash
# 1. Brokers (RabbitMQ + NATS + clamd) for local development:
docker compose up -d

# 2. A worker (debug scanner needs nothing installed):
cp versa-scan.example.toml versa-scan.toml
#    edit: worker.scanner, [bus] backend + url
vsd

# 3. Submit samples and wait for reports (another terminal):
vscli submit --scanner debug --wait eicar.txt
```

The `debug` scanner produces deterministic verdicts from file names
(`eicar` → detected, `locked` → password-protected skip, ...), so this
round trip works with no antivirus installed.

## Build

Toolchain is pinned in `rust-toolchain.toml`. The local gate IS the CI
gate, in this order:

```
cargo fmt --all -- --check
cargo clippy --all-targets
cargo test
```

Broker integration tests are skipped unless the brokers are reachable:

```
docker compose up -d rabbitmq nats clamd
VS_SCAN_TEST_RABBITMQ=amqp://versa:versa@localhost:5672/%2f \
VS_SCAN_TEST_NATS=nats://localhost:4222 \
cargo test
```

CI (`.github/workflows/ci.yml`) runs fmt/clippy/test on Ubuntu + Windows,
with the broker services on Ubuntu; release binaries are uploaded as
artifacts. A `Dockerfile` builds both binaries for Linux.

## Running a worker

```bash
cp versa-scan.example.toml versa-scan.toml
# edit: worker.role, worker.scanner, [bus] backend + url, [clamd] address

vsd                # role auto-detected (hostname: *.sandbox.* / *.openbox.*)
vsd --detect       # probe every known scanner and exit
vsd --config /path/versa-scan.toml
```

- **sandbox** role: consumes scan requests for the configured scanner,
  batches them (same priority, N files, higher priority preempts), fetches
  samples from the request URLs, scans, validates, publishes reports, and
  only then acks (publish-then-ack; nothing is silently dropped - failures
  either requeue bounded times or produce an error report).
- **openbox** role: periodic scanner database update + worker self-update
  (manifest check, hash-verified swap, restart-by-exit on auto_apply).

Worker autostart: `vsd install-task` (Windows Task Scheduler ONSTART/SYSTEM,
or a systemd unit on Linux).

Worker self-update: set `[self_update] enabled = true`, `url` to a server
serving `manifest.txt` (`<semver>;<sha256-of-zip>`) and `<semver>.zip`.
`vsd update-check` / `vsd update-apply` drive it manually.

## Submitting samples

```bash
# Serve the store persistently (optional; submit also runs one per session):
vscli serve --bind 0.0.0.0:8080

# Submit (hashes, stores, serves, publishes to the scanners, waits):
vscli submit suspicious1.exe suspicious2.dll --scanner all --wait
vscli submit --scanner clamd --priority high --timeout 300 sample.bin \
    --bind 0.0.0.0:8080 --advertise http://10.0.0.5:8080

# Inspect:
vscli status
vscli reports <sample-id>
```

- `--bind` is where the embedded artifact server listens; `--advertise` is
  the URL workers must reach it on (use the host's real IP/hostname behind
  NAT).
- `--scanner all` fans out to every known scanner (`clamd`, `yara-x`,
  `hash-blocklist`, `defender`, `debug`); a slug targets one.
- `--wait` prints a table (`sample / scanner / outcome`) and exits non-zero
  if any report is missing at the timeout. Reports are persisted to the
  store's `reports/reports.jsonl` regardless.

## Scanners

| Slug | Platform | Mechanism |
|----------------|--------------|------------------------------------------------------------------------|
| `clamd` | any | clamd TCP protocol (PING/VERSION/INSTREAM), parallel streams; `freshclam` for updates |
| `yara-x` | any | embedded YARA-X engine over your rules (`[yara_x] rules_path`); rules hot-reload on change |
| `hash-blocklist` | any | sha256 feed matcher (`[hash_blocklist] feeds`); feeds hot-reload on change |
| `defender` | Windows | `MpCmdRun.exe -Scan` + PowerShell status; `MpCmdRun -SignatureUpdate` for updates |
| `debug` | any | deterministic fake for tests |

Adding a scanner means implementing the `ScannerPort` trait
(`crates/versa-scan-core/src/ports/driven/scanner.rs`) and registering the
adapter at the composition root - see `docs/DESIGN.md` for the contract and
`crates/versa-scan-infra/src/outbound_adapters/scanners/` for existing
implementations. For hash-blocklist feeds, abuse.ch MalwareBazaar sha256
exports work as-is. The `yara-x` example rule set lives in `examples/rules/`.

## Security model

The bus is treated as untrusted input. Hardening in place:

- **Sample ids are file names** and are validated at the wire boundary to
  `[A-Za-z0-9._-]` (no path separators, no dot-only values) - a hostile
  publisher cannot escape the batch workspace. `report_dest` is validated
  the same way.
- **Artifact server auth**: set `[artifact] token = "..."` in the vscli
  config; every sample URL the CLI publishes gets `?token=...` appended and
  the server rejects requests without it (404, constant-time compare).
  Empty token = open server (fine on loopback; a loud warning is logged
  when binding non-loopback without one).
- **Fetch allowlist**: `[worker] fetch_allowed_hosts = ["art.local:8080"]`
  restricts what URLs workers will GET. Empty = allow all (default).
- **Bounded retries everywhere**: fetch/publish failures cap at 3 attempts;
  scanner-unavailable caps at `worker.scanner_max_attempts` (default 10);
  after the cap, samples get error reports - nothing loops forever and
  nothing vanishes without a report.
- **Defender fails closed**: exit 2 with unparseable findings is a scan
  error, never a clean verdict.

## Wire contract

JSON, versioned (`schema: 1`), defined in `crates/versa-scan-infra/src/wire.rs`:

- Requests (`SampleRequestV1`) carry: sample id (uuid), http(s) URL,
  sha256, size, priority (`low|normal|high`), report destination,
  correlation id. Topology: `vs.scan.requests.<scanner>`.
- Reports (`ScanReportV1`) carry: typed outcome (`detected`/`clean`/
  `skipped`/`error`), scanner + AV profile snapshot, worker identity,
  timing, `attempt` (for dedupe). Topology: `vs.scan.reports.>`; requesters
  derive per-session destinations (`vs.scan.reports.<session>.<sample>` on
  NATS, one session queue on RabbitMQ).

Priority is honored natively by RabbitMQ (`x-max-priority`); NATS ignores
it by design. Settlement semantics (ack/nak-requeue/discard,
publish-then-ack) are documented in `docs/DESIGN.md` alongside the full
system design.

## Configuration

Single TOML (`versa-scan.toml`, see `versa-scan.example.toml`) +
`VERSA_SCAN_<SECTION>__<KEY>` env overrides (double underscore separates
nesting levels, e.g. `VERSA_SCAN_WORKER__SCANNER=clamd`). Loaded once at
startup - no hot reload by design (worker connections are
deployment-static).

## Development

- `AGENTS.md` is the contributor rulebook (architecture invariants,
  conventions, the development gate).
- Core behavior is spec'd by tests: the batch planner decision table,
  retry policy, validation, workspace lifecycle, and orchestrator
  settlement behavior (publish-then-ack, retry bounds, duplicate guards).
- Scanner adapters are fixture-tested; bus adapters get real-broker
  integration tests on Linux CI; the worker and CLI flows have in-process
  end-to-end tests over the in-memory bus and a local artifact server.
