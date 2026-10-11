#!/usr/bin/env bash
# Runs the full test suite inside WSL against the docker brokers.
#
# Why: Windows<->WSL port forwarding for published container ports is
# unreliable (mirrored networking + distro idle-stops), so the suite runs
# INSIDE WSL against localhost. The script keeps a native-FS copy of the
# repo at ~/vs-scan (fast builds; /mnt/* is 9P-slow) in sync with this
# checkout, brings up rabbitmq + nats, and runs `cargo test --workspace`.
#
# Requires: WSL with docker + a rustup toolchain (1.98) for the current
# user. First run compiles the workspace (a few minutes).
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST="$HOME/vs-scan"

mkdir -p "$DST"
tar --exclude=./target --exclude=./.git -C "$SRC" -cf - . | tar -C "$DST" -xf -

cd "$DST"
docker compose up -d rabbitmq nats

wait_port() {
    local port="$1" name="$2"
    for _ in $(seq 1 30); do
        if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
            exec 3>&- 3<&-
            echo "$name ready on $port"
            return 0
        fi
        sleep 1
    done
    echo "$name never became ready on $port" >&2
    return 1
}
wait_port 5672 rabbitmq
wait_port 4222 nats

export VS_SCAN_TEST_RABBITMQ=amqp://versa:versa@localhost:5672/%2f
export VS_SCAN_TEST_NATS=nats://localhost:4222

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi
exec cargo test --workspace
