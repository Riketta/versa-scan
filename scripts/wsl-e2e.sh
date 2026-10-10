#!/usr/bin/env bash
# Full round-trip e2e inside WSL, over each real bus:
#   vsd (debug scanner) + vscli submit --wait -> report table -> ack.
#
# Same repo-copy mechanics as wsl-test.sh (syncs this checkout to
# ~/vs-scan, builds, runs RabbitMQ first, then NATS). A failing backend
# aborts with its logs printed.

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

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi
cargo build --workspace

WORK="$(mktemp -d)"
trap 'pkill -f "target/debug/vsd" 2>/dev/null || true; rm -rf "$WORK"' EXIT

run_backend() {
    local backend="$1" url="$2" port="$3"
    echo "=== e2e over $backend ==="

    cat > "$WORK/e2e-$backend.toml" <<EOF
[worker]
role = "sandbox"
scanner = "debug"
workspace_root = "$WORK/ws-$backend"

[bus]
backend = "$backend"

[bus.rabbitmq]
url = "amqp://versa:versa@localhost:5672/%2f"

[bus.nats]
url = "nats://localhost:4222"
EOF

    "$DST/target/debug/vsd" --config "$WORK/e2e-$backend.toml" \
        > "$WORK/vsd-$backend.log" 2>&1 &
    VSD_PID=$!
    sleep 2

    if ! kill -0 "$VSD_PID" 2>/dev/null; then
        echo "vsd died at startup; log:"
        cat "$WORK/vsd-$backend.log"
        return 1
    fi

    echo "clean-bytes-for-e2e" > "$WORK/sample.txt"
    "$DST/target/debug/vscli" --store "$WORK/cli-store" --config "$WORK/e2e-$backend.toml" \
        submit "$WORK/sample.txt" --scanner debug --wait --timeout 30 \
        --bind "127.0.0.1:$port" --advertise "http://127.0.0.1:$port" \
        > "$WORK/vscli-$backend.out" 2>&1

    if ! grep -q "clean" "$WORK/vscli-$backend.out"; then
        echo "no clean verdict for $backend; output:"
        cat "$WORK/vscli-$backend.out"
        echo "vsd log:"
        cat "$WORK/vsd-$backend.log"
        return 1
    fi
    cat "$WORK/vscli-$backend.out"

    kill "$VSD_PID" 2>/dev/null || true
    wait "$VSD_PID" 2>/dev/null || true
    echo "=== $backend OK ==="
}

run_backend rabbitmq amqp://versa:versa@localhost:5672/%2f 18081
run_backend nats nats://localhost:4222 18082
echo "e2e passed over both buses"
