#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

PODMAN_BIN="${PODMAN_BIN:-/opt/podman/bin/podman}"
IMAGE="${IMAGE:-ardur-ebpf-dev:fedora43}"
OUT="${OUT:-$ROOT/reports/phase2-ebpf-smoke-output-rootful.txt}"
RUN_ROOTFUL="${RUN_ROOTFUL:-1}"

usage() {
  cat <<'EOF'
Usage: scripts/run-phase2-ebpf-smoke.sh

Runs the gated Phase 2 Linux eBPF process lifecycle/session smoke tests and writes the
rootful smoke output to reports/phase2-ebpf-smoke-output-rootful.txt.

Requirements:
  - Linux kernel with /sys/kernel/btf/vmlinux.
  - Podman with a rootful privileged run path.
  - tracefs/debugfs mounted and bind-mounted into the smoke container.
  - local image ardur-ebpf-dev:fedora43, or tooling/phase2-ebpf/Containerfile
    so the script can build it locally.

On macOS this script runs the rootful container inside podman-machine-default
through `podman machine ssh`. It does not push, publish, expose services, or
install a daemon.

Environment:
  PODMAN_BIN=/path/to/podman     macOS podman binary (default /opt/podman/bin/podman)
  IMAGE=tag                     dev image tag (default ardur-ebpf-dev:fedora43)
  OUT=path                      output file path
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ "$RUN_ROOTFUL" != "1" ]; then
  echo "ERROR: this smoke intentionally requires RUN_ROOTFUL=1 because eBPF load/attach needs privileges." >&2
  exit 2
fi

shell_quote() {
  python3 -c 'import shlex, sys; print(shlex.quote(sys.argv[1]))' "$1"
}

Q_ROOT="$(shell_quote "$ROOT")"
Q_IMAGE="$(shell_quote "$IMAGE")"
Q_OUT="$(shell_quote "$OUT")"
mkdir -p "$(dirname "$OUT")"

REMOTE_CMD="set -euo pipefail
cd $Q_ROOT
if ! sudo podman image exists $Q_IMAGE; then
  sudo podman build -t $Q_IMAGE -f tooling/phase2-ebpf/Containerfile .
fi
mkdir -p \$(dirname $Q_OUT)
sudo podman run --rm --privileged --pid=host --ulimit memlock=-1:-1 \\
  -v /sys/kernel/tracing:/sys/kernel/tracing:rw \\
  -v /sys/kernel/debug:/sys/kernel/debug:rw \\
  -v $Q_ROOT/go:/workspace/go \\
  -w /workspace/go \\
  -e ARDUR_RUN_EBPF_SMOKE=1 \\
  $Q_IMAGE \\
  sh -lc 'set -e; date -u +%Y-%m-%dT%H:%M:%SZ; uname -a; test -r /sys/kernel/btf/vmlinux && echo BTF=yes || echo BTF=no; mount | grep -E "'"'"tracefs|debugfs"'"'" || true; ulimit -l; grep CapEff /proc/self/status; go test -v ./pkg/kernelcapture -run TestLinuxEBPF -count=1'
"

case "$(uname -s)" in
  Darwin)
    if [ ! -x "$PODMAN_BIN" ]; then
      echo "ERROR: podman binary not found at $PODMAN_BIN" >&2
      exit 1
    fi
    "$PODMAN_BIN" machine ssh -- "$REMOTE_CMD" | tee "$OUT"
    ;;
  Linux)
    bash -lc "$REMOTE_CMD" | tee "$OUT"
    ;;
  *)
    echo "ERROR: unsupported host OS for live eBPF smoke: $(uname -s)" >&2
    exit 1
    ;;
esac

echo "wrote $OUT"
