#!/usr/bin/env bash
set -u -o pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

INTERVAL_SECONDS="${INTERVAL_SECONDS:-1800}"
SLEEPS="${SLEEPS:-10}"
LOGDIR="${LOGDIR:-$ROOT/logs/phase2-ebpf-loop}"
mkdir -p "$LOGDIR"

run_check() {
  local checkpoint="$1"
  local label="$2"
  shift 2
  local slug
  slug="$(printf '%s' "$label" | tr '[:upper:] ' '[:lower:]-' | tr -cd '[:alnum:]-_')"
  local out="$LOGDIR/${checkpoint}-${slug}.log"
  local started ended rc
  started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  {
    printf 'started=%s\n' "$started"
    printf 'command='
    printf '%q ' "$@"
    printf '\n\n'
    "$@"
  } >"$out" 2>&1
  rc=$?
  ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  {
    printf -- '- `%s`: exit=%s, started=%s, ended=%s, log=%s\n' "$label" "$rc" "$started" "$ended" "$out"
  } >>"$LOGDIR/${checkpoint}.md"
  return 0
}

write_header() {
  local checkpoint="$1"
  local ts="$2"
  local status
  status="$(git status --short --branch)"
  {
    printf '# Phase 2 eBPF loop checkpoint %s\n\n' "$checkpoint"
    printf 'timestamp_utc: %s\n' "$ts"
    printf 'worktree: %s\n' "$ROOT"
    printf 'scope: local-only regression, packaging, and drift checks; no push, publish, daemon install, service exposure, or destructive action.\n\n'
    printf '## Git status\n\n```text\n%s\n```\n\n' "$status"
    printf '## Checks\n\n'
  } >"$LOGDIR/${checkpoint}.md"
}

finalize_checkpoint() {
  local checkpoint="$1"
  {
    printf '\n## Drift guard\n\n'
    printf -- '- Stay inside the narrow MVP: privileged local Linux process exec+exit eBPF capture, ringbuf decode, honest synthetic receipt projection.\n'
    printf -- '- Do not expand into production daemon, public release, universal CLI, file/network capture, or cross-platform kernel claims during this loop.\n'
  } >>"$LOGDIR/${checkpoint}.md"
}

for i in $(seq 0 "$SLEEPS"); do
  ts="$(date -u +%Y%m%dT%H%M%SZ)"
  checkpoint="checkpoint-${i}-${ts}"
  write_header "$checkpoint" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  run_check "$checkpoint" "shell syntax" bash -n scripts/run-phase2-ebpf-smoke.sh
  run_check "$checkpoint" "kernelcapture unit" bash -lc 'cd go && go test ./pkg/kernelcapture -count=1'
  run_check "$checkpoint" "kernelcapture race" bash -lc 'cd go && go test -race ./pkg/kernelcapture -count=1'
  run_check "$checkpoint" "quick repo check" ./scripts/check-local.sh --quick
  finalize_checkpoint "$checkpoint"
  printf 'wrote %s\n' "$LOGDIR/${checkpoint}.md"
  if [ "$i" -lt "$SLEEPS" ]; then
    sleep "$INTERVAL_SECONDS"
  fi
done
