#!/usr/bin/env bash
# cleanup_orphans.sh — safety net for the tool-use agent loop's exploration
# containers (agent/container_runtime.py's ContainerSession).
#
# ContainerSession.cleanup() runs from a `finally` block in
# agent_loop.py's _run_agent_with_tools() and should remove every
# exploration container it starts. This script exists for the case that
# doesn't cover: the Codespace disconnects, the process gets killed
# (kill -9, OOM kill, a Codespaces idle-timeout stop mid-run), or anything
# else that prevents that `finally` from ever running. Without this, an
# orphaned container silently sits there consuming the Codespaces storage
# quota until someone notices.
#
# Usage:
#   ./cleanup_orphans.sh              # remove taskverifier_* containers older than 60 min
#   ./cleanup_orphans.sh 15           # custom age threshold in minutes
#   ./cleanup_orphans.sh --dry-run    # list what would be removed, remove nothing
#
# Safe to run on a schedule (e.g. a cron job, or just run it manually before
# starting a new batch) -- only ever touches containers whose name starts
# with the exact prefix agent/container_runtime.py uses
# (CONTAINER_NAME_PREFIX = "taskverifier"), never anything else on the
# machine.

set -uo pipefail

DRY_RUN=false
AGE_MINUTES=60

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    ''|*[!0-9]*) : ;;  # ignore non-numeric args other than the flags above
    *) AGE_MINUTES="$arg" ;;
  esac
done

echo "Looking for taskverifier_* containers older than ${AGE_MINUTES} minutes..."

now_epoch=$(date +%s)
found_any=false

# docker ps -a --filter matches by name prefix; --format gives us name and
# creation time as unix epoch seconds directly, so we don't need to parse
# docker's human-readable date output.
while IFS=$'\t' read -r name created_epoch; do
  [ -z "$name" ] && continue
  found_any=true
  age_minutes=$(( (now_epoch - created_epoch) / 60 ))

  if [ "$age_minutes" -ge "$AGE_MINUTES" ]; then
    if [ "$DRY_RUN" = true ]; then
      echo "  [dry-run] would remove: ${name} (age: ${age_minutes}m)"
    else
      echo "  removing: ${name} (age: ${age_minutes}m)"
      docker rm -f "$name" >/dev/null 2>&1 \
        && echo "    removed" \
        || echo "    WARNING: failed to remove ${name} -- check manually"
    fi
  else
    echo "  skipping: ${name} (age: ${age_minutes}m, under threshold)"
  fi
done < <(docker ps -a --filter "name=^taskverifier_" --format '{{.Names}}\t{{.CreatedAt}}' 2>/dev/null \
          | while IFS=$'\t' read -r n c; do
              # docker's --format CreatedAt isn't directly epoch seconds;
              # re-resolve via `docker inspect` per-container for an exact
              # unix timestamp instead of parsing the human-readable string.
              epoch=$(docker inspect --format '{{.Created}}' "$n" 2>/dev/null | xargs -I{} date -d {} +%s 2>/dev/null)
              [ -n "$epoch" ] && printf '%s\t%s\n' "$n" "$epoch"
            done)

if [ "$found_any" = false ]; then
  echo "  (none found)"
fi

echo "Done."