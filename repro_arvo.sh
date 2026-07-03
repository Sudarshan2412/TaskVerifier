#!/usr/bin/env bash
# Run in GitHub Codespaces (needs Docker). Pulls each ARVO vulnerable image,
# feeds the bundled PoC via the `arvo` entrypoint, and saves the real
# crash log + exit code so you can fill exit_code_vul / real_crash accurately.
#
# Usage: ./repro_arvo.sh 67297 368 62886

set -uo pipefail
mkdir -p sample_crash_logs

for id in "$@"; do
  echo "=== arvo:${id} ==="
  log="sample_crash_logs/arvo_${id}_crash.txt"

  docker pull "n132/arvo:${id}-vul" >/dev/null 2>&1

  # `arvo` is the container's built-in entrypoint that feeds the PoC
  # to the vulnerable binary and prints the sanitizer report.
  docker run --rm "n132/arvo:${id}-vul" arvo > "${log}" 2>&1
  exit_code=$?

  echo "exit_code_vul: ${exit_code}"
  echo "log saved to: ${log}"

  if grep -qiE "ERROR: (AddressSanitizer|MemorySanitizer|UndefinedBehaviorSanitizer)" "${log}"; then
    echo "real_crash: true"
  else
    echo "real_crash: false  (no sanitizer report found -- check ${log} manually)"
  fi
  echo
done