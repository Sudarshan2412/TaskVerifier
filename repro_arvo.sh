#!/usr/bin/env bash
# Run in GitHub Codespaces (needs Docker). Pulls each ARVO vulnerable image,
# feeds the bundled PoC via the `arvo` entrypoint, and saves the real
# crash log + exit code so you can fill exit_code_vul / real_crash accurately.
#
# FIXES vs. previous version (both found on re-check, neither caught before
# because the earlier pilot runs happened not to hit a failed pull):
#   - The pull-failure warning used to get silently erased: it was written
#     with `tee -a` to the log, but the environment-header block a few lines
#     later wrote with plain `>` (truncate), wiping it out before the run
#     even happened. Every write to the log is now `>>`; the file is
#     initialized exactly once, first, with `:  > "${log}"`.
#   - The "raw signal, no sanitizer report" check tested for exit code 138
#     as "SIGBUS" -- wrong; SIGBUS is signal 7, so 128+7=135, not 138,  and
#     138 isn't a real fault signal on Linux at all. Rather than guess
#     another magic number, this now uses the general convention: any exit
#     code above 128 means "killed by signal (code-128)", so it flags the
#     signal number directly instead of hardcoding specific ones.
#
# CHANGES vs. original:
#   - Records docker image digest, host kernel version, ASLR setting, and
#     docker version alongside the crash log, so a repro mismatch between
#     two machines can be root-caused from the log file alone.
#   - Checks `docker pull`'s own exit status instead of silently discarding
#     it; a failed pull used to fall straight into `docker run` against
#     whatever was cached locally.
#
# Usage: ./repro_arvo.sh 67297 368 62886

set -uo pipefail
mkdir -p sample_crash_logs

for id in "$@"; do
  echo "=== arvo:${id} ==="
  log="sample_crash_logs/arvo_${id}_crash.txt"
  image="n132/arvo:${id}-vul"

  # Initialize the log exactly once, first. Every write after this point
  # uses >> -- nothing later in this loop is allowed to use plain > again,
  # specifically so a warning written early can't get silently wiped by a
  # later block.
  : > "${log}"

  pull_output=$(docker pull "${image}" 2>&1)
  pull_status=$?
  if [ "${pull_status}" -ne 0 ]; then
    {
      echo "WARNING: docker pull failed (exit ${pull_status}) -- running against"
      echo "whatever is cached locally, if anything. This alone can cause a"
      echo "mismatch against a teammate who pulled successfully."
      echo "${pull_output}"
    } | tee -a "${log}"
  fi

  digest=$(docker inspect --format='{{.Id}}' "${image}" 2>/dev/null || echo "unavailable")

  {
    echo "# --- repro environment -------------------------------------"
    echo "# image:            ${image}"
    echo "# image_id:         ${digest}"
    echo "# host_kernel:      $(uname -srm)"
    echo "# aslr_setting:     $(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo unavailable)"
    echo "# docker_version:   $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unavailable)"
    echo "# --------------------------------------------------------------"
  } >> "${log}"

  # `arvo` is the container's built-in entrypoint that feeds the PoC
  # to the vulnerable binary and prints the sanitizer report.
  docker run --rm "${image}" arvo >> "${log}" 2>&1
  exit_code=$?

  echo "exit_code_vul: ${exit_code}"
  echo "image_id: ${digest}"
  echo "log saved to: ${log}"

  # FIX (arvo:12957): UBSan does NOT print "ERROR: UndefinedBehaviorSanitizer"
  # -- its actual format is "<file>:<line>:<col>: runtime error: <message>",
  # optionally followed by a "SUMMARY: UndefinedBehaviorSanitizer: ..." line.
  # The old pattern only ever matched ASan/MSan's "ERROR: ..." header, so a
  # genuine UBSan crash (verified: arvo:12957 is exactly this -- sanitizer is
  # ubsan, crash type is a UBSan-specific check) was silently misclassified
  # as "no crash" even when the container's exit code showed something did
  # happen. Matching "runtime error:" catches UBSan; the ERROR:/SUMMARY:
  # patterns still catch ASan/MSan as before.
  if grep -qiE "ERROR: (AddressSanitizer|MemorySanitizer)|runtime error:|SUMMARY: UndefinedBehaviorSanitizer" "${log}"; then
    echo "real_crash: true"
  elif [ "${exit_code}" -gt 128 ]; then
    signal_num=$((exit_code - 128))
    echo "real_crash: false  (killed by signal ${signal_num} -- sanitizer runtime never got" \
         "to report; see image_id/host_kernel/aslr_setting above before assuming the CVE" \
         "doesn't repro)"
  else
    echo "real_crash: false  (no sanitizer report found -- check ${log} manually)"
  fi
  echo
done