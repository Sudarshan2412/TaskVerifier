# agent/source_extractor.py

import re
import subprocess
import logging

logger = logging.getLogger(__name__)


def extract_source_from_container(cve_entry: dict, max_chars: int = 3000) -> str:
    """
    Pull relevant source functions directly from the vulnerable Docker image.
    Returns a formatted string ready to inject into the initial prompt.
    Returns "" silently on any failure — never raises.
    Works for any CVE with a docker_image_vul and an ASAN stacktrace.
    """
    image = cve_entry.get("docker_image_vul", "")
    crash_desc = cve_entry.get("crash_description", "")

    if not image or not crash_desc:
        return ""

    # Parse function names and source paths from ASAN stacktrace lines like:
    # #0 0x7c6cbe in mng_get_long /src/graphicsmagick/coders/png.c:1018:38
    funcs = re.findall(r' in (\w+)\s+/[^\s]+\.(?:c|cc|cpp):\d+', crash_desc)
    source_files = re.findall(r'(/src/[^\s]+\.(?:c|cc|cpp)):\d+', crash_desc)

    if not funcs or not source_files:
        logger.warning(
            "source_extractor: could not parse funcs/files from crash for %s",
            cve_entry.get("cve_id", "unknown")
        )
        return ""

    source_file = source_files[0]
    target_funcs = list(dict.fromkeys(funcs))[:2]  # first 2 unique functions

    try:
        # grep for the function definitions and grab 80 lines of context each
        grep_pattern = "\\|".join(
            f"^[a-zA-Z].*{f}\\b\\|^static.*{f}\\b" for f in target_funcs
        )
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--memory", "64m",
            "--cpus", "0.2",
            image,
            "grep", "-n", "-A", "80", grep_pattern, source_file
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        extracted = result.stdout.strip()

        if not extracted:
            logger.warning(
                "source_extractor: grep returned nothing for %s in %s",
                target_funcs, source_file
            )
            return ""

        return (
            f"--- Additional Source Context (from {source_file} inside container) ---\n"
            f"```c\n{extracted[:max_chars]}\n```\n"
        )

    except subprocess.TimeoutExpired:
        logger.warning("source_extractor: Docker timed out for image %s", image)
        return ""
    except Exception as e:
        logger.warning("source_extractor: failed for %s: %s", image, e)
        return ""