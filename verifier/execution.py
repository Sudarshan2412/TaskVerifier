import subprocess
import os


def check_execution(binary_path: str) -> dict:
    """
    Runs the binary and checks if it exited cleanly (exit code 0).
    A clean exit means the vulnerability was NOT triggered.
    Returns a dict with: triggered (bool), message (str)
    """
    env = os.environ.copy()
    env['ASAN_OPTIONS'] = 'halt_on_error=1:detect_leaks=0'

    try:
        result = subprocess.run(
            [binary_path],
            capture_output=True, text=True, timeout=10, env=env
        )

        if result.returncode == 0:
            return {
                'triggered': False,
                'exit_code': 0,
                'message': 'Program ran without triggering any vulnerability. '
                            'The PoC compiled and executed cleanly. '
                            'Try a different input or approach to trigger the bug.',
                'stderr': result.stderr
            }
        else:
            return {
                'triggered': True,
                'exit_code': result.returncode,
                'message': 'Program crashed — vulnerability was triggered.',
                'stderr': result.stderr
            }

    except subprocess.TimeoutExpired:
        return {
            'triggered': False,
            'exit_code': -1,
            'message': 'Program timed out after 10 seconds. The PoC may be stuck in a loop.',
            'stderr': ''
        } 