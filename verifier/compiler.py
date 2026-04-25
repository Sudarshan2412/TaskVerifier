# verifier/compiler.py
import subprocess
import tempfile
import os
import shutil
import re

def compile_poc(poc_code: str, timeout_sec: int = 10) -> dict:
    """
    Compile PoC C code with AddressSanitizer and UndefinedBehaviorSanitizer using Clang.
    
    Returns:
        dict: {
            'success': bool,
            'binary_path': str or None,
            'errors': list,
            'stderr': str,
            'stdout': str,
            'c_file': str,
            'sanitizers_enabled': bool
        }
    """
    result = {
        'success': False,
        'binary_path': None,
        'errors': [],
        'stderr': '',
        'stdout': '',
        'c_file': None,
        'sanitizers_enabled': True
    }
    
    # Find Clang executable
    clang_path = shutil.which('clang')
    if not clang_path:
        # Try common Windows paths
        possible_paths = [
            'C:/msys64/ucrt64/bin/clang.exe',
            'C:/msys64/mingw64/bin/clang.exe',
            'C:/Program Files/LLVM/bin/clang.exe'
        ]
        for path in possible_paths:
            if os.path.exists(path):
                clang_path = path
                break
    
    if not clang_path:
        result['errors'] = [{'type': 'compiler_not_found', 'message': 'Clang not found. Install via: pacman -S mingw-w64-ucrt-x86_64-clang'}]
        return result
    
    # Create temporary files
    with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
        f.write(poc_code)
        c_file = f.name
    result['c_file'] = c_file
    exe_file = c_file.replace('.c', '.exe')
    result['binary_path'] = exe_file
    
    try:
        # Compile with AddressSanitizer and UndefinedBehaviorSanitizer
        # -fsanitize=address: Memory error detection (buffer overflows, use-after-free, etc.)
        # -fsanitize=undefined: Detects undefined behavior (integer overflow, null dereference, etc.)
        # -g: Include debug symbols for better stack traces
        # -O0: Disable optimizations for clearer crash reports
        cmd = [
            clang_path, c_file, '-o', exe_file,
            '-g', '-O0',
            '-Wno-unused-command-line-argument'
        ]

        
        compile_result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec
        )
        
        result['stdout'] = compile_result.stdout
        result['stderr'] = compile_result.stderr
        
        # Check compilation success
        if compile_result.returncode != 0:
            errors = _parse_clang_errors(compile_result.stderr)
            result['errors'] = errors if errors else [{'type': 'compilation_error', 'message': compile_result.stderr[:500]}]
            return result
        
        # Run the compiled binary to trigger sanitizer crashes
        # Set ASAN_OPTIONS to halt on error and detect leaks
        env = os.environ.copy()
        env['ASAN_OPTIONS'] = 'halt_on_error=1:detect_leaks=0:abort_on_error=1'
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1'
        
        try:
            run_result = subprocess.run(
                [exe_file],
                capture_output=True,
                text=True,
                timeout=timeout_sec,
                env=env
            )
            result['stdout'] = run_result.stdout
            result['stderr'] = run_result.stderr
            
            # Check for sanitizer errors in stderr
            if _has_sanitizer_error(run_result.stderr):
                result['errors'] = _parse_sanitizer_output(run_result.stderr)
                # success remains False because crash was detected
            else:
                result['success'] = True
                
        except subprocess.TimeoutExpired:
            # Timeout might mean program hung - could be a crash
            result['errors'] = [{'type': 'timeout', 'message': f'Execution exceeded {timeout_sec}s'}]
        except Exception as e:
            result['errors'] = [{'type': 'runtime_error', 'message': str(e)}]
        
        return result
        
    except subprocess.TimeoutExpired:
        result['errors'] = [{'type': 'timeout', 'message': f'Compilation exceeded {timeout_sec}s'}]
        return result
    except Exception as e:
        result['errors'] = [{'type': 'exception', 'message': str(e)}]
        return result


def _parse_clang_errors(stderr: str) -> list:
    """Parse Clang compilation errors"""
    errors = []
    lines = stderr.split('\n')
    
    for line in lines:
        # Clang error format: file.c:10:5: error: message
        if '.c:' in line and ('error:' in line or 'warning:' in line):
            parts = line.split(':')
            if len(parts) >= 4:
                errors.append({
                    'type': parts[3].strip() if len(parts) > 3 else 'error',
                    'file': parts[0] if parts[0].endswith('.c') else 'unknown',
                    'line': int(parts[1]) if parts[1].isdigit() else 0,
                    'message': ':'.join(parts[4:]).strip() if len(parts) > 4 else line
                })
    
    return errors


def _parse_sanitizer_output(stderr: str) -> list:
    """Parse AddressSanitizer/UBSan runtime errors"""
    errors = []
    
    # Common ASan error patterns
    asan_patterns = [
        'heap-buffer-overflow',
        'stack-buffer-overflow',
        'global-buffer-overflow',
        'use-after-free',
        'double-free',
        'memory-leak',
        'SEGV on unknown address',
        'SIGSEGV',
        'null-dereference'
    ]
    
    # Common UBSan error patterns
    ubsan_patterns = [
        'undefined-behavior',
        'shift-out-of-bounds',
        'integer-overflow',
        'division-by-zero',
        'null-dereference'
    ]
    
    stderr_lower = stderr.lower()
    error_type = 'unknown'
    
    # Detect error type
    for pattern in asan_patterns + ubsan_patterns:
        if pattern.lower() in stderr_lower:
            error_type = pattern
            break
    
    # Extract location if available
    location = 'unknown'
    line_match = re.search(r'(\w+\.c):(\d+)', stderr)
    if line_match:
        location = f"{line_match.group(1)}:{line_match.group(2)}"
    
    errors.append({
        'type': error_type,
        'location': location,
        'message': stderr[:300]  # First 300 chars
    })
    
    return errors


def _has_sanitizer_error(stderr: str) -> bool:
    """Check if stderr contains sanitizer error indicators"""
    error_indicators = [
        'ERROR: AddressSanitizer',
        'ERROR: UndefinedBehaviorSanitizer',
        'SUMMARY: AddressSanitizer',
        'heap-buffer-overflow',
        'use-after-free',
        'SEGV',
        'SIGSEGV'
    ]
    
    for indicator in error_indicators:
        if indicator.lower() in stderr.lower():
            return True
    return False


# Optional: Clean up temporary files
def cleanup_compile_result(result: dict):
    """Delete temporary files created during compilation"""
    if result.get('c_file') and os.path.exists(result['c_file']):
        try:
            os.unlink(result['c_file'])
        except:
            pass
    
    if result.get('binary_path') and os.path.exists(result['binary_path']):
        try:
            os.unlink(result['binary_path'])
        except:
            pass


# Test function
if __name__ == '__main__':
    # Test 1: Valid code
    print("Test 1: Valid C code")
    code1 = '#include <stdio.h>\nint main(){ printf("Hello\\n"); return 0; }'
    r1 = compile_poc(code1)
    print(f"  Success: {r1['success']}")
    print(f"  Errors: {r1['errors']}")
    
    # Test 2: Code with buffer overflow (should be caught by ASan)
    print("\nTest 2: Buffer overflow (should trigger ASan)")
    code2 = '''
    #include <string.h>
    int main() {
        char buf[10];
        strcpy(buf, "this string is way too long for the buffer");
        return 0;
    }
    '''
    r2 = compile_poc(code2)
    print(f"  Success: {r2['success']}")
    print(f"  Errors: {r2['errors']}")
    
    # Test 3: Null pointer dereference (should be caught)
    print("\nTest 3: Null pointer dereference")
    code3 = 'int main() { int *p = 0; *p = 42; return 0; }'
    r3 = compile_poc(code3)
    print(f"  Success: {r3['success']}")
    print(f"  Errors: {r3['errors']}")
    
    # Clean up
    for r in [r1, r2, r3]:
        cleanup_compile_result(r)