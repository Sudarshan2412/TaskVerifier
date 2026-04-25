import subprocess
import re
import os

def run_and_parse(binary_path: str) -> dict:
    """
    Runs the compiled binary. If it crashes, parses the ASan/UBSan output.
    Returns: crash_type, crash_address, top 2 stack frames, and raw output.
    """
    env = os.environ.copy()
    env['ASAN_OPTIONS'] = 'halt_on_error=1:detect_leaks=0'

    try:
        result = subprocess.run(
            [binary_path],
            capture_output=True, text=True, timeout=10, env=env
        )

        if result.returncode == 0:
            # Program ran fine — no crash.
            return {'crashed': False, 'raw_output': result.stderr}

        # It crashed — now parse the output
        crash_info = parse_asan_output(result.stderr)
        crash_info['crashed'] = True
        crash_info['raw_output'] = result.stderr
        return crash_info
    
    except subprocess.TimeoutExpired:
        return {
            'crashed': True,
            'crash_type': 'timeout',
            'crash_address': 'unknown',
            'stack_frames': [],
            'raw_output': f'Program timed out after 10 seconds'
        }
    except FileNotFoundError:
        return {
            'crashed': True,
            'crash_type': 'binary_not_found',
            'crash_address': 'unknown',
            'stack_frames': [],
            'raw_output': f'Binary not found: {binary_path}'
        }

def parse_asan_output(stderr: str) -> dict:
    """
    Extracts crash type, address, and top 2 stack frames from ASan output.
    """
    crash_type = 'unknown'
    crash_address = 'unknown'
    stack_frames = []

    # Extract crash type — multiple possible formats
    type_patterns = [
        r'ERROR: \w+Sanitizer: ([\w-]+)',
        r'SANITIZER: ([\w-]+)',
        r'SUMMARY: \w+Sanitizer: ([\w-]+)',
    ]
    for pattern in type_patterns:
        type_match = re.search(pattern, stderr, re.IGNORECASE)
        if type_match:
            crash_type = type_match.group(1)
            break

    # Extract crash address — handle multiple formats
    address_patterns = [
        # Format: "on address 0x602000000051"
        r'on address (0x[0-9a-fA-F]+)',
        # Format: "address 0x602000000051"
        r'address (0x[0-9a-fA-F]+)',
        # Format: "at 0x602000000051"
        r'at (0x[0-9a-fA-F]+)',
        # Format: "0x602000000051 is located"
        r'(0x[0-9a-fA-F]+) is located',
        # Format: "WRITE of size 4 at 0x602000000051"
        r'at (0x[0-9a-fA-F]+)(?:\s|$)',
        # Format: "accessing address 0x602000000051"
        r'accessing address (0x[0-9a-fA-F]+)',
        # Format: "[0x602000000051, ...]"
        r'\[(0x[0-9a-fA-F]+)',
    ]
    
    for pattern in address_patterns:
        addr_match = re.search(pattern, stderr, re.IGNORECASE)
        if addr_match:
            crash_address = addr_match.group(1)
            break
    
    # If still unknown, try to find any hex address (as last resort)
    if crash_address == 'unknown':
        hex_match = re.search(r'0x[0-9a-fA-F]{8,16}', stderr)
        if hex_match:
            crash_address = hex_match.group(0)

    # Extract stack frames with improved pattern
    # Formats like:
    # #0 0x401234 in main /tmp/test.c:10
    # #1 0x401567 in func /path/to/file.c:20:5
    frame_patterns = [
        # Pattern with location: file:line
        r'#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+([^\s:]+\.\w+):(\d+)',
        # Pattern without line number but with location
        r'#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+([^\s]+)',
        # Pattern from your sample output
        r'#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+\(([^:]+):(\d+):\d+\)',
    ]
    
    for pattern in frame_patterns:
        for match in re.finditer(pattern, stderr):
            frame_num = int(match.group(1))
            if frame_num < 2:  # Only top 2 frames
                frame_info = {
                    'frame': frame_num,
                    'function': match.group(2)
                }
                # Check if we have location and line
                if len(match.groups()) >= 4:
                    frame_info['location'] = match.group(3)
                    frame_info['line'] = int(match.group(4))
                elif len(match.groups()) >= 3:
                    frame_info['location'] = match.group(3)
                else:
                    frame_info['location'] = 'unknown'
                
                # Avoid duplicates
                if not any(f['frame'] == frame_num for f in stack_frames):
                    stack_frames.append(frame_info)
        
        # If we found frames, break out of pattern loop
        if stack_frames:
            break

    return {
        'crash_type': crash_type,
        'crash_address': crash_address,
        'stack_frames': stack_frames[:2]  # Ensure only top 2
    }

# Test function
if __name__ == "__main__":
    # Test with sample ASan output
    test_output = """
    =================================================================
    ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000051 at pc 0x401234 bp 0x7ffe Loc
    READ of size 1 at 0x602000000051 thread T0
        #0 0x401234 in main /src/test.c:10
        #1 0x401567 in func /src/helper.c:25
    SUMMARY: AddressSanitizer: heap-buffer-overflow /src/test.c:10 in main
    """
    
    result = parse_asan_output(test_output)
    print("Parsed ASan output:")
    print(f"  Crash type: {result['crash_type']}")
    print(f"  Crash address: {result['crash_address']}")
    print(f"  Stack frames: {result['stack_frames']}")