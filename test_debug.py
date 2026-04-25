from verifier.compiler import compile_poc
import os

code = '#include <stdio.h>\nint main(){ printf("hi"); return 0; }'
r = compile_poc(code)

print('success:', r['success'])
print('binary_path:', r.get('binary_path'))
print('errors:', r.get('errors', []))
print('stderr:', r.get('stderr', ''))
print('stdout:', r.get('stdout', ''))
print('stage:', r.get('stage', ''))
