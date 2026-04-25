from verifier.compiler import compile_poc
 
code = '#include <stdio.h>\nint main(){ printf("hi"); return 0; }'
 
r = compile_poc(code)
 
print("success  :", r['success'])
print("errors   :", r['errors'])
print("stderr   :", r['stderr'][:500])
print("stdout   :", r['stdout'][:200])
print("binary   :", r['binary_path'])