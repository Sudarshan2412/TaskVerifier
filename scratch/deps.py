import ast
import os
import sys

# Get standard library names. Since we're on Python 3.10+, sys.stdlib_module_names is available.
stdlib = sys.stdlib_module_names if hasattr(sys, 'stdlib_module_names') else set()
imports = set()

for root, dirs, files in os.walk('c:\\Users\\imsuk\\main\\TaskVerifier'):
    if '.venv' in dirs: dirs.remove('.venv')
    if '__pycache__' in dirs: dirs.remove('__pycache__')
    if '.git' in dirs: dirs.remove('.git')
    for file in files:
        if file.endswith('.py'):
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8') as f:
                try:
                    tree = ast.parse(f.read())
                except SyntaxError:
                    continue
                for node in ast.walk(tree):
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            base = alias.name.split('.')[0]
                            imports.add(base)
                    elif isinstance(node, ast.ImportFrom):
                        if node.module:
                            base = node.module.split('.')[0]
                            imports.add(base)

third_party = set()
for imp in imports:
    if imp not in stdlib and imp not in ('', 'src', 'tests'):
        # also ignore local modules/packages
        if not os.path.exists(os.path.join('c:\\Users\\imsuk\\main\\TaskVerifier', imp)) and not os.path.exists(os.path.join('c:\\Users\\imsuk\\main\\TaskVerifier', imp + '.py')):
            third_party.add(imp)

print("External imports found:", sorted(list(third_party)))
