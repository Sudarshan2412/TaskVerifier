import subprocess

def run_docker(cmd):
    full_cmd = ['docker', 'run', '--rm', '--entrypoint', 'sh', 'n132/arvo:368-vul', '-c', cmd]
    res = subprocess.run(full_cmd, capture_output=True, text=True)
    return res.stdout if res.returncode == 0 else res.stderr

print(run_docker("cat /src/freetype2/src/cff/cffparse.c | grep -n -A 10 -B 5 'cff_parse_blend'"))
