import os
import subprocess

to_unzip = []
for root, dirs, files in os.walk("."):
    to_unzip.extend([os.path.abspath(os.path.join(root, f)) for f in files if f.upper().endswith('.ZIP')])

for f in to_unzip:
    print(f"Extracting {f}")
    d = f[:-4]
    process = subprocess.Popen(f'7z x "{f}" -o"{d}"', shell=True, stdout=subprocess.PIPE)
    process.wait()
    os.chmod(f, 0o777)
    os.remove(f)
    
print("Finished")
