import subprocess
import time

# Test hping3 SYN traffic
cmd = [
    "wsl", "-d", "Ubuntu", "-u", "root",
    "hping3", "-S", "-p", "9090", "-c", "20", "-i", "u10000", "127.0.0.1"
]
res = subprocess.run(cmd, capture_output=True, text=True)
print("Returncode:", res.returncode)
print("Stdout:\n", res.stdout)
print("Stderr:\n", res.stderr)
