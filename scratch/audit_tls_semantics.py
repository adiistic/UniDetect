import json
import sys
from pathlib import Path

# Load ssl.log raw headers and records
ssl_log_path = Path("data/experiments/BENIGN/exp_benign_tls_005/zeek/ssl.log")
headers = []
records = []
with open(ssl_log_path, "r", encoding="utf-8") as f:
    for line in f:
        if line.startswith("#fields"):
            headers = line.strip().split("\t")[1:]
        elif not line.startswith("#"):
            parts = line.strip().split("\t")
            records.append(dict(zip(headers, parts)))

print("=== ZEEK SSL.LOG FIELD AUDIT ===")
print("Field count:", len(headers))
print("Available fields:", headers)

print("\nSpecific Field Presence Check:")
for field in ["server_name", "version", "resumed", "subject", "issuer", "validation_status", "ja3", "ja3s"]:
    is_present = field in headers
    sample_val = records[0].get(field, "N/A") if records else "N/A"
    print(f"  {field:20s}: Present in ssl.log = {str(is_present):5s} | Sample = {sample_val}")
