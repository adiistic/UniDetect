#!/usr/bin/env bash
# ==============================================================================
# UniDetect - Controlled Live Zeek Runner (WSL / Linux)
# ==============================================================================
# Passively observes network traffic on a specified network interface and
# writes Zeek TSV logs into the target output directory.
#
# IMPORTANT SECURITY CONSTRAINTS:
# - Passive observation only.
# - No packets are generated, injected, or transmitted by UniDetect.
# - No traffic is blocked, modified, or scanned.
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# Usage & Help Function
# ------------------------------------------------------------------------------
show_usage() {
    cat << 'EOF'
UniDetect Live Zeek Runner

Usage:
  ./scripts/run_zeek_live.sh <interface> [output_directory]

Arguments:
  <interface>         Required. Name of the network interface to observe (e.g. eth0, wlan0).
  [output_directory]  Optional. Directory where Zeek logs will be written.
                      Default: data/live_zeek_logs

Examples:
  ./scripts/run_zeek_live.sh eth0
  ./scripts/run_zeek_live.sh eth0 ~/unidetect-live/logs
  ./scripts/run_zeek_live.sh eth0 /tmp/zeek-live

Interface Discovery:
  To find available network interfaces, run:
    ip -br link
    # or
    ip link
    # or
    ip addr

To stop Zeek:
  Press Ctrl+C
EOF
}

# ------------------------------------------------------------------------------
# 1. Argument Validation
# ------------------------------------------------------------------------------
if [ $# -lt 1 ] || [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    show_usage
    exit 1
fi

INTERFACE="$1"
OUTPUT_DIR="${2:-data/live_zeek_logs}"

# ------------------------------------------------------------------------------
# 2. Check Zeek Installation
# ------------------------------------------------------------------------------
if ! command -v zeek >/dev/null 2>&1; then
    echo "[-] Error: 'zeek' command not found in PATH." >&2
    echo "    Please install Zeek inside WSL / Linux before running this script." >&2
    echo "    Verify installation with: zeek --version" >&2
    exit 1
fi

ZEEK_VERSION=$(zeek --version 2>&1 || true)

# ------------------------------------------------------------------------------
# 3. Create & Resolve Output Directory
# ------------------------------------------------------------------------------
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR_ABS=$(cd "$OUTPUT_DIR" && pwd)

# ------------------------------------------------------------------------------
# 4. Display Startup Banner & Configuration
# ------------------------------------------------------------------------------
echo "======================================================================"
echo " UniDetect - Controlled Live Zeek Runner (Passive Ingestion)"
echo "======================================================================"
echo " Zeek Version:        $ZEEK_VERSION"
echo " Observed Interface:  $INTERFACE"
echo " Output Log Directory: $OUTPUT_DIR_ABS"
echo " Operational Mode:    PASSIVE OBSERVER ONLY"
echo " Logs Generated:      conn.log, dns.log, weird.log, ssl.log, etc."
echo "======================================================================"
echo "[+] Starting Zeek in foreground mode..."
echo "[+] To stop monitoring: Press Ctrl+C"
echo "----------------------------------------------------------------------"

# ------------------------------------------------------------------------------
# 5. Trap Exit Signals & Run Zeek
# ------------------------------------------------------------------------------
cleanup() {
    echo ""
    echo "[-] Stopping Zeek live capture on interface '$INTERFACE'..."
    echo "[+] Zeek logs saved in: $OUTPUT_DIR_ABS"
    exit 0
}

trap cleanup SIGINT SIGTERM

cd "$OUTPUT_DIR_ABS"

# Execute Zeek on the interface
# Note: Zeek writes active logs (conn.log, etc.) in the current working directory.
exec zeek -i "$INTERFACE"
