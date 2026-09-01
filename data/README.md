# UniDetect Data Directory

This directory stores input data files used for passive network traffic analysis by UniDetect.

## Structure & Purpose
- `pcaps/`: Place raw `.pcap` or `.pcapng` network capture files here for offline analysis.
- `zeek_logs/`: Place Zeek log files (e.g. `conn.log`, `dns.log`, `http.log`) extracted from passive traffic capture.

## Security Notice
UniDetect operates exclusively as a **passive observer**. Data placed in this folder is analyzed strictly offline or in a read-only manner. UniDetect will never retransmit or replay packets from these files back onto the network.
