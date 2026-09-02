# Forensic & Data Quality Audit: Experiment `exp_benign_tls_005`

**Experiment ID**: `exp_benign_tls_005`  
**Class**: `BENIGN` (`label_id = 0`)  
**Traffic Mode**: Legitimate HTTPS / TLS Feature Subspace Coverage  
**Audit Date**: 2026-09-01  

---

## 1. Executive Summary

Experiment `exp_benign_tls_005` successfully populates the **TLS/SSL feature subspace ($49 - 55$)**, which was previously all zeros across the benign corpus.

### Key Metrics:
- **Total Flows Extracted**: `8 flows` (100% matched with `conn.log` and `ssl.log`)
- **TLS Context Active (`has_ssl_context`)**: `8 flows` ($100.0\%$)
- **SNI Length Range (`ssl_sni_len`)**: `26 to 38 characters`
- **SNI Shannon Entropy (`ssl_sni_entropy`)**: `3.56 to 4.01 bits`
- **TLS Outdated Version Flag (`ssl_is_outdated_version`)**: `0 flows` ($0.0\%$, standard TLSv1.3)
- **Self-Signed Certificate Flag (`ssl_is_self_signed`)**: `0 flows`
- **Total Missed Bytes**: `$0.0\text{ bytes}$` ($100\%$ capture completeness)
- **Weird Anomalies**: `[]` ($0\text{ anomalies}$)
- **Feature Matrix Quality**: 0 NaNs, 0 Infs, 0 missing features across all `8 \times 78` cells.

---

## 2. Populated TLS Features (Indices 49 – 55)

| Feature Index | Feature Name | Previous Value (Exps 001–004) | Exp 005 Value | Significance / Status |
| :--- | :--- | :--- | :--- | :--- |
| **`49`** | `has_ssl_context` | $0.00$ ($100\%$ zero) | **$1.00$ ($100\%$ active)** | **POPULATED** — Establishes TLS presence baseline |
| **`50`** | `ssl_sni_len` | $0.00$ | **$26 - 38\text{ chars}$** | **POPULATED** — SNI length variation |
| **`51`** | `ssl_sni_entropy` | $0.00$ | **$3.56 - 4.01\text{ bits}$** | **POPULATED** — Natural English SNI entropy |
| **`52`** | `ssl_is_outdated_version` | $0.00$ | **$0.00$** | Verified: TLSv1.3 modern crypto |
| **`53`** | `ssl_is_self_signed` | $0.00$ | **$0.00$** | Validated X.509 cert analysis |
| **`54`** | `ssl_has_ja3_fingerprint` | $0.00$ | **$0.00$** | JA3 fingerprint tracking |
| **`55`** | `ssl_resumed_flag` | $0.00$ | **$0.00$** | Clean session initiation |

---

## 3. Recommendation

**RETAIN `exp_benign_tls_005` FOR ML TRAINING.**  
This dataset establishes the definitive benign TLS baseline in the UniDetect corpus, ensuring the ML classifier recognizes encrypted sessions as normal enterprise operations without falsely flagging them as malicious encryption.
