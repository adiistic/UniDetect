# TLS Feature Semantics & Pipeline Validation Audit

**Audit Target**: Experiment `exp_benign_tls_005` & Phase 4 TLS Feature Extractor  
**Feature Range**: Indices 49 – 55 (`has_ssl_context` through `ssl_resumed_flag`)  
**Audit Date**: 2026-09-02  
**Audit Type**: Deep Code, Header, and Semantic Integrity Audit  

---

## 1. Feature-by-Feature Semantic Audit Matrix

| Feature Name | Vector Index | Zeek Source Field | Parser Field | Correlator Path | Observed Value in Exp 005 | Semantic Status | Validation Status | Known Limitations / Technical Root Cause |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **`has_ssl_context`** | **49** | `uid` in `ssl.log` | `logs["ssl"]` | `get_ssl_for_flow(flow)` | `1.0` | `1.0` (True) | **`VALIDATED_POSITIVE`** | Fully functional; activated whenever Zeek attaches the SSL protocol analyzer. |
| **`ssl_sni_len`** | **50** | `server_name` in `ssl.log` | `ssl_rec["server_name"]` | `ssl_rec` via UID | `26.0 - 38.0` | Character count | **`VALIDATED_POSITIVE`** | Fully functional; extracts client-provided SNI domain length. |
| **`ssl_sni_entropy`** | **51** | `server_name` in `ssl.log` | `ssl_rec["server_name"]` | `ssl_rec` via UID | `3.557 - 4.007` | Shannon entropy | **`VALIDATED_POSITIVE`** | Fully functional; calculates bit-entropy of the SNI domain string. |
| **`ssl_is_outdated_version`**| **52** | `version` in `ssl.log` | `ssl_rec["version"]` | `ssl_rec` via UID | `0.0` | `0.0` (False) | **`VALIDATED_NEGATIVE`** | `TLSv13` was observed in traffic; correctly evaluated as non-outdated. Outdated TLS (e.g. TLSv1.0) not yet tested in traffic. |
| **`ssl_is_self_signed`** | **53** | `validation_status` / `subject` / `issuer` | `ssl_rec.get("subject")` | `ssl_rec` via UID | `0.0` | `0.0` (Default) | **`UNVALIDATED`** | `subject` and `issuer` are absent from base Zeek `ssl.log` (Zeek outputs them in `x509.log` referenced via `cert_chain_fps`). Parser currently checks only `ssl.log`. |
| **`ssl_has_ja3_fingerprint`**| **54** | `ja3` in `ssl.log` | `ssl_rec.get("ja3")` | `ssl_rec` via UID | `0.0` | `0.0` (Default) | **`UNAVAILABLE_IN_ZEEK_CONFIG`** | Field `ja3` is not present in standard Zeek `ssl.log` headers unless the optional `salesforce/ja3` Zeek package is installed and loaded. |
| **`ssl_resumed_flag`** | **55** | `resumed` in `ssl.log` | `ssl_rec["resumed"]` | `ssl_rec` via UID | `0.0` | `0.0` (False) | **`VALIDATED_NEGATIVE`** | Exp 005 generated fresh standalone TLS handshakes (`resumed = F`); correctly evaluated as non-resumed. Resumed TLS session not yet tested in traffic. |

---

## 2. Deep-Dive Forensic Findings

### A. JA3 Availability in Base Zeek Installation
- **Observation**: Inspection of the raw Zeek `ssl.log` header produced in `exp_benign_tls_005`:
  ```
  #fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p version cipher curve server_name resumed last_alert next_protocol established ssl_history cert_chain_fps client_cert_chain_fps sni_matches_cert
  ```
- **Finding**: The `ja3` field is **absent** from the default Zeek distribution. 
- **Conclusion**: The resulting feature value `ssl_has_ja3_fingerprint = 0.0` reflects Zeek configuration capability (`UNAVAILABLE_IN_ZEEK_CONFIG`), not a feature extractor calculation defect.

### B. Self-Signed Certificate Analysis
- **Observation**: The OpenSSL certificate presented by the local test server was self-signed.
- **Finding**: Base Zeek writes certificate details to `x509.log` and populates `cert_chain_fps` in `ssl.log`. Base `ssl.log` does not inline `subject` and `issuer` strings. Because `extract_ssl_features` inspects only `ssl_rec`, `ssl_is_self_signed` fell back to `0.0`.
- **Conclusion**: Marked as **`UNVALIDATED`**. To populate this in offline Zeek, `x509.log` cross-referencing or a Zeek validation policy script is required.

### C. Outdated TLS and Session Resumption
- **Observation**: `version` logged `"TLSv13"` and `resumed` logged `"F"`.
- **Finding**: The client explicitly initiated fresh TLSv1.3 handshakes without session caching.
- **Conclusion**: Correctly classified as **`VALIDATED_NEGATIVE`** for both features.

---

## 3. Recommendations & Next Steps

1. **Sufficiency for Benign TLS Coverage**: **Experiment 005 is SUFFICIENT for benign TLS transport & SNI feature extraction**. It establishes valid ground truth for `has_ssl_context`, `ssl_sni_len`, `ssl_sni_entropy`, and negative baselines for `ssl_is_outdated_version` and `ssl_resumed_flag`.
2. **Schema Integrity**: The 78-feature schema remains 100% stable without changes.
3. **No Additional Benign Experiments Required Immediately**: The benign TLS baseline is established and ready for integration with the larger dataset.
