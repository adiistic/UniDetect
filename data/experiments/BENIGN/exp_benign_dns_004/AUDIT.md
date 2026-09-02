# Forensic & Data Quality Audit: Experiment `exp_benign_dns_004`

**Experiment ID**: `exp_benign_dns_004`  
**Class**: `BENIGN` (`label_id = 0`)  
**Traffic Mode**: Legitimate DNS Behavioral Diversity (A, TXT, Multi-Answer, Depth 1-5, NXDOMAIN, Bursts)  
**Audit Date**: 2026-09-01  

---

## 1. Executive Summary

Experiment 004 substantially expands the benign DNS feature distribution of the UniDetect dataset, preventing the machine learning models from overfitting to uniform query lengths, single answer structures, or single-tier names.

### Key Metrics:
- **Total DNS Flows Captured**: `20 flows` (100% matched with `dns.log` and `conn.log`)
- **Query Length Range**: `8 to 49 characters`
- **Shannon Entropy Range**: `2.75 to 4.09`
- **Subdomain Depth Range**: `1 to 5 levels`
- **Max Label Length Range**: `5 to 24 characters`
- **Numeric Character Ratio**: `0.00 to 0.07`
- **Query Types**: `A (QTYPE=1)` and `TXT (QTYPE=16)`
- **Legitimate NXDOMAIN Count**: `3 flows`
- **Multi-Answer Responses**: `3 answers per response` on round-robin cluster lookups
- **Missed Bytes**: `$0.0\text{ bytes}$` ($100\%$ capture completeness)
- **Weird Anomalies**: `$0\text{ anomalies}$`

---

## 2. Comparison with Experiment 003 DNS Subspace

| Attribute | Experiment 003 (`exp_benign_multi_003`) | Experiment 004 (`exp_benign_dns_004`) | Expansion Significance |
| :--- | :--- | :--- | :--- |
| **DNS Flow Count** | 5 flows | **20 flows** | $5\times$ sample coverage |
| **Query Lengths** | $17 - 21\text{ chars}$ (Narrow) | **$8 - 49\text{ chars}$ (Broad)** | Spans tiny to deep enterprise names |
| **Subdomain Depth**| Fixed at $2.0$ levels | **$1.0 - 5.0\text{ levels}$** | Multi-tier cloud/enterprise hierarchies |
| **Max Label Length**| $7 - 8\text{ chars}$ | **$5 - 24\text{ chars}$** | Realistic label length variation |
| **Query Types** | Type A only ($1.0$) | **Type A (17) + Type TXT (3)** | Covers SPF/DKIM verification queries |
| **Response Codes** | NOERROR only ($0\text{ NXDOMAIN}$) | **NOERROR + NXDOMAIN (3)** | Teaches model benign NXDOMAIN patterns |
| **Answer Counts** | $1.0\text{ answer/flow}$ | **$0, 1, \text{and } 3\text{ answers}$** | Multi-IP round-robin diversity |

---

## 3. Recommendation

**RETAIN `exp_benign_dns_004` FOR ML TRAINING.**  
This dataset establishes a comprehensive, mathematically sound baseline of legitimate DNS operations across all 13 DNS feature dimensions ($27 - 39$).
