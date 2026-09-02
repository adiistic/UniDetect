"""Constants and canonical label definitions for UniDetect."""

FEATURE_COUNT = 78
SCHEMA_VERSION = "78d-v1"

# Canonical experiment class IDs and mappings
CLASS_ID_BENIGN = 0
CLASS_ID_DDOS = 1
CLASS_ID_RECON = 2
CLASS_ID_SLOW_HTTP = 3
CLASS_ID_DNS_TUNNEL = 4
CLASS_ID_C2_BEACON = 5

CLASS_NAMES = {
    CLASS_ID_BENIGN: "BENIGN",
    CLASS_ID_DDOS: "DDOS",
    CLASS_ID_RECON: "RECON",
    CLASS_ID_SLOW_HTTP: "SLOW_HTTP",
    CLASS_ID_DNS_TUNNEL: "DNS_TUNNEL",
    CLASS_ID_C2_BEACON: "C2_BEACON",
}

CLASS_NAME_TO_ID = {name: cid for cid, name in CLASS_NAMES.items()}

# Subtypes mapping for rich contextual classification
CLASS_SUBTYPES = {
    CLASS_ID_DDOS: ["TCP SYN Flood", "UDP Flood"],
}

# Standard candidate corpus stats reported by dataset pipeline
CANDIDATE_CORPUS_DISTRIBUTION = {
    "BENIGN": 52,
    "DDOS": 301,
    "RECON": 59,
    "SLOW_HTTP": 50,
    "DNS_TUNNEL": 52,
    "C2_BEACON": 50,
}
TOTAL_CORPUS_VECTORS = 564
