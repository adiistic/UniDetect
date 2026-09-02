"""
UniDetect Mathematical & Linguistic Feature Utilities (Person 2 - Phase 4)

Provides safe, deterministic utility functions for calculating Shannon entropy,
lexical domain metrics, and IP address classifications without external network calls.
"""

import ipaddress
import math
from collections import Counter
from typing import Optional


def shannon_entropy(s: Optional[str]) -> float:
    """Calculate the Shannon Entropy of a string: H = -sum(p(x) * log2(p(x))).

    Args:
        s: Input text string (e.g. domain name, SNI hostname).

    Returns:
        Shannon entropy in bits [0.0, 8.0]. Returns 0.0 for empty or None strings.
    """
    if not s:
        return 0.0

    length = len(s)
    if length <= 1:
        return 0.0

    counts = Counter(s)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def is_private_ip(ip_str: Optional[str]) -> bool:
    """Determine whether an IP address string belongs to a private/internal network.

    Covers RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback, link-local,
    and IPv6 private / unique local addresses.

    Args:
        ip_str: IP address string.

    Returns:
        True if IP is private/loopback/link-local, False otherwise (or if invalid/empty).
    """
    if not ip_str or ip_str in ("-", "(empty)", "0.0.0.0", ""):
        return False

    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False


def dns_vowel_ratio(query: Optional[str]) -> float:
    """Calculate the ratio of vowels to alphabetic characters in a DNS query domain.

    DGA domains typically have abnormally low or abnormally skewed vowel ratios.

    Args:
        query: Domain name string.

    Returns:
        Float ratio in [0.0, 1.0].
    """
    if not query:
        return 0.0

    lower = query.lower()
    alphas = [c for c in lower if c.isalpha()]
    if not alphas:
        return 0.0

    vowels = sum(1 for c in alphas if c in "aeiou")
    return round(float(vowels) / len(alphas), 4)


def dns_numeric_ratio(query: Optional[str]) -> float:
    """Calculate the ratio of numeric digits to total characters in a domain name.

    Hex-encoded tunneling or algorithmic domains often have higher numeric ratios.

    Args:
        query: Domain name string.

    Returns:
        Float ratio in [0.0, 1.0].
    """
    if not query:
        return 0.0

    stripped = query.replace(".", "")
    if not stripped:
        return 0.0

    digits = sum(1 for c in stripped if c.isdigit())
    return round(float(digits) / len(stripped), 4)


def dns_subdomain_depth(query: Optional[str]) -> int:
    """Calculate the subdomain depth (number of domain labels minus base domain).

    Deep label structures often indicate DNS tunneling or sub-delegated DGA paths.

    Args:
        query: Domain name string.

    Returns:
        Integer count of domain labels above TLD/root (minimum 0).
    """
    if not query or query in ("-", "(empty)", "."):
        return 0

    labels = [lbl for lbl in query.strip(".").split(".") if lbl]
    # For 'sub.example.com', labels=3, depth=2 (sub + example)
    return max(0, len(labels) - 1)


def dns_max_label_len(query: Optional[str]) -> int:
    """Calculate the maximum character length across individual labels in a domain name.

    DNS tunneling often packs data into large individual labels (approaching the 63-char limit).

    Args:
        query: Domain name string.

    Returns:
        Maximum label length integer (minimum 0).
    """
    if not query or query in ("-", "(empty)", "."):
        return 0

    labels = [lbl for lbl in query.strip(".").split(".") if lbl]
    if not labels:
        return 0

    return max(len(lbl) for lbl in labels)
