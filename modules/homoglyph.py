# import re
# from difflib import SequenceMatcher
# import urllib.parse
# CONFUSABLES = {'\u0430':'a','\u03B1':'a','\u0435':'e','\u03B5':'e','\u043E':'o','\u03BF':'o','\uFF4F':'o','\u0131':'i','\u0456':'i','0':'o','1':'l'}
# def normalize_confusables(s: str) -> str:
#     return ''.join([CONFUSABLES.get(ch, ch) for ch in s])
# def extract_domain(url: str) -> str:
#     if not url: return ''
#     if not re.match(r'https?://', url): url='http://'+url
#     try:
#         p = urllib.parse.urlparse(url); return (p.hostname or '').lower()
#     except: return url.lower()
# def best_similarity(a: str, b_list: list) -> float:
#     best=0.0
#     for t in b_list:
#         r = SequenceMatcher(None, a, t).ratio()
#         if r>best: best=r
#     return best
# def analyze_homoglyph(url: str, trusted_domains: list) -> float:
#     domain = extract_domain(url)
#     if not domain: return 0.0
#     raw = domain; normalized = normalize_confusables(raw)
#     if normalized==raw and normalized in trusted_domains: return 0.0
#     sim_norm = best_similarity(normalized, trusted_domains)
#     sim_raw = best_similarity(raw, trusted_domains)
#     score=0.0
#     if sim_norm>=0.85 and sim_raw < sim_norm - 0.05: score += 80 * (sim_norm)
#     if any(ord(c)>127 for c in raw): score += 30
#     digit_ratio = sum(c.isdigit() for c in raw) / max(1, len(raw))
#     if digit_ratio>0.15: score += 20 * digit_ratio
#     return min(100.0, max(0.0, score))
# def extract_features_from_url(url):
#     """
#     Simple URL feature extractor for phishing detection.
#     You can expand this later for more advanced features.
#     """
#     features = {}
#     features['url_length'] = len(url)
#     features['num_dots'] = url.count('.')
#     features['has_https'] = 1 if 'https' in url else 0
#     features['has_at'] = 1 if '@' in url else 0
#     features['has_hyphen'] = 1 if '-' in url else 0
#     features['count_digits'] = sum(c.isdigit() for c in url)
#     features['count_special'] = sum(not c.isalnum() for c in url)
#     features['count_letters'] = sum(c.isalpha() for c in url)
#     return features



import re
from difflib import SequenceMatcher
import urllib.parse

# Confusable Unicode character map (used for homoglyph detection)
CONFUSABLES = {
    '\u0430': 'a',  # Cyrillic a
    '\u03B1': 'a',  # Greek alpha
    '\u0435': 'e',  # Cyrillic e
    '\u03B5': 'e',  # Greek epsilon
    '\u043E': 'o',  # Cyrillic o
    '\u03BF': 'o',  # Greek omicron
    '\uFF4F': 'o',  # Full-width o
    '\u0131': 'i',  # dotless i
    '\u0456': 'i',  # Cyrillic i
    '0': 'o',
    '1': 'l'
}

def normalize_confusables(s: str) -> str:
    """Replace visually confusable Unicode characters with ASCII equivalents."""
    return ''.join([CONFUSABLES.get(ch, ch) for ch in s])

def extract_domain(url: str) -> str:
    """Extract the domain name from a URL."""
    if not url:
        return ''
    if not re.match(r'https?://', url):
        url = 'http://' + url
    try:
        p = urllib.parse.urlparse(url)
        return (p.hostname or '').lower()
    except Exception:
        return url.lower()

def best_similarity(a: str, b_list: list) -> float:
    """Compute the best string similarity between `a` and any in `b_list`."""
    best = 0.0
    for t in b_list:
        r = SequenceMatcher(None, a, t).ratio()
        if r > best:
            best = r
    return best

def analyze_homoglyph(url: str, trusted_domains: list) -> float:
    """
    Analyze a URL for homoglyph-based phishing likelihood.
    Returns a score (0–100).
    """
    domain = extract_domain(url)
    if not domain:
        return 0.0

    raw = domain
    normalized = normalize_confusables(raw)

    if normalized == raw and normalized in trusted_domains:
        return 0.0

    sim_norm = best_similarity(normalized, trusted_domains)
    sim_raw = best_similarity(raw, trusted_domains)

    score = 0.0
    if sim_norm >= 0.85 and sim_raw < sim_norm - 0.05:
        score += 80 * (sim_norm)

    if any(ord(c) > 127 for c in raw):
        score += 30

    digit_ratio = sum(c.isdigit() for c in raw) / max(1, len(raw))
    if digit_ratio > 0.15:
        score += 20 * digit_ratio

    return min(100.0, max(0.0, score))

# --------------------------------------------------------------------------
# 🧩 Feature extractor (backward-compatible)
# --------------------------------------------------------------------------

# Try to import and use the richer feature extractor from modules/features.py
try:
    from .features import extract_features_from_url as extract_features_from_url_rich

    def extract_features_from_url(url):
        """
        Wrapper: Prefer the richer feature extractor from modules.features
        Falls back to simple extractor if not available.
        """
        return extract_features_from_url_rich(url)

except Exception as e:
    print(f"[INFO] Using simple feature extractor (no modules.features found): {e}")

    def extract_features_from_url(url):
        """
        Simple URL feature extractor for phishing detection.
        """
        features = {}
        features['url_length'] = len(url)
        features['num_dots'] = url.count('.')
        features['has_https'] = 1 if 'https' in url else 0
        features['has_at'] = 1 if '@' in url else 0
        features['has_hyphen'] = 1 if '-' in url else 0
        features['count_digits'] = sum(c.isdigit() for c in url)
        features['count_special'] = sum(not c.isalnum() for c in url)
        features['count_letters'] = sum(c.isalpha() for c in url)
        return features

