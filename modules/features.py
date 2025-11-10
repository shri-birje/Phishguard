# modules/features.py
import re
import math
import idna
import unicodedata
from collections import Counter

# simple Levenshtein (iterative)
def levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    la, lb = len(a), len(b)
    if la == 0: return lb
    if lb == 0: return la
    prev = list(range(lb+1))
    for i, ca in enumerate(a, start=1):
        cur = [i] + [0]*lb
        for j, cb in enumerate(b, start=1):
            add = prev[j] + 1
            delete = cur[j-1] + 1
            change = prev[j-1] + (0 if ca==cb else 1)
            cur[j] = min(add, delete, change)
        prev = cur
    return prev[lb]

# punycode / ascii form
def to_ascii(domain: str) -> str:
    try:
        return idna.encode(domain).decode()
    except Exception:
        return domain

# character entropy
def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    counts = Counter(s)
    probs = [c/len(s) for c in counts.values()]
    return -sum(p*math.log2(p) for p in probs)

# count non-ascii (unicode confusables)
def count_non_ascii(s: str) -> int:
    return sum(1 for ch in s if ord(ch) > 127)

# common homoglyph substitution map (extend as needed)
HOMOGLYPH_MAP = {
    '0':'o', '1':'l', '3':'e', '4':'a', '5':'s', '7':'t', '8':'b',
    'l':'1', 'o':'0', 'i':'1', 's':'5', 'a':'4'
}
def homoglyph_sub_count(domain: str) -> int:
    c = 0
    for ch in domain:
        if ch.lower() in HOMOGLYPH_MAP:
            c += 1
    return c

SUSPICIOUS_TLDS = {'.zip', '.top', '.xyz', '.country', '.info', '.icu', '.loan'}

def extract_features_from_url(url: str, trusted_domains: list = None) -> dict:
    """
    url: full url or domain (pass only hostname ideally)
    trusted_domains: list of trusted canonical domains to compute distances to
    returns: dict of numeric features
    """
    # normalize
    host = url.lower().strip()
    # remove protocol and path if present
    host = re.sub(r'^https?://', '', host)
    host = host.split('/')[0]
    # remove port
    host = host.split(':')[0]

    # domain parts
    parts = host.split('.')
    tld = '.' + parts[-1] if len(parts)>1 else ''
    sld = parts[-2] if len(parts)>1 else parts[0]
    ascii = to_ascii(host)

    feats = {}
    feats['len_domain'] = len(host)
    feats['num_parts'] = len(parts)
    feats['tld_suspicious'] = 1 if tld in SUSPICIOUS_TLDS else 0
    feats['non_ascii_count'] = count_non_ascii(host)
    feats['homoglyph_subs'] = homoglyph_sub_count(host)
    feats['punycode_diff'] = 1 if ascii != host else 0
    feats['levenshtein_min_trusted'] = 999
    feats['entropy'] = shannon_entropy(host)
    feats['digit_ratio'] = sum(ch.isdigit() for ch in host)/max(1,len(host))
    feats['alpha_ratio'] = sum(ch.isalpha() for ch in host)/max(1,len(host))
    # optional: compare to a small list of well-known brands (trusted_domains)
    if trusted_domains:
        best = 999
        for t in trusted_domains:
            d = levenshtein(sld, t.split('.')[0])
            if d < best: best = d
        feats['levenshtein_min_trusted'] = best
    else:
        feats['levenshtein_min_trusted'] = 999

    return feats
