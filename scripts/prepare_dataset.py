# scripts/prepare_dataset.py
"""
Prepare dataset:
- Loads data/phish_raw.txt (one URL per line) => label=1
- Loads data/benign_raw.txt (one domain per line) => label=0
- Optionally loads data/synthetic_phish.csv (domain,label,source) if present
- Normalizes/cleans domains, removes duplicates, resolves conflicts by preferring phishing labels
- Outputs data/labeled_urls.csv with columns: domain,label,source
- Usage: python scripts/prepare_dataset.py
"""

import re
import csv
import sys
import urllib.parse
from pathlib import Path
from collections import OrderedDict

# --- Config ---
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data"
PHISH_RAW = DATA_DIR / "phish_raw.txt"
BENIGN_RAW = DATA_DIR / "benign_raw.txt"
SYNTHETIC_CSV = DATA_DIR / "synthetic_phish.csv"   # optional
OUT_CSV = DATA_DIR / "labeled_urls.csv"
MAX_DOMAIN_LEN = 253

# helper: extract hostname from url-like string
def extract_host(u: str) -> str:
    if not u or not u.strip():
        return ''
    text = u.strip()
    # if it looks like only a domain, allow it
    if not re.match(r'https?://', text) and '/' not in text:
        # might be domain only like "paypal.com" or "paypal.com/login"
        # if has path but no schema, urlparse will still put domain correctly after adding http
        pass
    if not re.match(r'https?://', text):
        text = "http://" + text
    try:
        p = urllib.parse.urlparse(text)
        host = (p.hostname or '').lower()
        # strip potential leading/trailing dots
        host = host.strip('.')
        return host
    except Exception:
        return text.lower()

def read_lines(file_path: Path):
    if not file_path.exists():
        return []
    with file_path.open("r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def read_synthetic_csv(path: Path):
    rows = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for r in reader:
            domain = (r.get("domain") or r.get("url") or "").strip()
            label = r.get("label") or r.get("Label") or "1"
            source = r.get("source") or "synthetic"
            rows.append({"domain": domain, "label": int(float(label)), "source": source})
    return rows

def is_valid_domain(d: str) -> bool:
    if not d:
        return False
    if len(d) > MAX_DOMAIN_LEN:
        return False
    # basic domain pattern (very permissive)
    if re.search(r'[^a-z0-9\.\-‎\u0400-\u04FF\u0370-\u03FF\u00C0-\u017F]', d):
        # allow unicode but filter odd control chars; we allow extended ranges above as example
        # we'll keep this permissive — some confusable unicode will be present intentionally
        pass
    # reject purely numeric hostnames
    if all(ch.isdigit() or ch=='.' for ch in d):
        return False
    return True

def main():
    DATA_DIR.mkdir(exist_ok=True)
    print("Project root:", PROJECT_ROOT)
    print("Data dir:", DATA_DIR)

    # 1) load files
    phish_lines = read_lines(PHISH_RAW)
    benign_lines = read_lines(BENIGN_RAW)
    synthetic_rows = read_synthetic_csv(SYNTHETIC_CSV)

    print(f"Loaded {len(phish_lines)} lines from {PHISH_RAW.name}")
    print(f"Loaded {len(benign_lines)} lines from {BENIGN_RAW.name}")
    if synthetic_rows:
        print(f"Loaded {len(synthetic_rows)} synthetic rows from {SYNTHETIC_CSV.name}")

    # 2) normalize -> hostnames
    phish_hosts = [extract_host(u) for u in phish_lines]
    benign_hosts = [extract_host(u) for u in benign_lines]

    # 3) build ordered dict to preserve first-seen priority
    # we prefer phishing label (1) over benign (0) when duplicates occur
    merged = OrderedDict()

    # add synthetic first (so you can choose priority; here synthetic treated as phishing)
    for r in synthetic_rows:
        d = extract_host(r["domain"])
        if not is_valid_domain(d): continue
        merged[d] = {"domain": d, "label": int(r.get("label",1)), "source": r.get("source","synthetic")}

    # add phish lines
    for u in phish_hosts:
        if not u: continue
        if not is_valid_domain(u): continue
        # prefer to set label=1 if conflict
        existing = merged.get(u)
        if existing:
            # if existing is benign, overwrite with phishing
            if existing["label"] == 0:
                merged[u] = {"domain": u, "label": 1, "source": "phish_raw"}
        else:
            merged[u] = {"domain": u, "label": 1, "source": "phish_raw"}

    # add benign lines (do not overwrite existing phishing)
    for u in benign_hosts:
        if not u: continue
        if not is_valid_domain(u): continue
        if u in merged:
            continue
        merged[u] = {"domain": u, "label": 0, "source": "benign_raw"}

    # 4) basic cleaning: remove obvious local/empty entries
    # also remove entries with more than 6 labels parts (likely URL path leftover)
    cleaned = []
    for k,v in merged.items():
        # skip localhost / loopback
        if k.startswith("localhost") or k.startswith("127.") or k.startswith("0.") or k == "":
            continue
        # reject entries that look like paths due to bad extraction
        if "/" in k or " " in k:
            continue
        # optional: skip single-letter domains
        if len(k) < 2:
            continue
        cleaned.append(v)

    print(f"After cleaning: {len(cleaned)} unique domains")

    # 5) write output CSV
    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain","label","source"])
        for r in cleaned:
            writer.writerow([r["domain"], r["label"], r.get("source","")])

    print("Wrote:", OUT_CSV)
    # summary stats
    total = len(cleaned)
    pos = sum(1 for r in cleaned if r["label"] == 1)
    neg = total - pos
    print(f"Total: {total}, Phishing (1): {pos}, Benign (0): {neg}")

if __name__ == "__main__":
    main()
