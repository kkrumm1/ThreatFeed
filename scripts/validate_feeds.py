#!/usr/bin/env python3
"""Validate ThreatFeed raw.csv files before they reach iboss.
Usage: validate_feeds.py <repo_dir> [<previous_ref>]
Exit 0 = safe to publish, 1 = needs human review (reasons printed)."""
import re, subprocess, sys, pathlib

REPO = pathlib.Path(sys.argv[1])
PREV = sys.argv[2] if len(sys.argv) > 2 else None
FEEDS = ["Afraid_org", "S3_WebProxies", "GenericWebProxy", "Azure_WebProxies",
         "GoogleStorage_WebProxies", "Cloudfront_WebProxies"]
# Max lines added+removed per feed in one sync before a human must look.
MAX_CHURN = {"Afraid_org": 400, "S3_WebProxies": 400}
DEFAULT_MAX_CHURN = 100
# Whole platforms that must never be blocked outright.
PLATFORM_ROOTS = {
    "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "googleapis.com",
    "storage.googleapis.com", "windows.net", "core.windows.net", "web.core.windows.net",
    "blob.core.windows.net", "github.io", "githubusercontent.com", "raw.githubusercontent.com",
    "pages.dev", "netlify.app", "vercel.app", "b-cdn.net", "fastly.net",
    "global.ssl.fastly.net", "web.app", "firebaseapp.com", "azurewebsites.net",
    "herokuapp.com", "onrender.com", "workers.dev", "appspot.com",
}
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
PATH = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,63}/[A-Za-z0-9._~%/-]+/?$")

def load(text):
    out = []
    for line in text.splitlines():
        s = line.strip().lower()
        if s and s != "domain":
            out.append(s)
    return out

def protected_list():
    p = REPO / "protected.txt"
    if not p.exists():
        return []
    return [l.strip().lower() for l in p.read_text().splitlines()
            if l.strip() and not l.lstrip().startswith("#")]

def covers(entry, site):
    """True if blocking `entry` would block `site` (entry equals site or is a parent of it)."""
    host = entry.split("/", 1)[0]
    if "/" in entry:  # path entry only blocks that path on that host
        return False
    return site == host or site.endswith("." + host)

problems, protected = [], protected_list()
for feed in FEEDS:
    f = REPO / feed / "raw.csv"
    if not f.exists():
        problems.append(f"{feed}: raw.csv missing")
        continue
    entries = load(f.read_text(encoding="utf-8", errors="replace"))
    if not entries:
        problems.append(f"{feed}: file is empty")
        continue
    bad = [e for e in entries if not (DOMAIN.match(e) or PATH.match(e))]
    if bad:
        problems.append(f"{feed}: {len(bad)} malformed lines, e.g. {bad[:5]}")
    roots = [e for e in entries if e.split('/', 1)[0] in PLATFORM_ROOTS and '/' not in e]
    if roots:
        problems.append(f"{feed}: whole-platform entries {roots}")
    hits = sorted({f"{e} -> {s}" for e in entries for s in protected if covers(e, s)})
    if hits:
        problems.append(f"{feed}: would block protected sites {hits[:20]}")
    if PREV:
        try:
            old = load(subprocess.run(["git", "-C", str(REPO), "show", f"{PREV}:{feed}/raw.csv"],
                                      capture_output=True, text=True, check=True).stdout)
        except subprocess.CalledProcessError:
            old = []
        added, removed = set(entries) - set(old), set(old) - set(entries)
        limit = MAX_CHURN.get(feed, DEFAULT_MAX_CHURN)
        print(f"{feed}: {len(entries)} entries (+{len(added)} / -{len(removed)})")
        if len(added) + len(removed) > limit:
            problems.append(f"{feed}: {len(added)} added / {len(removed)} removed exceeds limit {limit}")
        if old and len(entries) < 0.8 * len(old):
            problems.append(f"{feed}: shrank more than 20% ({len(old)} -> {len(entries)})")
    else:
        print(f"{feed}: {len(entries)} entries")

if problems:
    print("\nNEEDS REVIEW:")
    for p in problems:
        print(" -", p)
    sys.exit(1)
print("\nAll checks passed.")
