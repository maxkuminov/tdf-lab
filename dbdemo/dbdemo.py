#!/usr/bin/env python3
"""
Field-level encrypted table demo — ZTDF on the tdf-lab platform.

A SQLite table (records.sqlite, next to this script) holds employee rows whose
sensitive fields (ssn, salary, notes) exist ONLY as TDF ciphertexts, one TDF
per cell. Each row is sealed under its own classification attribute:

    secret  ->  https://lab.example/attr/classification/value/secret
    public  ->  https://lab.example/attr/classification/value/public

The lab's subject mappings (README.md, "Seed the policy") entitle:
    user-a (classification=secret)  ->  secret AND public rows
    user-b (classification=public)  ->  public rows only

so `view user-a` renders the full table while `view user-b` shows DENIED in every
secret row's protected cells. The database file itself never contains a
plaintext SSN/salary/note — dump it with `sqlite3` or `strings` to check.

Every decrypted cell costs one KAS rewrap; the DENIED cells are the KAS
refusing that rewrap because policy says so, not a client-side check.

NOTE ON NANOTDF: this demo was originally intended to use NanoTDF (the compact
binary format, ~300B per cell), but NanoTDF was removed from OpenTDF entirely
in the v0.12.0 releases of 2026-01-27 (platform PR #3013) — KAS rewrap path,
Go SDK, otdfctl and the spec docs all at once. Standard TDF (ZTDF) is the only
format this platform speaks; the cost is ~2.5-3.5KB of zip+manifest per cell.

Usage:
    python3 dbdemo.py seed          # (re)build the table, sealing as user-a
    python3 dbdemo.py view user-a    # full table
    python3 dbdemo.py view user-b      # public rows only, secret cells DENIED
    python3 dbdemo.py sizes         # per-cell ciphertext overhead
    python3 dbdemo.py export        # write records.json for the web console
                                    # (webapp/public/ + webapp/dist/); run it
                                    # after every seed so the console's
                                    # Database panel matches

Stdlib only. Depends on `otdfctl` (on PATH, or set OTDFCTL=/path/to/otdfctl)
and the lab being up. Reads USER_A_PASSWORD / USER_B_PASSWORD and the
TDF_*_HOST names from the repo-root .env (override with LAB_ENV=...).
All demo data is fictional; the SSN-shaped values use the never-issued 9xx
area with an invalid group, so none can be a real number.
"""

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
LAB = os.path.dirname(HERE)                      # repo root (holds .env)
ENV_FILE = os.environ.get("LAB_ENV", os.path.join(LAB, ".env"))
DB = os.path.join(HERE, "records.sqlite")
OTDFCTL = os.environ.get("OTDFCTL") or shutil.which("otdfctl") or "otdfctl"
FQN_BASE = "https://lab.example/attr/classification/value/"

# name, department, classification, ssn, salary, notes — all fictional
ROWS = [
    ("Ada Lovelace",  "Engineering",  "public", "900-12-0001", "$210,000", "Approved for conference travel"),
    ("Grace Hopper",  "Engineering",  "secret", "900-12-0002", "$285,000", "Leads the compiler skunkworks"),
    ("Edgar Codd",    "Data Platform","secret", "900-12-0003", "$260,000", "Negotiating retention package"),
    ("Radia Perlman", "Networking",   "public", "900-12-0004", "$240,000", "Mentors the intern cohort"),
    ("Alan Turing",   "Research",     "secret", "900-12-0005", "$310,000", "Relocation review pending"),
]
ENC_FIELDS = ("ssn", "salary", "notes")


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def read_env():
    env = {}
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k] = v.strip().strip('"').strip("'")
    except OSError as e:
        die(f"cannot read {ENV_FILE}: {e}")
    return env


_ENV = read_env() if os.path.exists(ENV_FILE) else {}
PLATFORM = "https://" + _ENV.get("TDF_PLATFORM_HOST", "platform.lab.example")
KEYCLOAK = "https://" + _ENV.get("TDF_KEYCLOAK_HOST", "keycloak.lab.example")


def get_token(user):
    """Password grant against the public cli — the lab's headless
    user-token path (README.md, "Allow and deny")."""
    var = user.upper().replace("-", "_") + "_PASSWORD"   # user-a -> USER_A_PASSWORD
    pw = read_env().get(var)
    if not pw:
        die(f"no {var} in {ENV_FILE}")
    data = urllib.parse.urlencode({
        "grant_type": "password", "client_id": "cli",
        "username": user, "password": pw,
    }).encode()
    url = f"{KEYCLOAK}/realms/lab-realm/protocol/openid-connect/token"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=15) as r:
            return json.load(r)["access_token"]
    except Exception as e:
        die(f"token grant for {user} failed ({e}) — is the lab up? curl -fsS {PLATFORM}/healthz")


def encrypt(token, plaintext, fqn):
    p = subprocess.run(
        [OTDFCTL, "encrypt", "--host", PLATFORM, "--with-access-token", token,
         "--attr", fqn, "--mime-type", "text/plain"],
        input=plaintext.encode(), capture_output=True, timeout=60)
    if p.returncode != 0:
        die(f"encrypt failed: {p.stderr.decode(errors='replace')[-500:]}")
    return p.stdout


def decrypt(token, blob):
    """Returns (status, text): status one of ok | denied | error."""
    fd, path = tempfile.mkstemp(suffix=".tdf")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        p = subprocess.run(
            [OTDFCTL, "decrypt", "--host", PLATFORM, "--with-access-token", token, path],
            capture_output=True, timeout=60)
    finally:
        os.unlink(path)
    if p.returncode == 0:
        return ("ok", p.stdout.decode(errors="replace"))
    err = p.stderr.decode(errors="replace")
    if "permissiondenied" in err.lower().replace(" ", "").replace("_", ""):
        return ("denied", "")
    return ("error", " ".join(err.split())[-160:])


def cmd_seed():
    if not shutil.which(OTDFCTL) and not os.access(OTDFCTL, os.X_OK):
        die(f"{OTDFCTL} not found — install otdfctl or set OTDFCTL")
    print("sealing as user-a (one TDF per sensitive cell) ...")
    token = get_token("user-a")
    con = sqlite3.connect(DB)
    con.execute("DROP TABLE IF EXISTS employees")
    con.execute("""CREATE TABLE employees(
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        department TEXT NOT NULL,
        classification TEXT NOT NULL CHECK (classification IN ('secret','public')),
        ssn_tdf BLOB NOT NULL,
        salary_tdf BLOB NOT NULL,
        notes_tdf BLOB NOT NULL)""")
    for name, dept, cls, ssn, sal, notes in ROWS:
        fqn = FQN_BASE + cls
        blobs = [encrypt(token, v, fqn) for v in (ssn, sal, notes)]
        con.execute(
            "INSERT INTO employees(name,department,classification,ssn_tdf,salary_tdf,notes_tdf)"
            " VALUES(?,?,?,?,?,?)", (name, dept, cls, *blobs))
        sizes = ", ".join(f"{f}={len(b)}B" for f, b in zip(ENC_FIELDS, blobs))
        print(f"  {name:14s} [{cls:6s}]  {sizes}")
    con.commit()
    con.close()
    print(f"\nseeded {len(ROWS)} rows -> {DB}")
    print("plaintext never touches the database — try: "
          f"strings {os.path.basename(DB)} | grep -c 900-12-0001")


def load_rows():
    if not os.path.exists(DB):
        die(f"{DB} missing — run `dbdemo.py seed` first")
    con = sqlite3.connect(DB)
    rows = con.execute(
        "SELECT name, department, classification, ssn_tdf, salary_tdf, notes_tdf"
        " FROM employees ORDER BY id").fetchall()
    con.close()
    return rows


def render(header, table):
    widths = [max(len(str(r[i])) for r in [header] + table) for i in range(len(header))]
    fmt = lambda r: "  ".join(str(c).ljust(w) for c, w in zip(r, widths))
    print(fmt(header))
    print(fmt(["-" * w for w in widths]))
    for r in table:
        print(fmt(r))


def cmd_view(user):
    rows = load_rows()
    token = get_token(user)
    print(f"decrypting {len(rows) * 3} cells as {user} "
          "(each cell = one KAS rewrap; DENIED = the KAS refused) ...\n")
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = [[ex.submit(decrypt, token, r[3 + i]) for i in range(3)] for r in rows]
        results = [[f.result() for f in row] for row in futs]
    ok = denied = 0
    table = []
    for r, res in zip(rows, results):
        cells = []
        for status, text in res:
            if status == "ok":
                cells.append(text)
                ok += 1
            elif status == "denied":
                cells.append("*** DENIED ***")
                denied += 1
            else:
                cells.append(f"!ERR {text[:60]}")
        table.append([r[0], r[1], r[2], *cells])
    render(["Name", "Dept", "Class", "SSN", "Salary", "Notes"], table)
    print(f"\n{user}: {ok} cells decrypted, {denied} denied by policy")


def cmd_sizes():
    rows = load_rows()
    table = []
    total_ct = total_pt = 0
    for (name, _, cls, *blobs), src in zip(rows, ROWS):
        for field, blob, pt in zip(ENC_FIELDS, blobs, src[3:]):
            table.append([name, cls, field, len(pt), len(blob), f"{len(blob) / max(len(pt), 1):,.0f}x"])
            total_ct += len(blob)
            total_pt += len(pt)
    render(["Name", "Class", "Field", "Plain B", "TDF B", "Blowup"], table)
    print(f"\ntotal plaintext {total_pt}B -> ciphertext {total_ct}B "
          "(ZTDF = zip + JSON manifest per cell; NanoTDF would have been ~300B/cell, "
          "but was removed from OpenTDF in v0.12.0, Jan 2026)")


WEBAPP = os.path.join(LAB, "webapp")


def cmd_export():
    """Write the sealed table as JSON for the console's Database panel.

    The ciphertext is deliberately served without auth: anyone may fetch the
    sealed bytes (possession is not access) — only a KAS rewrap turns a cell
    into plaintext, and that is where policy is enforced.
    """
    import base64
    rows = load_rows()
    out = {
        "generatedAt": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat(timespec="seconds"),
        "table": "employees",
        "encryptedFields": list(ENC_FIELDS),
        "fqnBase": FQN_BASE,
        "rows": [],
    }
    for i, (name, dept, cls, *blobs) in enumerate(rows, 1):
        out["rows"].append({
            "id": i, "name": name, "department": dept, "classification": cls,
            "fqn": FQN_BASE + cls,
            "cells": {f: {"b64": base64.b64encode(b).decode(), "bytes": len(b)}
                      for f, b in zip(ENC_FIELDS, blobs)},
        })
    doc = json.dumps(out)
    wrote = []
    for d in (os.path.join(WEBAPP, "public"), os.path.join(WEBAPP, "dist")):
        # public/ -> included in every future `vite build`; dist/ -> live now.
        # dist/ is skipped if it does not exist yet (nothing is served then).
        if d.endswith("dist") and not os.path.isdir(d):
            continue
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, "records.json")
        with open(path, "w") as f:
            f.write(doc)
        wrote.append(path)
    for w in wrote:
        print(f"wrote {w} ({len(doc)}B)")
    print("the console's Database panel reads /records.json — no rebuild needed "
          "for a re-export; a `vite build` empties dist/, so public/ is the "
          "copy that survives rebuilds")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed", help="(re)create and seal the table as user-a")
    v = sub.add_parser("view", help="decrypt and render the table as a user")
    v.add_argument("user", choices=["user-a", "user-b"])
    sub.add_parser("sizes", help="per-cell ciphertext overhead")
    sub.add_parser("export", help="write records.json for the web console")
    args = ap.parse_args()
    if args.cmd == "seed":
        cmd_seed()
    elif args.cmd == "view":
        cmd_view(args.user)
    elif args.cmd == "sizes":
        cmd_sizes()
    else:
        cmd_export()


if __name__ == "__main__":
    main()
