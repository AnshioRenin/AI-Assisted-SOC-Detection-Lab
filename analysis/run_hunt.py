#!/usr/bin/env python3
"""
run_hunt.py - SQL threat hunting over exported Wazuh events, using Python's
built-in sqlite3 (no separate SQLite install needed).

Usage:
    1. Put this file in the same folder as your exported events.csv
       (e.g. AI-Assisted-SOC-Detection-Lab/analysis/)
    2. Run:  python run_hunt.py
    3. Screenshot the output for docs/screenshots/05-sql-threat-hunt.png

It loads the CSV into a SQLite database (hunt.db), auto-detects the relevant
columns, and runs a few classic hunts - including the LSASS credential-dumping
activity from your Atomic Red Team tests.
"""

import csv
import os
import re
import sqlite3
import sys

CSV_FILE = "events.csv"
DB_FILE = "hunt.db"


def sanitize(name):
    """Make a CSV header safe to use as a SQLite column name."""
    s = re.sub(r"[^0-9a-zA-Z]+", "_", name).strip("_")
    return s or "col"


def find_col(columns, *needles, exclude=()):
    """Find the first column whose lowercased name contains any needle
    (and none of the exclude terms)."""
    for orig, safe in columns:
        low = safe.lower()
        if any(n in low for n in needles) and not any(x in low for x in exclude):
            return orig, safe
    return None


def print_rows(cur, sql, params=(), limit=20):
    cur.execute(sql, params)
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    if not rows:
        print("   (no results)")
        return
    widths = [min(45, max(len(str(c)), *(len(str(r[i])) for r in rows))) for i, c in enumerate(cols)]
    line = "   " + " | ".join(str(c).ljust(widths[i]) for i, c in enumerate(cols))
    print(line)
    print("   " + "-" * (len(line) - 3))
    for r in rows[:limit]:
        print("   " + " | ".join(str(r[i])[:widths[i]].ljust(widths[i]) for i in range(len(cols))))
    if len(rows) > limit:
        print(f"   ... and {len(rows) - limit} more")


def main():
    if not os.path.exists(CSV_FILE):
        print(f"[!] Could not find {CSV_FILE} in this folder.")
        print(f"    Current folder: {os.getcwd()}")
        print("    Export your events from the Wazuh dashboard (Events tab -> Download CSV)")
        print(f"    and save it here as {CSV_FILE}, then run this again.")
        sys.exit(1)

    # --- Load the CSV ---
    with open(CSV_FILE, newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader)
        columns = [(h, sanitize(h)) for h in header]
        # de-duplicate safe names
        seen = {}
        fixed = []
        for orig, safe in columns:
            if safe in seen:
                seen[safe] += 1
                safe = f"{safe}_{seen[safe]}"
            else:
                seen[safe] = 0
            fixed.append((orig, safe))
        columns = fixed
        rows = list(reader)

    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    con = sqlite3.connect(DB_FILE)
    cur = con.cursor()
    col_defs = ", ".join(f'"{safe}" TEXT' for _, safe in columns)
    cur.execute(f"CREATE TABLE events ({col_defs})")
    placeholders = ", ".join("?" for _ in columns)
    for r in rows:
        r = (r + [None] * len(columns))[: len(columns)]
        cur.execute(f"INSERT INTO events VALUES ({placeholders})", r)
    con.commit()

    print("=" * 70)
    print(f" Loaded {len(rows)} events from {CSV_FILE} into {DB_FILE}")
    print("=" * 70)
    print("\n[ Columns detected ]")
    for orig, safe in columns:
        print(f"   {orig}")

    # --- Detect key columns ---
    cmd = find_col(columns, "commandline")
    image = find_col(columns, "image", exclude=("parent", "original"))
    parent = find_col(columns, "parentimage")
    eventid = find_col(columns, "eventid", "event_id")
    host = find_col(columns, "computer", "hostname", "agent_name")

    # --- HUNT 1: LSASS credential-dumping command lines (the headline) ---
    if cmd:
        print("\n[ HUNT 1 ] Possible LSASS credential dumping (command line contains 'lsass')")
        sel = [c for c in (host, image, cmd) if c]
        cols_sql = ", ".join(f'"{s}" AS "{o}"' for o, s in sel)
        print_rows(cur, f'SELECT {cols_sql} FROM events WHERE "{cmd[1]}" LIKE ?', ("%lsass%",))

    # --- HUNT 2: Encoded / hidden PowerShell ---
    if cmd:
        print("\n[ HUNT 2 ] Suspicious PowerShell (encoded / hidden)")
        sel = [c for c in (host, cmd) if c]
        cols_sql = ", ".join(f'"{s}" AS "{o}"' for o, s in sel)
        print_rows(
            cur,
            f'SELECT {cols_sql} FROM events WHERE "{cmd[1]}" LIKE ? OR "{cmd[1]}" LIKE ? OR "{cmd[1]}" LIKE ?',
            ("%-enc%", "%-encodedcommand%", "%hidden%"),
        )

    # --- HUNT 3: Most/least common processes (rare-process hunt) ---
    if image:
        print("\n[ HUNT 3 ] Process frequency (rare processes are often the interesting ones)")
        print_rows(
            cur,
            f'SELECT "{image[1]}" AS "{image[0]}", COUNT(*) AS count FROM events '
            f'WHERE "{image[1]}" IS NOT NULL AND "{image[1]}" != "" '
            f"GROUP BY 1 ORDER BY count ASC",
        )

    # --- HUNT 4: Suspicious parent -> child spawns ---
    if parent and image:
        print("\n[ HUNT 4 ] Script interpreters spawned by other processes (parent -> child)")
        sel = [c for c in (host, parent, image) if c]
        cols_sql = ", ".join(f'"{s}" AS "{o}"' for o, s in sel)
        print_rows(
            cur,
            f'SELECT {cols_sql} FROM events '
            f'WHERE ("{image[1]}" LIKE ? OR "{image[1]}" LIKE ?) '
            f'AND "{parent[1]}" IS NOT NULL',
            ("%powershell%", "%cmd.exe%"),
        )

    print("\n" + "=" * 70)
    print(" Hunt complete. The HUNT 1 results are your headline finding:")
    print(" the credential-dumping tools surfaced directly from the log data.")
    print("=" * 70)
    con.close()


if __name__ == "__main__":
    main()
