''' eve_to_csv.py
Convert ResMed EVE EDF annotations to CSV with absolute timestamps.
Usage:
#   python eve_to_csv.py EVE1.edf [EVE2.edf ...] [--out EVE_events.csv]
'''

import argparse
import re
from pathlib import Path
import numpy as np
import pandas as pd
import pyedflib

def to_native(ts):

    '''docstring for to_naive'''

    ts = pd.Timestamp(ts)
    return ts.tz_convert(None) if ts.tzinfo is not None else ts

def normalize_label(desc: str) -> str:

    '''docstring for normalize_label'''

    d = desc.strip().lower()
    # common patterns (ResMed often includes OA/CA/H/RERA/LL/PB words)
    if "obstruct" in d or re.search(r"\\boa\\b|\\bo/a\\b|\\boa\\)", d):
        return "Obstructive Apnea"
    if "central" in d or re.search(r"\\bca\\b|\\bc/a\\b|\\bca\\)", d):
        return "Central Apnea"
    if "hypop" in d or "hypno" in d or re.search(r"\\bhyp\\b", d):
        return "Hypopnea"
    if "rera" in d:
        return "RERA"
    if "periodic" in d or "cheyne" in d or "pb" in d:
        return "Periodic Breathing"
    if "leak" in d or "ll" in d:
        return "Large Leak"
    # fallbacks
    if "apnea" in d:
        return "Apnea (unspecified)"
    return "Other"

def read_eve(path: Path) -> pd.DataFrame:

    '''docstring for read_eve'''

    f = pyedflib.EdfReader(str(path))
    try:
        start_dt = f.getStartdatetime()
        start_dt = to_native(start_dt)
        # seconds from start, float durations, text
        onsets, durations, descs = f.readAnnotations()
    finally:
        f.close()

    rows = []
    for onset, dur, desc in zip(onsets, durations, descs):
        onset = float(onset)
        dur = float(dur if not (dur is None or (isinstance(dur,float) and np.isnan(dur))) else 0.0)
        label_norm = normalize_label(desc)
        ts_abs = start_dt + pd.to_timedelta(onset, unit="s")
        rows.append({
            "type_norm": label_norm,
            "raw_label": str(desc),
            "start_seconds_from_file": onset,
            "duration_seconds": dur,
            "start_timestamp_iso": ts_abs.isoformat()
        })
    return pd.DataFrame(rows)

def main():

    '''docstring for main'''

    ap = argparse.ArgumentParser()
    ap.add_argument("eve_paths", nargs="+", help="One or more *_EVE.edf files")
    ap.add_argument("--out", default="EVE_events.csv")
    args = ap.parse_args()

    dfs = []
    for p in args.eve_paths:
        df = read_eve(Path(p))
        df["source_file"] = Path(p).name
        dfs.append(df)

    out = pd.concat(dfs, ignore_index=True).sort_values("start_timestamp_iso")
    # keep only respiratory events + keep raw for reference
    keep = out["type_norm"].isin([
        "Obstructive Apnea","Central Apnea",
        "Hypopnea","RERA","Apnea (unspecified)",
        "Periodic Breathing","Large Leak","Other"
    ])
    out = out.loc[keep].reset_index(drop=True)

    # also include a relative 'start_seconds' normalized to the earliest
    #  absolute timestamp (useful for matching)
    t0 = pd.to_datetime(out["start_timestamp_iso"]).min()
    out["start_seconds"] = (pd.to_datetime(out["start_timestamp_iso"])
                             - t0).dt.total_seconds()
    out.to_csv(args.out, index=False)
    print(f"Saved {args.out} with {len(out)} annotations")

if __name__ == "__main__":
    main()
