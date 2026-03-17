'''
# edf_to_csv.py
# Convert a ResMed (or other) EDF file's Flow channel to CSV.
# Output: flow.csv with columns [timestamp_iso, seconds, flow]
'''

from pathlib import Path
import sys
import re
import pandas as pd
import numpy as np
import mne

# ------- settings you can tweak -------
# Add common flow channel name patterns here (case-insensitive):
FLOW_PATTERNS = [
    r"^flow\\b",
    r"^flow rate\\b",
    r"^breath.*flow",
    r"^airflow",
    r"^vent(ilation)? flow",
    r"^flow.*\\(l/min\\)",
]
# -------------------------------------

def choose_flow_channel(raw):
    """Return best-matching flow channel name and index."""
    ch_names = [ch.strip() for ch in raw.ch_names]
    # Try exact favorites first
    preferred = ["Flow Rate", "Flow", "Flow (L/min)"]
    for cand in preferred:
        for i, ch in enumerate(ch_names):
            if ch.lower() == cand.lower():
                return ch, i

    # Regex fallback
    for i, ch in enumerate(ch_names):
        low = ch.lower()
        for pat in FLOW_PATTERNS:
            if re.search(pat, low, flags=re.IGNORECASE):
                return ch, i

    # If not found, return the first channel as last resort
    return ch_names[0], 0

def main():

    '''docstring for main'''

    if len(sys.argv) < 2:
        print("Usage: python edf_to_csv.py <your_file.edf> [output.csv]")
        sys.exit(1)

    edf_path = Path(sys.argv[1])
    if not edf_path.exists():
        print(f"File not found: {edf_path}")
        sys.exit(1)

    out_path = Path(sys.argv[2]) if len(sys.argv) >= 3 else Path("flow.csv")

    print(f"Reading EDF: {edf_path}")
    raw = mne.io.read_raw_edf(str(edf_path), preload=True, verbose="ERROR")

    flow_ch_name, flow_idx = choose_flow_channel(raw)
    sfreq = float(raw.info["sfreq"])
    print(f"Detected sampling rate: {sfreq:.3f} Hz")
    print(f"Using channel: '{flow_ch_name}' (index {flow_idx})")

    # Get data for the chosen channel
    data, times = raw.get_data(picks=[flow_idx], return_times=True)
    flow = data[0].astype(np.float64)

    # Absolute start time (if available)
    meas_date = raw.info.get("meas_date")
    if meas_date is None:
        # Fallback: create a relative timestamp index
        ts = pd.to_datetime(times, unit="s", origin="unix")
    else:

        # meas_date may already include timezone → make it tz‑naive safely
        ts0 = pd.Timestamp(meas_date)
        if ts0.tzinfo is not None:
            ts0 = ts0.tz_convert(None)
        ts = ts0 + pd.to_timedelta(times, unit="s")


    df = pd.DataFrame({
        "timestamp_iso": ts,
        "seconds": times,
        "flow": flow
    })

    # Save
    df.to_csv(out_path, index=False)
    print(f"Saved CSV: {out_path.resolve()}  ({len(df):,} samples)")

if __name__ == "__main__":
    main()
