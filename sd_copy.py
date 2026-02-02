#!/usr/bin/env python3
# -*- coding: utf-8 -*-

r"""
CPAP-UPLOAD.py

Copies:
  1) All files in SD root (non-recursive)
  2) All files under SETTINGS/ (recursive)
  3) The N newest dated subfolders under DATALOG/ (recursive)

Preserves (Windows FAT32 -> NTFS):
  - Date modified (mtime) via shutil.copy2()
  - Date created via WinAPI SetFileTime (Created/Access/Write)
  - Directory timestamps restored after copy (so folder dates don't change)

Examples (PowerShell):
  # Copy newest 1 DATALOG folder (default)
  python "C:\Users\bc0112\Desktop\CPAP-UPLOAD.py" --sd-root "E:\" --dest-root "C:\Users\bc0112\Desktop\LatestCPAP" --verbose

  # Copy newest 3 DATALOG folders
  python "C:\Users\bc0112\Desktop\CPAP-UPLOAD.py" --sd-root "E:\" --dest-root "C:\Users\bc0112\Desktop\LatestCPAP" --datalog-latest-n 3 --verbose

  # Dry run
  python "C:\Users\bc0112\Desktop\CPAP-UPLOAD.py" --sd-root "E:\" --dest-root "C:\Users\bc0112\Desktop\LatestCPAP" --datalog-latest-n 3 --dry-run --verbose
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from shutil import copy2
from typing import Optional, List, Tuple

# FAT32 timestamp granularity is often coarse (commonly ~2 seconds).
DEFAULT_TIME_SLACK = 3.0


# =============================================================================
# Windows FILETIME helpers (preserve Date created + access + write)
# =============================================================================
if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    FILE_READ_ATTRIBUTES = 0x0080
    FILE_WRITE_ATTRIBUTES = 0x0100
    OPEN_EXISTING = 3
    FILE_FLAG_BACKUP_SEMANTICS = 0x02000000  # required to open directories
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    CreateFileW = kernel32.CreateFileW
    CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
    ]
    CreateFileW.restype = wintypes.HANDLE

    GetFileTime = kernel32.GetFileTime
    GetFileTime.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    GetFileTime.restype = wintypes.BOOL

    SetFileTime = kernel32.SetFileTime
    SetFileTime.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
        ctypes.POINTER(wintypes.FILETIME),
    ]
    SetFileTime.restype = wintypes.BOOL

    CloseHandle = kernel32.CloseHandle
    CloseHandle.argtypes = [wintypes.HANDLE]
    CloseHandle.restype = wintypes.BOOL

    SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004  # share read/write/delete

    def _open_handle(path: Path, access: int) -> wintypes.HANDLE:
        flags = FILE_FLAG_BACKUP_SEMANTICS if path.is_dir() else 0
        h = CreateFileW(
            str(path),
            access,
            SHARE_ALL,
            None,
            OPEN_EXISTING,
            flags,
            None
        )
        if h == INVALID_HANDLE_VALUE:
            raise OSError(ctypes.get_last_error(), f"CreateFileW failed: {path}")
        return h

    def get_filetimes(path: Path) -> Tuple[wintypes.FILETIME, wintypes.FILETIME, wintypes.FILETIME]:
        """Read (created, access, write) FILETIME from a file/dir."""
        h = _open_handle(path, FILE_READ_ATTRIBUTES)
        try:
            c = wintypes.FILETIME()
            a = wintypes.FILETIME()
            w = wintypes.FILETIME()
            ok = GetFileTime(h, ctypes.byref(c), ctypes.byref(a), ctypes.byref(w))
            if not ok:
                raise OSError(ctypes.get_last_error(), f"GetFileTime failed: {path}")
            return c, a, w
        finally:
            CloseHandle(h)

    def set_filetimes(path: Path, c, a, w) -> None:
        """Write (created, access, write) FILETIME to a file/dir."""
        h = _open_handle(path, FILE_WRITE_ATTRIBUTES)
        try:
            ok = SetFileTime(h, ctypes.byref(c), ctypes.byref(a), ctypes.byref(w))
            if not ok:
                raise OSError(ctypes.get_last_error(), f"SetFileTime failed: {path}")
        finally:
            CloseHandle(h)

    def preserve_windows_times(src: Path, dst: Path) -> None:
        """Preserve Created/Access/Write times from src -> dst; warn only on failure."""
        try:
            c, a, w = get_filetimes(src)
            set_filetimes(dst, c, a, w)
        except Exception as e:
            logging.warning(f"[TIMES] Could not preserve created time for: {dst} ({e})")

    def filetime_to_unix_seconds(ft: wintypes.FILETIME) -> float:
        # FILETIME: 100-ns ticks since 1601-01-01
        val = (ft.dwHighDateTime << 32) + ft.dwLowDateTime
        return (val / 10_000_000.0) - 11644473600.0

    def get_created_seconds(path: Path) -> float:
        c, _, _ = get_filetimes(path)
        return filetime_to_unix_seconds(c)

else:
    def preserve_windows_times(src: Path, dst: Path) -> None:
        return

    def get_created_seconds(path: Path) -> float:
        raise NotImplementedError("Created-time verification is Windows-only.")


# =============================================================================
# Latest datalog subfolder selection (name-based date parsing with fallback)
# =============================================================================
DATE_RX = re.compile(
    r"""
    (?<!\d)
    (?P<y>20\d{2})          # year
    [._-]?
    (?P<m>\d{2})            # month
    [._-]?
    (?P<d>\d{2})            # day
    (?:                     # optional time portion
        [ T_-]?
        (?P<h>\d{2})
        [:\-._]?
        (?P<mi>\d{2})
        [:\-._]?
        (?P<s>\d{2})
    )?
    (?!\d)
    """,
    re.VERBOSE
)

def parse_datetime_from_name(name: str) -> Optional[datetime]:
    """
    Parse a datetime from folder name like:
      20260130
      2026-01-30
      2026_01_30
      2026-01-30_120000
      20260130-120000
    """
    m = DATE_RX.search(name)
    if not m:
        return None
    try:
        y = int(m.group("y"))
        mo = int(m.group("m"))
        d = int(m.group("d"))
        h = int(m.group("h")) if m.group("h") else 0
        mi = int(m.group("mi")) if m.group("mi") else 0
        s = int(m.group("s")) if m.group("s") else 0
        return datetime(y, mo, d, h, mi, s)
    except Exception:
        return None

def pick_latest_subfolders(datalog_dir: Path, n: int) -> List[Path]:
    """
    Pick the N newest immediate subfolders under datalog_dir.
    Ranking rules:
      1) Prefer folders with a parsed date in the name
      2) Then by parsed timestamp (or fallback mtime if no parsed date)
    Returns a list sorted from newest -> oldest.
    """
    subdirs = [p for p in datalog_dir.iterdir() if p.is_dir()]
    if not subdirs or n <= 0:
        return []

    scored: List[Tuple[int, float, str, Path]] = []
    # tuple = (has_parsed_date, timestamp, name, path)
    for d in subdirs:
        dt = parse_datetime_from_name(d.name)
        if dt:
            scored.append((1, dt.timestamp(), d.name, d))
        else:
            scored.append((0, d.stat().st_mtime, d.name, d))

    scored.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
    selected = [t[3] for t in scored[:min(n, len(scored))]]
    return selected


# =============================================================================
# Logging / verification / hashing
# =============================================================================
def setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )

def sha256_file(path: Path, chunk: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()

def verify_copy(
    src: Path,
    dst: Path,
    slack: float,
    verify_hash: bool,
    verify_created: bool
) -> Tuple[bool, str]:
    try:
        ss = src.stat()
        ds = dst.stat()
    except FileNotFoundError:
        return False, "destination_missing"

    if ss.st_size != ds.st_size:
        return False, f"size_mismatch src={ss.st_size} dst={ds.st_size}"

    # Date modified verification (mtime)
    if abs(ss.st_mtime - ds.st_mtime) > slack:
        return False, f"mtime_mismatch src={ss.st_mtime:.3f} dst={ds.st_mtime:.3f} slack={slack}"

    # Date created verification (Windows-only, optional)
    if verify_created and os.name == "nt":
        sc = get_created_seconds(src)
        dc = get_created_seconds(dst)
        if abs(sc - dc) > slack:
            return False, f"created_mismatch src={sc:.3f} dst={dc:.3f} slack={slack}"

    if verify_hash:
        if sha256_file(src) != sha256_file(dst):
            return False, "hash_mismatch"

    return True, "ok"


# =============================================================================
# Copy helpers (copy2 + preserve created + restore directory timestamps)
# =============================================================================
def ensure_dir(path: Path, dry_run: bool) -> None:
    if not path.exists():
        logging.debug(f"Creating directory: {path}")
        if not dry_run:
            path.mkdir(parents=True, exist_ok=True)

def ensure_parent(path: Path, dry_run: bool) -> None:
    ensure_dir(path.parent, dry_run)

def copy_file(
    src: Path,
    dst: Path,
    dry_run: bool,
    slack: float,
    verify: bool,
    verify_hash: bool,
    verify_created: bool
) -> None:
    ensure_parent(dst, dry_run)
    logging.info(f"COPY  {src}  ->  {dst}")
    if dry_run:
        return

    # copy2 preserves modified time + metadata as best as possible
    copy2(src, dst)

    # Preserve created/access/write on Windows
    if os.name == "nt":
        preserve_windows_times(src, dst)

    if verify:
        ok, reason = verify_copy(src, dst, slack=slack, verify_hash=verify_hash, verify_created=verify_created)
        if not ok:
            raise IOError(f"Verification failed: {dst} ({reason})")
        logging.debug(f"VERIFY OK: {dst}")

def restore_directory_timestamps(dst_dir: Path, src_dir: Path, dry_run: bool) -> None:
    """
    Restore directory timestamps so folder Date modified/created don't change due to file copy.
    """
    try:
        if dry_run:
            return
        ensure_dir(dst_dir, dry_run=False)

        if os.name == "nt":
            preserve_windows_times(src_dir, dst_dir)
        else:
            st = src_dir.stat()
            os.utime(dst_dir, (st.st_atime, st.st_mtime))
    except Exception as e:
        logging.warning(f"Could not restore directory timestamps for {dst_dir}: {e}")

def copy_tree(
    src_dir: Path,
    dst_dir: Path,
    dry_run: bool,
    slack: float,
    verify: bool,
    verify_hash: bool,
    verify_created: bool
) -> int:
    """
    Copies tree items in reverse order
    
    :param src_dir: Source directory
    :type src_dir: Path
    :param dst_dir: Destination directory
    :type dst_dir: Path
    :param dry_run: Simulated copy
    :type dry_run: bool
    :param slack: Slack time for imprecise time in timestamps
    :type slack: float
    :param verify: Verify copy
    :type verify: bool
    :param verify_hash: Verify hash
    :type verify_hash: bool
    :param verify_created: Verify created date (Windows only)
    :type verify_created: bool
    :return: number of copied items
    :rtype: int
    """
    ensure_dir(dst_dir, dry_run)
    copied = 0

    for root, _, files in os.walk(src_dir, topdown=False, followlinks=False):
        root_path = Path(root)
        rel = root_path.relative_to(src_dir)
        dst_root = dst_dir / rel

        ensure_dir(dst_root, dry_run)

        for f in files:
            src = root_path / f
            if src.is_symlink() or not src.is_file():
                continue
            dst = dst_root / f
            copy_file(src, dst, dry_run, slack, verify, verify_hash, verify_created)
            copied += 1

        restore_directory_timestamps(dst_root, root_path, dry_run)

    restore_directory_timestamps(dst_dir, src_dir, dry_run)
    return copied

def run_backup(
    sd_root: Path,
    dest_root: Path,
    datalog_name: str,
    settings_name: str,
    days_to_import: int,
    dry_run: bool,
    verify: bool,
    verify_hash: bool,
    verify_created: bool,
    slack: float
) -> None:
    """
    run_backup takes in all the necessary parameters and calls the various helper functions to create
    and import of the data from the CPAP SDCard
    
    :param sd_root: The root directory of the CPAP SDCard. Usually Drive Letter or Mountpoint
    :type sd_root: Path
    :param dest_root: The destination folder directory (anything below current working directory)
    :type dest_root: Path
    :param datalog_name: folder name of the nightly data folders
    :type datalog_name: str
    :param settings_name: folder name of the machine settings files
    :type settings_name: str
    :param days_to_import: number of days to import (newest 'n' folders under DATALOG)
    :type days_to_import: int
    :param dry_run: performs a simulated copy
    :type dry_run: bool
    :param verify: Perform verification
    :type verify: bool
    :param verify_hash: Perform hash verification
    :type verify_hash: bool
    :param verify_created: Verify Created Times copied (Windows only)
    :type verify_created: bool
    :param slack: slack time (in seconds) of drift for time values
    :type slack: float

    :returns: This function returns nothing
    :rtype: None
    """
    print(f"Copying contents of SD card: {sd_root} to: {dest_root}")
    sd_root = sd_root.resolve()
    dest_root = dest_root.resolve()

    if not sd_root.exists():
        raise SystemExit(f"SD root does not exist: {sd_root}")

    if not dry_run:
        dest_root.mkdir(parents=True, exist_ok=True)

    logging.info(f"Source (SD):        {sd_root}")
    logging.info(f"Destination:        {dest_root}")
    logging.info(f"DATALOG folder:     {datalog_name}")
    logging.info(f"SETTINGS folder:    {settings_name}")
    logging.info(f"DATALOG newest N:   {days_to_import}")
    logging.info(f"Dry-run:            {dry_run}")
    logging.info(f"Verify:             {verify}")
    logging.info(f"Verify hash:        {verify_hash}")
    logging.info(f"Verify created:     {verify_created}")
    logging.info(f"Time slack (sec):   {slack}")

    total = 0

    # 1) Root-level files
    logging.info("Step 1: Root-level files (non-recursive)...")
    for item in sd_root.iterdir():
        if item.is_file() and not item.is_symlink():
            copy_file(item, dest_root / item.name, dry_run, slack, verify, verify_hash, verify_created)
            total += 1

    # 2) SETTINGS
    settings_dir = sd_root / settings_name
    logging.info(f"Step 2: SETTINGS path: {settings_dir}")
    if settings_dir.exists() and settings_dir.is_dir():
        logging.info("Copying SETTINGS/ recursively...")
        total += copy_tree(settings_dir, dest_root / settings_name, dry_run, slack, verify, verify_hash, verify_created)
    else:
        logging.warning(f"SETTINGS folder not found (skipping): {settings_dir}")

    # 3) N newest under DATALOG
    datalog_dir = sd_root / datalog_name
    logging.info(f"Step 3: DATALOG path:  {datalog_dir}")
    if datalog_dir.exists() and datalog_dir.is_dir():
        latest_folders = pick_latest_subfolders(datalog_dir, days_to_import)
        if not latest_folders:
            logging.warning(f"No subfolders found in DATALOG (skipping): {datalog_dir}")
        else:
            logging.info("Selected DATALOG subfolders (newest -> oldest):")
            for p in latest_folders:
                logging.info(f"  - {p.name}")

            for folder in latest_folders:
                total += copy_tree(
                    folder,
                    dest_root / datalog_name / folder.name,
                    dry_run, slack, verify, verify_hash, verify_created
                )

            # Restore timestamps on destination DATALOG container folder itself
            restore_directory_timestamps(dest_root / datalog_name, datalog_dir, dry_run)
    else:
        logging.warning(f"DATALOG folder not found (skipping): {datalog_dir}")

    logging.info(f"Done. Total files copied: {total}")


def parse_args() -> argparse.Namespace:
    """
    Parses arguments into variables for utilization
    
    :return: The argparse Namespace
    :rtype: Namespace
    """
    p = argparse.ArgumentParser(
        description="Copy root files, SETTINGS, and newest N DATALOG subfolders; preserve created/modified times and verify."
    )
    p.add_argument("--sd-root", required=True, help='SD root (e.g., "E:\\")')
    p.add_argument("--dest-root", required=True, help='Destination root (e.g., "C:\\Users\\...\\LatestCPAP")')

    p.add_argument("--datalog-name", default="DATALOG", help="DATALOG folder name (default: DATALOG)")
    p.add_argument("--settings-name", default="SETTINGS", help="SETTINGS folder name (default: SETTINGS)")

    p.add_argument("--days_to_import", type=int, default=1,
                   help="How many DATALOG subfolders (days) to copy (default: 1), from most-recent to older")

    p.add_argument("--dry-run", action="store_true", help="Print actions without copying anything")
    p.add_argument("--verbose", action="store_true", help="Verbose logging")

    p.add_argument("--no-verify", action="store_true", help="Disable post-copy verification")
    p.add_argument("--verify-hash", action="store_true", help="Verify SHA-256 hash (slow, strongest)")
    p.add_argument("--verify-created", action="store_true", help="Verify Date created too (Windows-only)")
    p.add_argument("--time-slack", type=float, default=DEFAULT_TIME_SLACK,
                   help=f"Allowed timestamp delta in seconds (default {DEFAULT_TIME_SLACK})")
    return p.parse_args()


def main() -> None:
    """
    Main program logic called when directly executing
    """
    args = parse_args()
    setup_logging(args.verbose)

    run_backup(
        sd_root=Path(args.sd_root),
        dest_root=Path(args.dest_root),
        datalog_name=args.datalog_name,
        settings_name=args.settings_name,
        days_to_import=args.days_to_import,
        dry_run=args.dry_run,
        verify=not args.no_verify,
        verify_hash=args.verify_hash,
        verify_created=args.verify_created,
        slack=args.time_slack
    )


if __name__ == "__main__":
    main()