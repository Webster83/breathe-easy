"""
ezshare_getter.py facilitates getting the ResMed 9/10/11 series files from a WiFi enabled (ezshare)
card and getting the most recent (N) days worth of data. This can be used standalone, or as an import module
that will enter at the runner function.

Author: BChap
Last Modified: 20260219
"""

import argparse
import ctypes
import os
import re
import requests
import sys
import time
import connect_wifi_windows
from bs4 import BeautifulSoup, Tag
from bs4.element import NavigableString
from ctypes import wintypes
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Optional, Mapping
from urllib.parse import urljoin, urlparse, unquote
from yaml import safe_load

def load_config(config: str) -> dict:
    """
    Loads the user provided configuration file and returns it as a dictionary
    """
    with open(config, "r", encoding="utf-8") as f:
        return safe_load(f)

def parse_args() -> argparse.Namespace:
    """
    To be implemented
    """
    p = argparse.ArgumentParser(
        description="Get ResMed S10/11 Data from an EZSh@re Wifi SD Card"
    )
    p.add_argument("--ip_address", required=False, default="192.168.4.1", help="IP address of EZShare Card")
    p.add_argument("--root_dir", required=False, default="A:")
    p.add_argument("--sd_ssid", required=False, default="ezshare", help="EZShare wifi profile name")
    p.add_argument("--save_to", required=False, default="latestcpap", help="CPAP Data Directory")
    p.add_argument("--overwrite", required=False, action="store_true", help="overwrite existing files?")
    p.add_argument("--home_ssid", required=False, default="", help="Home wifi profile name")
    p.add_argument("--n_days", required=True,help="Number of days to download")
    p.add_argument("--verbose", required=False, action="store_true", help="verbose logging")
    return p.parse_args()

def ensure_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)

def script_dir(verbose: bool = False) -> Path:
    try:
        p = Path(__file__).resolve().parent
        if verbose:
            print(p)
        return p
    except NameError:
        return Path.cwd()

def is_yyyymmdd(name: str) -> bool:
    try:
        datetime.strptime(name, "%Y%m%d")
        return True
    except ValueError:
        return False

def _split_ext_preserve_case(filename: str):
    """
    Split a filename into (stem, ext) preserving case.
    Example: 'Data.LOG' -> ('Data', '.LOG'), '.env' -> ('.env', '')
    """
    if filename.startswith(".") and filename.count(".") == 1:
        return filename, ""
    stem, ext = os.path.splitext(filename)
    return stem, ext

def _case_insensitive_exists(path: Path, filename: str) -> bool:
    """
    Returns True if a file exists in dest dir with same name ignoring case.
    """
    if not path.exists():
        return False
    if (path / filename).exists():
        return True
    if sys.platform.lower().startswith("win"):
        try:
            lower_target = filename.lower()
            for entry in path.iterdir():
                if entry.name.lower() == lower_target:
                    return True
        except FileNotFoundError:
            return False
    return False

def _resolve_case_collision(dest_dir: Path, filename: str, policy: str) -> Path:
    """
    Return a destination Path for the filename honoring the collision policy.
    Policies:
      - 'skip'      -> return the existing path (caller will skip)
      - 'suffix'    -> append '__dupN' before extension until no case-insensitive collision
      - 'overwrite' -> return the original path
    """
    target = dest_dir / filename
    if not _case_insensitive_exists(dest_dir, filename):
        return target

    if policy == "overwrite":
        return target
    if policy == "skip":
        return target  # caller will detect exists and skip

    # suffix policy
    stem, ext = _split_ext_preserve_case(filename)
    n = 2
    while True:
        candidate = dest_dir / f"{stem}__dup{n}{ext}"
        if not _case_insensitive_exists(dest_dir, candidate.name):
            return candidate
        n += 1

def pick_filename_from_response(res: requests.Response, url: str) -> str:
    """
    Prefer Content-Disposition filename; else derive from URL path.
    """
    cd = res.headers.get("Content-Disposition", "")
    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd, re.IGNORECASE)
    if m:
        return unquote(m.group(1))
    path = urlparse(url).path
    name = os.path.basename(path)
    return unquote(name) or "download.bin"

def _normalize_str_edf_filename(name: str) -> str:
    """
    SleepHQ-specific normalization: Only transform exactly 'STR.EDF' -> 'STR.edf'
    """
    return "STR.edf" if name == "STR.EDF" else name

def _parse_http_date(value: str) -> Optional[datetime]:
    """
    Parse an RFC 7231/1123 HTTP date string into an aware UTC datetime.
    """
    try:
        dt = parsedate_to_datetime(value)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def _datetime_to_filetime(dt_utc: datetime) -> wintypes.FILETIME:
    """
    Convert an aware UTC datetime to a Windows FILETIME (100‑ns intervals since 1601‑01‑01).
    """
    if dt_utc.tzinfo is None:
        dt_utc = dt_utc.replace(tzinfo=timezone.utc)
    else:
        dt_utc = dt_utc.astimezone(timezone.utc)

    # FILETIME = (Unix timestamp + 11644473600) * 10^7
    EPOCH_AS_FILETIME = 11644473600  # seconds between 1601-01-01 and 1970-01-01
    hundreds = int((dt_utc.timestamp() + EPOCH_AS_FILETIME) * 10**7)

    ft = wintypes.FILETIME()
    ft.dwLowDateTime = hundreds & 0xFFFFFFFF
    ft.dwHighDateTime = (hundreds >> 32) & 0xFFFFFFFF
    return ft

def _set_windows_creation_time(path: Path, dt: datetime, also_set_last_write: bool = False):
    """
    Set Windows creation time to 'dt' (UTC-aware).
    Optionally also set last write time to 'dt' for consistency.
    """
    FILE_WRITE_ATTRIBUTES = 0x0100
    OPEN_EXISTING = 3
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004

    CreateFileW = ctypes.windll.kernel32.CreateFileW
    SetFileTime = ctypes.windll.kernel32.SetFileTime
    CloseHandle = ctypes.windll.kernel32.CloseHandle

    CreateFileW.restype = wintypes.HANDLE
    CreateFileW.argtypes = [
        wintypes.LPCWSTR,  # lpFileName
        wintypes.DWORD,    # dwDesiredAccess
        wintypes.DWORD,    # dwShareMode
        wintypes.LPVOID,   # lpSecurityAttributes
        wintypes.DWORD,    # dwCreationDisposition
        wintypes.DWORD,    # dwFlagsAndAttributes
        wintypes.HANDLE,   # hTemplateFile
    ]

    SetFileTime.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.FILETIME),  # lpCreationTime
        ctypes.POINTER(wintypes.FILETIME),  # lpLastAccessTime
        ctypes.POINTER(wintypes.FILETIME),  # lpLastWriteTime
    ]
    SetFileTime.restype = wintypes.BOOL

    handle = CreateFileW(
        str(path),
        FILE_WRITE_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        0,
        None,
    )
    INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
    if handle == INVALID_HANDLE_VALUE:
        raise OSError("CreateFileW failed to open handle for writing attributes")

    try:
        ft = _datetime_to_filetime(dt)
        lpCreationTime = ctypes.byref(ft)
        lpAccessTime = None
        lpWriteTime = ctypes.byref(ft) if also_set_last_write else None

        ok = SetFileTime(handle, lpCreationTime, lpAccessTime, lpWriteTime)
        if not ok:
            raise OSError("SetFileTime failed")
    finally:
        CloseHandle(handle)

def _pick_best_timestamp(listing_dt: Optional[datetime], headers: Mapping[str, str]) -> Optional[datetime]:
    """
    Priority:
      1) listing_dt (assume local wall time; convert to UTC)
      2) Last-Modified header if sane (>= 2000 and not in the future)
    Returns an aware UTC datetime or None.
    """
    if listing_dt:
        try:
            # Convert naive local datetime -> epoch -> UTC aware
            ts = time.mktime(listing_dt.timetuple())
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except Exception:
            pass

    lm = headers.get("Last-Modified") or headers.get("last-modified")
    if lm:
        lm_dt = _parse_http_date(lm)
        if lm_dt:
            now_utc = datetime.now(timezone.utc) + timedelta(seconds=5)
            if lm_dt.year >= 2000 and lm_dt <= now_utc:
                return lm_dt

def _apply_timestamp(path: Path, chosen_dt_utc: Optional[datetime]):
    """
    Apply timestamps using chosen_dt_utc (aware UTC).
    Sets mtime/atime everywhere; on Windows, also sets creation time.
    """
    if not chosen_dt_utc:
        return
    ts = chosen_dt_utc.timestamp()
    try:
        os.utime(path, (ts, ts))
    except Exception as e:
        print(f"  [warn] could not set mtime/atime: {e}")

    if sys.platform.lower().startswith("win"):
        try:
            _set_windows_creation_time(path, chosen_dt_utc, also_set_last_write=False)
        except Exception as e:
            print(f"  [warn] could not set creation time: {e}")

def _normalize_href(el: Tag) -> Optional[str]:
    """
    Returns a single string href or None. BeautifulSoup can return href as str, list[str], or None.
    """
    href_val = el.get("href")
    if href_val is None:
        return None
    if isinstance(href_val, list):
        for item in href_val:
            if isinstance(item, str) and item.strip():
                return item
        return None
    if isinstance(href_val, str):
        href = href_val.strip()
        return href if href else None
    return None

def _extract_listing_dt_before_anchor(a: Tag) -> Optional[datetime]:
    """
    The listing shows: 'YYYY-MM-DD   HH:MM:SS   <size|<DIR>>   <a ...> name </a>'
    We take the text immediately before the <a> tag and regex out the date/time.
    """
    # Regex to capture date/time in the listing prefix, e.g., "2026-01-19   22:15:26"
    _dt_re = re.compile(r'(\d{4}-\d{2}-\d{2})\s+(\d{1,2}:\d{2}:\d{2})')

    prev_text = ""
    # Look for text in previous siblings (same line)
    for sib in a.previous_siblings:
        if isinstance(sib, NavigableString):
            prev_text = str(sib)
            break

    if not prev_text:
        # Fallback: try the parent node's text
        parent_text = a.parent.get_text(" ", strip=True) if a.parent else ""
        prev_text = parent_text

    m = _dt_re.search(prev_text)
    if not m:
        return None

    try:
        # Hours may be one or two digits (' 3:49:03' vs '22:15:26')
        dt = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
        return dt  # naive local time
    except ValueError:
        return None

def list_directory(session: requests.Session, list_url: str, verbose: bool = False):
    """
    Returns (files, dirs)
      files: [{"name": str, "href": str, "dt": Optional[datetime]}]
      dirs:  [{"name": str, "href": str}]
    Detection:
      - '/download?' => file
      - '?dir='      => directory
    """
    r = session.get(list_url, timeout=20)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")

    files, dirs = [], []
    do_not_copy = {
        "../", "/", "Back To Photo", "ezshare.cfg", "System Volume Information", "back"
    }

    for a in soup.select("a[href]"):
        name = a.get_text(strip=True)
        href_rel = _normalize_href(a)
        if not href_rel:
            continue
        href = urljoin(list_url, href_rel)

        if name in do_not_copy:
            if verbose:
                print(f"{name} matches do_not_copy, excluding")
            continue

        if "/download?" in href:
            listing_dt = _extract_listing_dt_before_anchor(a)
            if verbose:
                print(f"Appending {name},{href} to files (dt={listing_dt})")
            files.append({"name": name.rstrip("/"), "href": href, "dt": listing_dt})

        elif "?dir=" in href:
            if verbose:
                print(f"Appending {name},{href} to dirs")
            dirs.append({"name": name.rstrip("/"), "href": href})

        else:
            if verbose:
                print(f"unknown type {name},{href}. Skipping")

    return files, dirs

def download_file(
    session: requests.Session,
    file_url: str,
    dest_dir: Path,
    overwrite: bool = False,
    case_collision_policy: str = "suffix",
    dest_filename: Optional[str] = None,
    listing_dt: Optional[datetime] = None,
    verbose: bool = False,
):
    """
    Download a file URL (expected to be '/download?').
    - Preserves filename case (prefer dest_filename if provided).
    - Applies timestamp from listing (preferred) or sane Last-Modified.
    - Handles Windows case-insensitive collisions by policy.
    """
    with session.get(file_url, stream=True, timeout=60) as r:
        r.raise_for_status()

        ctype = r.headers.get("Content-Type", "")
        if "text/html" in (ctype or "").lower():
            if verbose:
                print(f"  [skip] HTML/listing detected (not a file): {file_url}")
            return

        # Filename precedence:
        # 1) Provided by caller (from listing) — preserves exact case
        # 2) Content-Disposition / URL path — fallback
        fname = dest_filename or pick_filename_from_response(r, file_url)

        # SleepHQ-specific rule: STR.EDF -> STR.edf
        fname = _normalize_str_edf_filename(fname)

        ensure_dir(dest_dir)
        out_path = _resolve_case_collision(
            dest_dir, fname, "overwrite" if overwrite else case_collision_policy
        )

        if (out_path.exists() and not overwrite) and case_collision_policy == "skip":
            if verbose:
                print(f"  [skip] exists (case-insensitive match): {out_path}")
            return

        if out_path.name != fname and not overwrite and verbose:
            print(f"  [info] name collision (case-insensitive). Saving as: {out_path.name}")

        if verbose:
            print(f"  [save] {out_path}")

        with open(out_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 64):
                if chunk:
                    f.write(chunk)

        # Prefer listing_dt; if missing, use sane Last-Modified; else leave OS time
        chosen = _pick_best_timestamp(listing_dt, r.headers)
        if verbose:
            print(f"  [ts] listing_dt={listing_dt}   Last-Modified={r.headers.get('Last-Modified')}   chosen={chosen}")
        _apply_timestamp(out_path, chosen)

        # Optional: adjust visible case on Windows if only-casing changed
        # _force_display_case_on_windows(dest_dir, out_path.name)

def process_root(s: requests.Session, path: str, dir: Path, overwrite: bool = False, verbose: bool = False):
    print(f"\n[Root] Listing {path}")
    root_files, root_dirs = list_directory(s, path, verbose=verbose)
    print(f"     found: {len(root_files)} files at root; {len(root_dirs)} dirs (dirs ignored here)")
    for file in root_files:
        if verbose:
            print(f"The file name to be downloaded is {file['name']}")
        download_file(
            s,
            file["href"],
            dir,
            overwrite=overwrite,
            dest_filename=file["name"],
            listing_dt=file.get("dt"),
            verbose=verbose,
        )

def process_settings(s: requests.Session, path: str, dir: Path, overwrite: bool = False, verbose: bool = False):
    print(f"\n[SETTINGS] Listing {path}")
    settings_files, settings_dirs = list_directory(s, path, verbose=verbose)
    print(f"     found: {len(settings_files)} files in SETTINGS; {len(settings_dirs)} dirs (dirs ignored here)")
    for file in settings_files:
        download_file(
            s,
            file["href"],
            dir,
            dest_filename=file["name"],
            listing_dt=file.get("dt"),
            overwrite=overwrite,
            verbose=verbose,
        )

def process_datalog(
    s: requests.Session,
    path: str,
    dir: Path,
    days: int,
    overwrite: bool = False,
    verbose: bool = False,
):
    """
    Fetch files from the most recent `days` DATALOG/YYYYMMDD folders and save under:
        <dir>/<YYYYMMDD>/<files>
    """
    print(f"\n[DATALOG] Listing {path}")
    _, datalog_dirs = list_directory(s, path, verbose=verbose)
    dated_dirs = [d for d in datalog_dirs if is_yyyymmdd(d["name"])]
    dated_dirs.sort(key=lambda d: d["name"], reverse=True)

    selected = dated_dirs[:days]
    if verbose:
        print(f" using most recent {len(selected)} dated folders: {[d['name'] for d in selected]}")

    for d in selected:
        ymd = d["name"]  # e.g., '20260216'
        print(f"\n[DATALOG]/{ymd} Listing {d['href']}")
        files, subdirs = list_directory(s, d["href"], verbose=verbose)
        if verbose:
            print(f"     found: {len(files)} files; {len(subdirs)} nested dirs (ignored)")

        # Ensure subfolder locally: <dir>/<YYYYMMDD>/
        dated_dir = dir / ymd
        ensure_dir(dated_dir)

        for file in files:
            download_file(
                s,
                file["href"],
                dated_dir,
                overwrite=overwrite,
                dest_filename=file["name"],
                listing_dt=file.get("dt"),
                verbose=verbose,
            )

def runnner():
    '''(ultimately get the args from parse args and then call run_ezshare directly)'''
    config = load_config("./config.yaml")
    sd_profile   = config["ezshare"]["card_ssid"]
    home_profile = config["ezshare"]["home_ssid"]
    sd_ip_addr   = config["ezshare"]["ip_address"]
    root_dir     = config["ezshare"]["dir"]
    save_dir      = config["global"]["save_to_path"]
    overwrite    = bool(config["ezshare"]["overwrite"])
    n_days       = int(config["ezshare"]["number_of_days"])
    verbose      = bool(config["global"].get("verbose", False))

    run_ezshare(sd_profile,
                home_profile,
                sd_ip_addr,
                root_dir,
                save_dir,
                overwrite,
                n_days,
                verbose)

def run_ezshare(sd_profile : str, 
                home_profile : str, 
                sd_ip_addr : str = '192.168.4.1', 
                root_dir : str = 'dir=A:', 
                save_dir : str = 'LatestCPAP',
                overwrite : bool = True,
                n_days : int = 1,
                verbose : bool = False) -> None:
    """
    run_ezshare is the import-callable entry point to this script, taking parameters
    to allow for successful execution. To make this multiplatform, it will need a platform
    parameter adding and then methods in this script to join wifi networks from
    *nix and Darwin/macOS. At that point, sd_profile and home_profile will need to be updated to dict()
    for key and value pairs, and the Windows method updated to just use the k/v for password field 
    
    :param str sd_profile: The Windows name of the SD Card wifi profile/SSID (eg 'ez share')
    :param str home_profile: The Windows name of your home wifi profile/SSID (eg 'Netgear', 'FBWifi')
    :param str sd_ip_addr: The IP address of the SD Card (default is 192.168.4.1)
    :param str root_dir: The Root directory the SD Card uses to list files (default 'dir=A:')
    :param str save_dir: Which subdirectory should hold the CPAP machine data copy (default LatestCPAP)
    :param bool overwrite: Overwrite existing folders?
    :param int n_days: Number of days to copy (if this copy occurs before the device has created tonight's folder, 1 will get last night)
    :param bool verbose: verbose output with additional detail on list folder and download file operations
    :return:
    :rtype: None
    """
    # Build the session variables
    sd_url = f"http://{sd_ip_addr}/dir?"
    
       # Prepare local output dirs
    base_out    = script_dir(verbose) / save_dir
    out_root    = base_out
    out_settings= base_out / "SETTINGS"
    out_datalog = base_out / "DATALOG"

    # Listing URLs
    root_list_url     = sd_url + root_dir
    settings_list_url = sd_url + root_dir + "/SETTINGS"
    datalog_list_url  = sd_url + root_dir + "/DATALOG"

    # Session
    s = requests.Session()
    s.headers.update({"User-Agent": "breathe-easy_ezshare_getter/1.0"})

    # Join the sd card wifi
    try:
        connect_wifi_windows.connect_wifi(sd_profile,20,3)
    except ConnectionError as conn_err:
        print(f"❌ {conn_err}")
        sys.exit("Unable to connect to the SD Card Network. Aborting")

    # Iterate through the known folders needed for Resmed S10/11 device data imports 
    # getting lists of files and folders found. The "process..." methods take care of the high level
    # logic, and leave the implementation of the actual list and download to genericized methods to allow for
    # code reuse
   
    print("Processing Root, SETTINGS, and DATALOG directories, downloading corresponding files")
    process_root(s, root_list_url, out_root, overwrite, verbose)
    process_settings(s, settings_list_url, out_settings, overwrite, verbose)
    process_datalog(s, datalog_list_url, out_datalog, n_days, overwrite, verbose)

    # Copy operations finised. I may need to do some code hardening as I have had failed transports before. 
    print(f"Completed copy operations. Files saved under {base_out}")

    # Reconnect to home Wi-Fi. This probably needs to be a "Finally" under a try/except so
    # that local connectivity is always restored after copy either succeeds or errors. 

    print(f"Joining {home_profile}")
    try:
        connect_wifi_windows.connect_wifi(home_profile,20,3)
    except ConnectionError as conn_err:
        print(f"❌ {conn_err}")
        sys.exit("Unable to connect to the home network. Aborting")
    
    time.sleep(2)

def main():
    args = parse_args()  # using config.yaml via runner()
    print(f"Calling run_ezshare with {args}")
    run_ezshare(args.sd_ssid,
                args.home_ssid,
                args.ip_address,
                args.root_dir,
                args.save_to,
                args.overwrite,
                int(args.n_days),
                args.verbose)



if __name__ == "__main__":
    main()
