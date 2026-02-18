"""ezshare_getter.py facilitates getting the ResMed 9/10/11 series files from a WiFi enabled (ezshare)
card and getting the most recent (N) days worth of data. This can be used standalone, or as an import module
that will enter at the runner function

Author: BChap
Last Modified: 20260217
"""

import argparse
import os
import re
import requests
import sys
import subprocess
import time

from bs4 import BeautifulSoup,Tag
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse, unquote
from yaml import safe_load

def load_config(config:str)->dict:
    """
    Loads the user provided configuration file and returns it as a dictionary
    
    :param str config: The config file name (assuming in current working directory)
    :return: Dictionary of the configuration Parameters
    :rtype: dict
    """
    with open(config, "r") as f:
        return safe_load(f)

def ensure_dir(path: Path):
    path.mkdir(parents=True,exist_ok=True)

def connect_windows_wifi(profile)->None:
    """Connect to a Wi-Fi network on Windows using the specififed profile
    :param str profile: The name of the Wi-Fi (netsh wlan show profiles) to connect to
    :rtype: none
    """

    subprocess.run(f"netsh wlan connect name={profile}")
    
    '''
    try:
        result = subprocess.run("netsh wlan connect name={profile}", 
                                capture_output=True, text = True, check=True
        )
        print(result.stdout.strip())
    except subprocess.CalledProcessError as error:
        print(f"{error} - an error occrred while trying to connect to the wi-fi network {profile}")
    '''    

def _split_ext_preserve_case(filename: str):
    """
    Split a filename into (stem, ext) preserving case.
    Example: 'Data.LOG' -> ('Data', '.LOG'), '.env' -> ('.env', '')
    """
    # Use rsplit only on the last dot; handle dotfiles
    if filename.startswith(".") and filename.count(".") == 1:
        return filename, ""
    stem, ext = os.path.splitext(filename)
    return stem, ext

def _case_insensitive_exists(path: Path, filename: str) -> bool:
    """
    Returns True if a file exists in dest dir with same name ignoring case.
    On non-Windows systems, case-sensitive compare is effectively same as normal exists().
    """
    if not path.exists():
        return False
    # If exact path exists, it's a collision regardless of OS
    if (path / filename).exists():
        return True
    # On Windows or case-insensitive FS, scan directory
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
      - 'skip'       -> return a path that signals skipping by pointing to an existing file
      - 'suffix'     -> append '__dupN' before extension until no case-insensitive collision
      - 'overwrite'  -> return the original path
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

def download_file(
    session: requests.Session,
    file_url: str,
    dest_dir: Path,
    overwrite: bool = False,
    case_collision_policy: str = "suffix",
    dest_filename: Optional[str] = None,
    verbose : bool = False
):
    with session.get(file_url, stream=True, timeout=60) as r:
        r.raise_for_status()

        ctype = r.headers.get("Content-Type", "")
        if "text/html" in (ctype or "").lower():
            print(f"  [skip] HTML/listing detected (not a file): {file_url}")
            return

        # 1) If caller provided a name (from listing), use it.
        # 2) Else fallback to Content-Disposition or URL path.
        fname = (
            dest_filename
            or pick_filename_from_response(r, file_url)
        )

        ensure_dir(dest_dir)
        out_path = _resolve_case_collision(dest_dir, fname, "overwrite" if overwrite else case_collision_policy)
        if (out_path.exists() and not overwrite) and case_collision_policy == "skip":
            if verbose:
                print(f"  [skip] exists (case-insensitive match): {out_path}")
            return

        if out_path.name != fname and not overwrite:
            if verbose:
                print(f"  [info] name collision (case-insensitive). Saving as: {out_path.name}")
        print(f"  [save] {out_path}")
        with open(out_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=1024 * 64):
                if chunk:
                    f.write(chunk)

def is_yyyymmdd(name: str)->bool:
    try:
        datetime.strptime(name, "%Y%m%d")
        return True
    except ValueError:
        return False

def _normalize_href(el: Tag) -> Optional[str]:

    """
    Returns a single string href or None.
    BeautifulSoup can return href as str, list[str], or None.
    """
    href_val = el.get("href")
    if href_val is None:
        return None
    if isinstance(href_val, list):
        # Pick the first non-empty string
        for item in href_val:
            if isinstance(item, str) and item.strip():
                return item
        return None
    if isinstance(href_val, str):
        href = href_val.strip()
        return href if href else None
    # Unknown type; ignore
    return None

def list_directory(session: requests.Session, list_url: str, verbose : bool = False):
    """
    Returns (files, directories), each as a list of dicts:
    {"name": <display text>,"href": <absolute url>}
    Detection Method:
      - '/download?' => file
      - '?dir=' => dir
   
    :param session: session
    :type session: requests.session
    :param list_url: directory to look into
    :type list_url: str
    
    :returns: 2 list of dicts, files and directories
    :rtype: tuple
    """
    do_not_copy = [
        "../",
        "/",
        "Back To Photo",
        "ezshare.cfg",  # full filename
        "System Volume Information",
        "back", # EZ Share has a "back" link to previous folder vs ../
    ]
    print(session)
    r = session.get(list_url,timeout=10)
    r.raise_for_status()
    soup = BeautifulSoup(r.text,"html.parser")

    files, dirs = [],[]

    for a in soup.select("a[href]"):
        text = a.get_text(strip=True)
        href_rel = _normalize_href(a)
        if not href_rel:
            continue
        href = urljoin(list_url, href_rel)

        # skip any desired files/backlinks/useless shit
        if text in do_not_copy:
            if verbose:
                print(f"{text} matches against do_not_copy, excluding")
            continue
        if "/download?" in href:
            if verbose:
                print(f"Appending {text},{href} to files")
            files.append({"name": text.rstrip("/"), "href": href})
        elif "?dir" in href:
            if verbose:
                print(f"Appending {text},{href} to dirs")
            dirs.append({"name": text.rstrip("/"), "href": href})
        else:
            # unknown link type: ignore safely
            if verbose:
                print(f"unknown type {text},{href}. Skipping")
            continue
    return files, dirs

def parse_args()->argparse.Namespace:
    '''
    parse_args uses argparse to parse command line arguments for the SleepHQ CPAP data upload script.
    
    :return Namespace: An argparse.Namespace object containing the parsed command line arguments:
    '''
    p = argparse.ArgumentParser(
        description="Get ResMed S10/11 Data from an EZSh@re Wifi SD Card"
    )
    p.add_argument("--ip_address", required=True, default='192.168.4.1', help='IP address of EZShare Card')
    p.add_argument("--root_dir", required=True, default="A:")
    p.add_argument("--sd_ssid", required=True, default="ezshare", help='EZShare wifi profile name')
    p.add_argument("--save_to", required=True, default="latestcpap", help='CPAP Data Directory')
    p.add_argument("--overwrite", required=False, default = False, help='overwrite existing files?')
    p.add_argument("--home_ssid", required=True, help="Home wifi profile name")
    return p.parse_args()

def pick_filename_from_response(res: requests.Response, url: str)->str:
    """
    Prefer Content-Disposition Filename, else derive from the URL path.
    
    :param requests.Response res: holds the request.Response
    :param str url: The URL of the file
    :return: The filename to use
    :rtype: str
    """
    cd = res.headers.get("Content-Disposition","")
    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd, re.IGNORECASE)
    if m:
        return unquote(m.group(1))
    path = urlparse(url).path
    name = os.path.basename(path)
    return unquote(name) or "download.bin"

def process_datalog(s:requests.Session, path:str,dir:Path, days: int, overwrite : bool = False, verbose : bool = False):
    print(f"\n[DATALOG] Listing {path}")
    _, datalog_dirs = list_directory(s, path,verbose=verbose)
    dated_dirs = [d for d in datalog_dirs if is_yyyymmdd(d["name"])]
    dated_dirs.sort(key = lambda d: d["name"], reverse = True)
    
    selected = dated_dirs[: days]
    if verbose:
        print(f" using most recent {len(selected)} dated folders: {[d['name'] for d in selected]}")

    for d in selected:
        print(f"\n[DATALOG]/{d['name']} Listing {d['href']}")
        files, subdirs = list_directory(s, d['href'])
        print(f"     found: {len(files)} files; {len(subdirs)} nested dirs (ignored)")
        for file in files:
            download_file(s,file["href"], dir, overwrite = overwrite,dest_filename=d['name'],verbose=verbose)

def process_root(s:requests.Session,path:str,dir:Path,overwrite : bool = False, verbose : bool = False):
    print(f"\n[Root] Listing {path}")
    root_files, root_dirs = list_directory(s, path)
    print(f"     found: {len(root_files)} files at root; {len(root_dirs)} dirs (dirs ignored here)")
    for file in root_files:
        print(f"The file name to be downloaded is {file["name"]}")
        download_file(s,file["href"], dir, overwrite = overwrite, dest_filename=file["name"],verbose=verbose)

def process_settings(s:requests.Session,path:str,dir:Path,overwrite : bool = False, verbose : bool = False):
    
    print(f"\n[SETTINGS] Listing {path}")
    settings_files, settings_dirs = list_directory(s, path)
    print(f"     found: {len(settings_files)} files in SETTINGS; {len(settings_dirs)} dirs (dirs ignored here)")
    for file in settings_files:
        download_file(s,file["href"], dir, dest_filename=file["name"],overwrite = overwrite,verbose=verbose)

def script_dir(verbose:bool = False)->Path:
    try:
        if verbose:
            print(Path(__file__).resolve().parent)
        return Path(__file__).resolve().parent
    except NameError:
        return Path.cwd()

def runner():
    """
    Runner is the callable module to replace main when called via an import 
    """
    config = load_config('./config.yaml')
    sd_profile = config['ezshare']['card_ssid']
    home_profile = config['ezshare']['home_ssid']
    sd_ip_addr = config['ezshare']['ip_address']
    root_dir = config['ezshare']['dir']
    savedir = config['global']['save_to_path']
    overwrite = config['ezshare']['overwrite']
    n_days = config['ezshare']['number_of_days']
    verbose = config['global']['verbose']
    
    # extrapolated variables
    sd_url = f"http://{sd_ip_addr}/dir?"

    # associate with the EZ Share SD card wifi network
    print(f"Joining {sd_profile}")
    connect_windows_wifi(sd_profile)
    time.sleep(2)
    
    # create the variables for the various path locations

    base_out = script_dir(verbose) / savedir
    out_root = base_out
    out_settings = base_out / "SETTINGS"
    out_datalog = base_out / "DATALOG"

    # listing URLS
    
    root_list_url = sd_url + root_dir
    settings_list_url = sd_url + root_dir + "/SETTINGS"
    datalog_list_url = sd_url + root_dir + "/DATALOG"

    # Create Requests Session
    s = requests.Session()
    s.headers.update({"User-Agent":"breathe-easy_ezshare_getter/1.0"})

    # Get all the desired files
    print("Processing Root, SETTINGS, and DATALOG directories, downloading corresponding files")
    # starting with root level
    process_root(s,root_list_url,out_root,overwrite,verbose)
    # and now the SETTINGS folder
    process_settings(s,settings_list_url,out_settings,overwrite,verbose)
    # and finally, the DATALOG (N days)
    process_datalog(s,datalog_list_url,out_datalog,n_days,overwrite,verbose)

    print(f"Completed copy operations. Files saved under {base_out}")
    print(f"Joining {config['ezshare']['home_ssid']}")
    connect_windows_wifi(home_profile)
    time.sleep(2)

def main():
    # args = parse_args()
    runner()

if __name__ == "__main__":
    main()