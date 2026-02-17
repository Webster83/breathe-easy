"""ezshare_getter.py facilitates getting the ResMed 9/10/11 series files from a WiFi enabled (ezshare)
card and getting the most recent (N) days worth of data. This can be used standalone, or as an import module
that will enter at the runner function

Author: BChap
Last Modified: 20260217
"""

from email.mime import base
import os
import re
import requests
import sys
import subprocess
import time

from bs4 import BeautifulSoup
from datetime import datetime
from pathlib import Path
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

def download_file(session:requests.Session, file_url:str, dest_dir: Path, overwrite: bool = False):
    """
    Downloads a file URL (expected to be /download?). Skips HTML responses 
    and writes to dest_dir 
    
    :param session: Description
    :type session: requests.Session
    :param file_url: Description
    :type file_url: str
    :param dest_dir: Description
    :type dest_dir: Path
    :param Overwrite: Description
    :type Overwrite: bool
    """

    with session.get(file_url, stream = True, timeout=60) as r:
        r.raise_for_status()

        ctype = r.headers.get("Conent-Type","")
        if "text/html" in ctype.lower():
            print(f"  [Skip] HTML/listing dectected (not a file): {file_url}")
            return

        fname = pick_filename_from_response(r, file_url)
        ensure_dir(dest_dir)
        out_path = dest_dir/fname

        if not overwrite and out_path.exists():
            print(f" [skip] exists {out_path}")
        
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

def list_directory(session: requests.session, list_url: str):
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
    r = session.get(list_url,timeout=10)
    r.raise_for_status()
    soup = BeautifulSoup(r.text,"html.parser")

    files, dirs = [],[]

    for a in soup.select("a[href]"):
        text = a.get_text(strip=True)
        href = urljoin(list_url, a["href"])

        # skip any desired files/backlinks/useless shit
        if text in do_not_copy:
            print(f"{text} matches against do_not_copy, excluding")
            continue
        if "/download?" in href:
            print(f"Appending {text},{href} to files")
            files.append({"name": text.rstrip("/"), "href": href})
        elif "?dir" in href:
            print(f"Appending {text},{href} to dirs")
            dirs.append({"name": text.rstrip("/"), "href": href})
        else:
            # unknown link type: ignore safely
            print(f"unknown type {text},{href}. Skipping")
    return files, dirs


    try:
        datetime.strptime(name, "%Y%m%d")
        return True
    except ValueError:
        return False

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

def script_dir()->Path:
    try:
        return Path(__file__).resolve().parent
    except NameError:
        return Path.cwd()
    
def zzz_list_directory(base_url, dirpath):
    do_not_copy = [
        "../",
        "/",
        "Back To Photo",
        "ezshare.cfg",  # full filename
        "System Volume Information",
        "back", # EZ Share has a "back" link to previous folder vs ../
    ]

    url = base_url + dirpath
    r = requests.get(url, timeout=10)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")
    files = []

    for link in soup.find_all("a"):
        # Normalize: strip whitespace, replace non-breaking spaces, remove zero-width spaces
        name = link.get_text().replace("\xa0", " ").replace("\u200b", "").strip()

        # Debug: show hidden characters
        print(f"Analyzing {repr(name)} (length: {len(name)})")

        if name in do_not_copy:
            print(f"Excluded {repr(name)} (exact match in do_not_copy)")
            continue

        print(f"{repr(name)} is acceptable, appending")
        files.append(name)

    print("Final file list:", files)
    return files

def zzz_download_file(savedir,base_url,dirpath,filename)->None:
    try: 
        url = f"{base_url}{dirpath}/{filename}"
        print(f"Downloading {url}")
        r = requests.get(url,timeout=10)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        save_folder = os.path.join(script_dir, savedir)
        os.makedirs(save_folder, exist_ok=True)
        safe_filename = filename.replace("/", "_")
        save_path = os.path.join(save_folder, safe_filename)
        with open(save_path, "wb") as f:
            f.write(r.content)
        print(f"Saved to: {save_path}")

    except requests.exceptions.RequestException as e:
        print(f"Download failed: {e}")
    except OSError as e:
        print(f"File save error: {e}")    

def runner():
    """
    Runner is the callable module to replace main when called via an import 
    """
    config = load_config('./config.yaml')
    sd_profile = config['wifi_sd']['profile']
    home_profile = config['home_wifi']['profile']
    sd_ip_addr = config['wifi_sd']['ip_address']
    sd_url = f"http://{sd_ip_addr}/dir?dir="
    root_dir = config['wifi_sd']['root_dir_string']
    savedir = config['wifi_sd']['local_dir']
    overwrite = True
    n_days=3

    # associate with the EZ Share SD card wifi network
    connect_windows_wifi(sd_profile)
    time.sleep(2)
    
    # Can we ping it?
    subprocess.run("ping 192.168.4.1",capture_output=True, text=True, check=True)
    
    # ok, so we can connect to the card, so now we can just write the logic for things
    
    base_out = script_dir() / savedir
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

    # Get all the latest files

    # starting with root level
    print(f"\n[Root] Listing {root_list_url}")
    root_files, root_dirs = list_directory(s, root_list_url)
    print(f"     found: {len(root_files)} files at root; {len(root_dirs)} dirs (dirs ignored here)")
    for file in root_files:
        download_file(s,file["href"], out_root, overwrite = overwrite)

    # and now the SETTINGS folder
    print(f"\n[SETTINGS] Listing {settings_list_url}")
    settings_files, settings_dirs = list_directory(s, settings_list_url)
    print(f"     found: {len(settings_files)} files at root; {len(settings_dirs)} dirs (dirs ignored here)")
    for file in settings_files:
        download_file(s,file["href"], out_settings, overwrite = overwrite)

    # and finally, the DATALOG (N days)
    print(f"\n[DATALOG] Listing {datalog_list_url}")
    _, datalog_dirs = list_directory(s, datalog_list_url)
    dated_dirs = [d for d in datalog_dirs if is_yyyymmdd(d["name"])]
    dated_dirs.sort(key = lambda d: d["name"], reverse = True)
    
    selected = dated_dirs[: n_days]
    print(f" using most recent {len(selected)} dated folders: {[d['name'] for d in selected]}")

    for d in selected:
        print(f"\n[DATALOG]/{d['name']} Listing {d['href']}")
        files, subdirs = list_directory(s, d['href'])
        print(f"     found: {len(files)} files; {len(subdirs)} nested dirs (ignored)")
        for file in files:
            download_file(s,file["href"], out_datalog, overwrite = overwrite)

    print(f"Completed copy operations. Files saved under {base_out}")
            
    print(f"Joining {config['home_wifi']['profile']}")
    connect_windows_wifi(home_profile)
    time.sleep(1)
    subprocess.run("ping 192.168.11.0",capture_output=True, text=True, check=True)

def main():
    runner()

if __name__ == "__main__":
    main()