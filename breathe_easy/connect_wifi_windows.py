
"""
connect_wifi_windows.py
author: BChap
Latest Revision Date: 20260222

Forces a Wi‑Fi rescan on Windows via wlanapi.dll (WlanScan) and connects to a saved profile.
- Supports two readback modes:
    * 'netsh' (default): read results from `netsh wlan show networks mode=Bssid`
    * 'api': read results from WlanGetAvailableNetworkList (no netsh dependency)
- Accepts interface hint, separate SSID vs profile name, and timing controls.

Notes:
- On recent Windows 11 builds, Wi‑Fi scan / BSSID access may require Location permission.
- This script must run on Windows.
"""

from __future__ import annotations

import argparse
import ctypes  # moved to top for pylint C0413
from ctypes import wintypes  # moved to top for pylint C0413
import platform
import subprocess
import sys
import time
import logging
from typing import Optional, Tuple, List

logger = logging.getLogger(__name__)

# =========================
# Shell / OS helpers
# =========================

def run_command(cmd: List[str]) -> Tuple[str, str, int]:
    """Run a command and return (stdout, stderr, returncode)."""
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def ensure_windows() -> None:
    """Exit if not on Windows."""
    if platform.system().lower() != "windows":
        print("❌ This script requires Windows.")
        sys.exit(2)


# =========================
# Native Wi‑Fi (wlanapi.dll) wrapper via ctypes
# =========================

ERROR_SUCCESS = 0

# --- Structures (selected) ---

class GUID(ctypes.Structure):  # pylint: disable=invalid-name
    """Win32 GUID structure used by wlanapi."""
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WLAN_INTERFACE_INFO(ctypes.Structure):  # pylint: disable=invalid-name
    """Win32 WLAN_INTERFACE_INFO structure."""
    _fields_ = [
        ("InterfaceGuid", GUID),
        ("strInterfaceDescription", wintypes.WCHAR * 256),
        ("isState", wintypes.DWORD),  # WLAN_INTERFACE_STATE (enum)
    ]


class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):  # pylint: disable=invalid-name
    """
    Layout (from wlanapi.h):
      DWORD dwNumberOfItems;
      DWORD dwIndex;
      WLAN_INTERFACE_INFO InterfaceInfo[1];  # flexible array
    """
    _fields_ = [
        ("dwNumberOfItems", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
    ]


class DOT11_SSID(ctypes.Structure):  # pylint: disable=invalid-name
    """Win32 DOT11_SSID structure (SSID bytes)."""
    _fields_ = [
        ("uSSIDLength", wintypes.ULONG),
        ("ucSSID", ctypes.c_ubyte * 32),
    ]


class WLAN_AVAILABLE_NETWORK(ctypes.Structure):  # pylint: disable=invalid-name
    """Win32 WLAN_AVAILABLE_NETWORK structure."""
    _fields_ = [
        ("strProfileName", wintypes.WCHAR * 256),
        ("dot11Ssid", DOT11_SSID),
        ("dot11BssType", wintypes.DWORD),
        ("uNumberOfBssids", wintypes.ULONG),
        ("bNetworkConnectable", wintypes.BOOL),
        ("wlanNotConnectableReason", wintypes.DWORD),
        ("uNumberOfPhyTypes", wintypes.ULONG),
        ("dot11PhyTypes", wintypes.DWORD * 8),
        ("bMorePhyTypes", wintypes.BOOL),
        ("wlanSignalQuality", wintypes.ULONG),
        ("bSecurityEnabled", wintypes.BOOL),
        ("dot11DefaultAuthAlgorithm", wintypes.DWORD),
        ("dot11DefaultCipherAlgorithm", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("dwReserved", wintypes.DWORD),
    ]


class WLAN_AVAILABLE_NETWORK_LIST(ctypes.Structure):  # pylint: disable=invalid-name
    """Header for variable‑length list of WLAN_AVAILABLE_NETWORK."""
    _fields_ = [
        ("dwNumberOfItems", wintypes.DWORD),
        ("dwIndex", wintypes.DWORD),
        ("Network", WLAN_AVAILABLE_NETWORK * 1),  # flexible array
    ]


# --- Load DLL and declare prototypes ---

_wlan = ctypes.WinDLL("wlanapi.dll")

# DWORD WlanOpenHandle(DWORD, PVOID, PDWORD, PHANDLE);
_wlan.WlanOpenHandle.argtypes = [
    wintypes.DWORD, wintypes.LPVOID,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.HANDLE)
]
_wlan.WlanOpenHandle.restype = wintypes.DWORD

# DWORD WlanCloseHandle(HANDLE, PVOID);
_wlan.WlanCloseHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
_wlan.WlanCloseHandle.restype = wintypes.DWORD

# DWORD WlanEnumInterfaces(HANDLE, PVOID, PWLAN_INTERFACE_INFO_LIST*);
_wlan.WlanEnumInterfaces.argtypes = [
    wintypes.HANDLE, wintypes.LPVOID, ctypes.POINTER(ctypes.c_void_p)
]
_wlan.WlanEnumInterfaces.restype = wintypes.DWORD

# VOID WlanFreeMemory(PVOID);
_wlan.WlanFreeMemory.argtypes = [wintypes.LPVOID]
_wlan.WlanFreeMemory.restype = None

# DWORD WlanScan(HANDLE, const GUID*, const PDOT11_SSID, const PWLAN_RAW_DATA, PVOID);
_wlan.WlanScan.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(GUID),
    wintypes.LPVOID, wintypes.LPVOID, wintypes.LPVOID
]
_wlan.WlanScan.restype = wintypes.DWORD

# DWORD WlanGetAvailableNetworkList(HANDLE, const GUID*, DWORD, PVOID,
#                                   PWLAN_AVAILABLE_NETWORK_LIST*);
_wlan.WlanGetAvailableNetworkList.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(GUID),
    wintypes.DWORD, wintypes.LPVOID, ctypes.POINTER(ctypes.c_void_p)
]
_wlan.WlanGetAvailableNetworkList.restype = wintypes.DWORD


# --- Native Wi‑Fi helpers ---

def _open_wlan() -> wintypes.HANDLE:
    """Open a Native Wi‑Fi client handle."""
    negotiated = wintypes.DWORD()
    h_client = wintypes.HANDLE()
    rc = _wlan.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(h_client))
    if rc != ERROR_SUCCESS:
        logging.error("Failed to open wlan (_open_wlan)")
        raise RuntimeError(f"WlanOpenHandle rc={rc}")
    return h_client


def _close_wlan(h_client: wintypes.HANDLE) -> None:
    """Close the Native Wi‑Fi client handle."""
    _wlan.WlanCloseHandle(h_client, None)


def _get_wlan_interfaces(h_client: wintypes.HANDLE) -> List[WLAN_INTERFACE_INFO]:
    """
    Return WLAN_INTERFACE_INFO objects by reinterpreting the variable-length
    WLAN_INTERFACE_INFO_LIST returned by WlanEnumInterfaces.
    """
    pp_list = ctypes.c_void_p()
    rc = _wlan.WlanEnumInterfaces(h_client, None, ctypes.byref(pp_list))
    if rc != ERROR_SUCCESS:
        raise RuntimeError(f"WlanEnumInterfaces rc={rc}")

    if pp_list.value is None:
        _wlan.WlanFreeMemory(pp_list)
        raise RuntimeError("WlanEnumInterfaces returned a null pointer")

    try:
        list_ptr = ctypes.cast(pp_list, ctypes.POINTER(WLAN_INTERFACE_INFO_LIST))
        header = list_ptr.contents
        count = int(header.dwNumberOfItems)

        # Address math: start of struct + (sizeof(header with 1) - sizeof(one elem))
        base_addr = ctypes.addressof(header)
        offset = (ctypes.sizeof(WLAN_INTERFACE_INFO_LIST)
                  - ctypes.sizeof(WLAN_INTERFACE_INFO))
        first_elem_addr = base_addr + offset

        array_type = WLAN_INTERFACE_INFO * count
        array_ptr = ctypes.cast(first_elem_addr, ctypes.POINTER(array_type))
        return list(array_ptr.contents)
    finally:
        _wlan.WlanFreeMemory(pp_list)


def _choose_interface(
    interfaces: List[WLAN_INTERFACE_INFO],
    interface_hint: Optional[str]
) -> WLAN_INTERFACE_INFO:
    """Pick an interface matching the hint (substring), else return the first."""
    if not interfaces:
        raise RuntimeError("No WLAN interfaces were found.")
    if interface_hint:
        hint = interface_hint.lower()
        for iface in interfaces:
            if hint in iface.strInterfaceDescription.lower():
                return iface
    return interfaces[0]


def force_scan_nativewifi(
    h_client: wintypes.HANDLE,
    iface: WLAN_INTERFACE_INFO
) -> None:
    """
    Force an active Wi‑Fi scan on the specified interface.
    Raises RuntimeError on failure.
    """
    rc = _wlan.WlanScan(h_client, ctypes.byref(iface.InterfaceGuid), None, None, None)
    if rc != ERROR_SUCCESS:
        raise RuntimeError(f"WlanScan rc={rc}")



def _ssid_bytes_to_str(ssid: DOT11_SSID) -> str:
    """Decode DOT11_SSID to Python string, tolerating non‑UTF8 bytes."""
    if ssid.uSSIDLength == 0:
        return ""
    raw = bytes(ssid.ucSSID[:ssid.uSSIDLength])
    try:
        return raw.decode("utf-8", errors="ignore")
    except UnicodeError:  # pylint: disable=broad-exception-caught
        # Only decoding-related issues are expected here; fall back to latin-1.
        return raw.decode("latin1", errors="ignore")



def get_visible_ssids_via_api(
    h_client: wintypes.HANDLE,
    iface: WLAN_INTERFACE_INFO
) -> List[str]:
    """Return visible SSIDs using WlanGetAvailableNetworkList (lowercased, skip empties)."""
    p_list = ctypes.c_void_p()
    rc = _wlan.WlanGetAvailableNetworkList(
        h_client, ctypes.byref(iface.InterfaceGuid), 0, None, ctypes.byref(p_list)
    )
    if rc != ERROR_SUCCESS:
        raise RuntimeError(f"WlanGetAvailableNetworkList rc={rc}")

    if p_list.value is None:
        _wlan.WlanFreeMemory(p_list)
        return []

    try:
        lst_ptr = ctypes.cast(p_list, ctypes.POINTER(WLAN_AVAILABLE_NETWORK_LIST))
        header = lst_ptr.contents
        count = int(header.dwNumberOfItems)

        base_addr = ctypes.addressof(header)
        offset = (ctypes.sizeof(WLAN_AVAILABLE_NETWORK_LIST)
                  - ctypes.sizeof(WLAN_AVAILABLE_NETWORK))
        first_elem_addr = base_addr + offset

        arr_t = WLAN_AVAILABLE_NETWORK * count
        arr_ptr = ctypes.cast(first_elem_addr, ctypes.POINTER(arr_t))
        ssids: List[str] = []
        for net in arr_ptr.contents:
            s = _ssid_bytes_to_str(net.dot11Ssid).strip()
            if s:
                ssids.append(s.lower())
        return ssids
    finally:
        _wlan.WlanFreeMemory(p_list)


# =========================
# Wi‑Fi helpers (netsh + parsing)
# =========================

def parse_visible_ssids(raw: str) -> List[str]:
    """Parse SSIDs from `netsh wlan show networks mode=Bssid` output (lowercased)."""
    ssids: List[str] = []
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("SSID ") and ":" in s:
            ssid = s.split(":", 1)[1].strip()
            if ssid:
                ssids.append(ssid.lower())
                logging.debug("Appending %s to ssids list",ssid)
    logging
    return ssids


def read_visible_ssids_via_netsh() -> List[str]:
    """Call netsh to enumerate visible networks and return lowercased SSIDs."""
    out, err, rc = run_command(["netsh", "wlan", "show", "networks", "mode=Bssid"])
    if rc != 0:
        print(f"⚠️ netsh rc={rc}: {err or out}")
        return []
    return parse_visible_ssids(out)


def get_current_ssid() -> Optional[str]:
    """Return the SSID of the currently connected Wi‑Fi network, else None."""
    out, _, _ = run_command(["netsh", "wlan", "show", "interfaces"])
    for line in out.splitlines():
        if "SSID" in line and "BSSID" not in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                ssid = parts[1].strip()
                if ssid:
                    return ssid
    return None


# =========================
# Scan + connect flow
# =========================

def scan_available_networks(
    desired_ssid: Optional[str],
    max_attempts: int,
    delay_between_scans: int,
    interface_hint: Optional[str],
    readback: str,
    hard_fail_on_scan_error: bool,
) -> List[str]:
    """
    Force a Wi‑Fi scan using Native Wi‑Fi API and return visible SSIDs (lowercased).
    Retries up to max_attempts with backoff to accommodate scan throttling.
    `readback` chooses 'netsh' or 'api' for retrieving results.
    """
    last_seen: List[str] = []
    h_client = _open_wlan()
    try:
        interfaces = _get_wlan_interfaces(h_client)
        iface = _choose_interface(interfaces, interface_hint)

        for attempt in range(1, max_attempts + 1):
            print(
                f"📡 Forcing Wi‑Fi scan"
                f"{f' on {iface.strInterfaceDescription!r}' if iface else ''}"
                f"(Attempt {attempt}/{max_attempts})"
            )
            try:
                force_scan_nativewifi(h_client, iface)
            except (RuntimeError, OSError, ctypes.ArgumentError) as e:
                msg = f"⚠️ WlanScan failed: {e}"
                if hard_fail_on_scan_error:
                    raise RuntimeError(msg) from e
                print(msg)

            time.sleep(delay_between_scans)

            if readback == "api":
                try:
                    ssids = get_visible_ssids_via_api(h_client, iface)
                except (RuntimeError, OSError, ctypes.ArgumentError) as e:
                    print(f"⚠️ WlanGetAvailableNetworkList failed: {e}")
                    ssids = []
            else:
                ssids = read_visible_ssids_via_netsh()

            last_seen = ssids
            if desired_ssid and desired_ssid.lower() in ssids:
                return ssids

        return last_seen
    finally:
        _close_wlan(h_client)


def connect_wifi(
    profile_name: str,
    ssid: Optional[str],
    interface: Optional[str],
    timeout: int,
    retry_interval: int,
    scan_attempts: int,
    scan_delay: int,
    readback: str,
    hard_fail_on_scan_error: bool,
) -> bool:
    """
    Connect to a saved WLAN profile, forcing a pre‑scan via WlanScan to ensure fresh results.

    Returns True on success; raises ConnectionError on failure.
    """
    current = get_current_ssid()
    if current and ssid and current.lower() == ssid.lower():
        print(f"✅ Already connected to SSID '{current}'.")
        return True
    if current and not ssid and current.lower() == profile_name.lower():
        print(f"✅ Already connected to '{profile_name}'.")
        return True

    # Force a fresh scan and verify visibility
    desired = (ssid or profile_name).lower()
    visible = scan_available_networks(
        desired_ssid=desired,
        max_attempts=scan_attempts,
        delay_between_scans=scan_delay,
        interface_hint=interface,
        readback=readback,
        hard_fail_on_scan_error=hard_fail_on_scan_error,
    )
    if desired not in visible:
        raise ConnectionError(
            f"Wi‑Fi network '{ssid or profile_name}' not in range after forced scan."
        )

    print(
        f"🔄 Attempting to connect to profile '{profile_name}'"
        f"{f' on interface {interface!r}' if interface else ''}..."
    )
    cmd = ["netsh", "wlan", "connect", f"name={profile_name}"]
    if ssid:
        # If profile name differs from SSID, supply both
        cmd.append(f"ssid={ssid}")
    if interface:
        cmd.append(f'interface="{interface}"')

    out, err, rc = run_command(cmd)
    if rc != 0:
        details = err or out or f"rc={rc}"
        raise ConnectionError(f"Failed to initiate connection: {details}")

    # Poll for association
    start = time.time()
    while time.time() - start < timeout:
        now = get_current_ssid()
        if ssid:
            if now and now.lower() == ssid.lower():
                print(f"✅ Successfully connected to '{now}'.")
                return True
        else:
            if now and now.lower() == profile_name.lower():
                print(f"✅ Successfully connected to '{now}'.")
                return True
        time.sleep(retry_interval)

    raise ConnectionError(f"Failed to join target within {timeout}s.")


# =========================
# CLI
# =========================

def main(argv: List[str]) -> int:
    """CLI entry point: parses args, triggers scan+connect flow, returns process exit code."""
    ensure_windows()
    parser = argparse.ArgumentParser(
        description=(
            "Force a Wi‑Fi rescan (WlanScan) and connect to a saved Windows WLAN profile."
        )
    )
    parser.add_argument("profile", help="Windows WLAN profile name to connect to.")
    parser.add_argument(
        "--ssid", help="On‑air SSID if different from profile name.", default=None
    )
    parser.add_argument(
        "--interface", help="Interface hint (e.g., 'Wi‑Fi').", default=None
    )
    parser.add_argument(
        "--timeout", type=int, default=25, help="Association timeout (seconds)."
    )
    parser.add_argument(
        "--retry-interval", type=int, default=3, help="Status poll interval (seconds)."
    )
    parser.add_argument(
        "--scan-attempts", type=int, default=3, help="Number of scan attempts."
    )
    parser.add_argument(
        "--scan-delay",
        type=int,
        default=6,
        help="Seconds to wait after WlanScan before reading results.",
    )
    parser.add_argument(
        "--readback",
        choices=["netsh", "api"],
        default="netsh",
        help=(
            "How to read visible networks after scanning: 'netsh' (default) or "
            "'api' (WlanGetAvailableNetworkList)."
        ),
    )
    parser.add_argument(
        "--hard-fail-on-scan-error",
        action="store_true",
        help="Raise immediately if WlanScan fails (instead of continuing).",
    )
    args = parser.parse_args(argv)

    try:
        connect_wifi(
            profile_name=args.profile,
            ssid=args.ssid,
            interface=args.interface,
            timeout=args.timeout,
            retry_interval=args.retry_interval,
            scan_attempts=args.scan_attempts,
            scan_delay=args.scan_delay,
            readback=args.readback,
            hard_fail_on_scan_error=args.hard_fail_on_scan_error,
        )
        return 0
    except ConnectionError as e:
        print(f"❌ {e}")
        return 1
    except RuntimeError as e:
        print(f"❌ {e}")
        return 2


def connect_simple(
    target: str,
    *,
    timeout: int = 25,
    retry_interval: int = 3,
    retry_count: int = 3,
    interface: Optional[str] = None,
    readback: str = "netsh",
) -> bool:
    """
    Convenience API to force a scan and connect to Wi‑Fi from another script.

    Parameters
    ----------
    target : str
        The Wi‑Fi name to aim for. If a profile with a different on‑air SSID
        is used, pass the profile name as 'target' and the SSID via 'ssid'.
        For simple cases where profile==SSID, just pass the name here.
    timeout : int
        Total seconds to wait for association to complete (default 25).
    retry_interval : int
        Seconds between link-status polls while waiting (default 3).
    retry_count : int
        Number of forced-scan attempts before giving up (default 3).
    interface : Optional[str]
        Friendly adapter name hint (e.g., "Wi‑Fi" or "Wi‑Fi 2"). Optional.
    readback : str
        How to read scan results: "netsh" (default) or "api".

    Returns
    -------
    bool
        True on successful association; raises ConnectionError on failure.

    Raises
    ------
    ConnectionError
        If the SSID/profile isn't visible after scanning or association fails.
    RuntimeError
        If Native Wi‑Fi API calls fail unexpectedly (e.g., blocked by policy).
    """
    # For the simple API, treat the target as both profile and SSID.
    profile_name = target
    ssid = target

    return connect_wifi(
        profile_name=profile_name,
        ssid=ssid,
        interface=interface,
        timeout=timeout,
        retry_interval=retry_interval,
        scan_attempts=retry_count,
        scan_delay=max(4, retry_interval),  # a sensible default coupling
        readback=readback,
        hard_fail_on_scan_error=False,
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
