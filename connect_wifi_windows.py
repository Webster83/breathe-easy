import subprocess
import time
import sys


def run_command(cmd):
    """Run a shell command and return output."""
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return result.stdout.strip(), result.stderr.strip(), result.returncode


def get_current_ssid():
    """Get the currently connected Wi-Fi SSID."""
    out, _, _ = run_command(["netsh", "wlan", "show", "interfaces"])
    for line in out.splitlines():
        if "SSID" in line and "BSSID" not in line:
            return line.split(":", 1)[1].strip()
    return None


def scan_available_networks(max_attempts=3, delay_between_scans=3):
    """
    Force a Wi-Fi scan and return a list of SSIDs currently visible.
    Retries if the list is empty.
    """
    for attempt in range(1, max_attempts + 1):
        print(f"📡 Scanning for Wi-Fi networks... (Attempt {attempt}/{max_attempts})")
        run_command(["netsh", "wlan", "scan"])
        time.sleep(delay_between_scans)  # Allow scan results to update

        out, _, _ = run_command(["netsh", "wlan", "show", "networks", "mode=Bssid"])
        ssids = []
        for line in out.splitlines():
            if line.strip().startswith("SSID "):
                ssid = line.split(":", 1)[1].strip()
                if ssid:
                    ssids.append(ssid)

        if ssids:  # If we found networks, return immediately
            return ssids

        print("⚠️ No networks found, retrying scan...")

    return []  # Return empty list if no networks found after retries


def connect_wifi(profile_name, timeout=20, retry_interval=3):
    """
    Attempt to connect to a Wi-Fi profile if not already connected.
    Raises ConnectionError if:
      - Network is not in range
      - Connection fails within timeout
    """
    current_ssid = get_current_ssid()
    if current_ssid and current_ssid.lower() == profile_name.lower():
        print(f"✅ Already connected to '{profile_name}'.")
        return True

    # Force scan and check if network is in range
    visible_networks = scan_available_networks(max_attempts=3, delay_between_scans=3)
    if profile_name not in visible_networks:
        raise ConnectionError(f"Wi-Fi network '{profile_name}' not in range.")

    print(f"🔄 Attempting to connect to '{profile_name}'...")
    _, err, _ = run_command(["netsh", "wlan", "connect", f"name={profile_name}"])
    if err:
        raise ConnectionError(f"Failed to initiate connection: {err}")

    start_time = time.time()
    while time.time() - start_time < timeout:
        ssid = get_current_ssid()
        if ssid and ssid.lower() == profile_name.lower():
            print(f"✅ Successfully connected to '{ssid}'.")
            return True
        time.sleep(retry_interval)

    raise ConnectionError(f"Failed to join '{profile_name}'.")


# CLI entry point
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python wifi_connect.py <ProfileName>")
        sys.exit(1)

    profile = sys.argv[1]
    try:
        connect_wifi(profile)
    except ConnectionError as e:
        print(f"❌ {e}")
        sys.exit(1)
    except Exception as e:
        print(f"⚠️ Unexpected error: {e}")
        sys.exit(1)