import requests
import argparse
import hashlib
import os
import sys
import pathlib
import json
import time
from pprint import pprint as pprint
from collections import defaultdict, OrderedDict


def get_shq_access_token(client_id,client_secret):
    url = "https://sleephq.com/oauth/token"
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'password',
        'scope': 'read write delete'
    }
    try:
        response = requests.post(url,data=payload)
        response.raise_for_status()
        print("Authorization successful\n")
        return 'Bearer ' + response.json()['access_token']
    except requests.RequestException as e:
        print(f"Failed to get acces token: {e}")
        print(f"uid:{payload}")
        sys.exit(1)

def get_shq_team_id(token):
    url = "https://sleephq.com/api/v1/me"
    headers = {
        'Authorization': token,
        'Accept': 'application/json'
    }
    try:
        response = requests.request("GET", url, headers=headers)
        response.raise_for_status()
        return response.json()['data']['current_team_id']
    except requests.RequestException as e:
        print(f"Failed to get Team Id: {e}")
        sys.exit(1)

# Prepares the files for import and adds them to a collection and a JSON dump for
# later processing in the request payload

def compute_sleephq_content_hash(filepath: str) -> str:
    """
    Calculates the SleepHQ content hash for a given file based on its bytes and filename as follows:
    SleepHQ content_hash = MD5(file_bytes + filename)

    :param filepath (str): Path to the file
    :return (str): Hexadecimal MD5 hash string
    
    """
    md5 = hashlib.md5()
    filename = os.path.basename(filepath).encode("utf-8")

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)

    md5.update(filename)
    return md5.hexdigest()

def get_files(dir_path, sub_path=None):
    """
    Returns: List[dict] where each dict has:
      filepath: absolute directory path with trailing os.sep
      filename: base filename
      path: SD-root relative directory like "./" or "./DATALOG/20230924/"
      content_hash: MD5(file_bytes + filename) [1](https://github.com/amanuense/CPAP_data_uploader/issues/1)
    """
    base = pathlib.Path(dir_path)

    file_items = []
    for p in base.rglob("*"):
        if not p.is_file() or p.name.startswith("."):
            continue

        abs_dir = str(p.parent.resolve()) + os.sep
        filename = p.name

        # path relative to base directory (SD root), in SleepHQ style
        rel_dir = p.parent.relative_to(base).as_posix()  # '' or 'DATALOG/20230924'
        shq_path = "./" if rel_dir in ("", ".") else f"./{rel_dir}/"

        fullpath = str(p.resolve())
        content_hash = compute_sleephq_content_hash(fullpath)

        file_items.append({
            "filepath": abs_dir,
            "filename": filename,
            "path": shq_path,
            "content_hash": content_hash,
        })

    return file_items


# Obtains an Import Reservation Id from SleepHQ
def get_shq_import_req_id(id, token):
    url = f"https://sleephq.com/api/v1/teams/{id}/imports"
    headers = {'Authorization': token, 'Accept': 'application/json'}
    payload = {'programatic': False}
    try:
        response = requests.post(url, headers=headers, data=payload)
        response.raise_for_status()
        return response.json()['data']['id']
    except requests.RequestException as e:
        print(f"Failed to reserve import ID: {e}")
        sys.exit(1)


# Uploads the files, one by one to SleepHQ

def post_files_to_shq(import_id, token, file_list):
    url = f"https://sleephq.com/api/v1/imports/{import_id}/files"

    headers = {
        "Authorization": token if token.lower().startswith("bearer ") else f"Bearer {token}",
        "Accept": "application/vnd.api+json, application/json;q=0.9, */*;q=0.8",
    }

    for file in file_list:
        pprint(f"Current file:\n{file}")

        filepath = os.path.join(file["filepath"], file["filename"])
        print(f"Filepath: {filepath}")

        shq_path = file.get("path", "./")
        md5_hash = file["content_hash"]  # already computed in get_files()

        # ✅ Send the field name the API is asking for
        form_data = {
            "name": file["filename"],
            "path": shq_path,
            "content_hash": md5_hash,
        }

        response = None
        try:
            with open(filepath, "rb") as f:
                files = {"file": (file["filename"], f, "application/octet-stream")}

                response = requests.post(
                    url,
                    headers=headers,
                    data=form_data,
                    files=files,
                    timeout=120
                )

            response.raise_for_status()
            print(f"File {file['filename']} has been imported successfully")

        except requests.RequestException as e:
            print(f"Failed to upload file {file['filename']}:\n*****-{e}")
            if response is not None:
                print(f"Response headers:{response.headers}")
                print(f"Response body:{response.text}")
            sys.exit(1)

        finally:
            time.sleep(1)


# Closes the Import and starts the processing of the uploaded files
def process_shq_imports(id, token):
    url = f"https://sleephq.com/api/v1/imports/{id}/process_files"
    headers = {
        'Authorization': token,
        'Accept': 'application/json'
    }
    try:
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        print(f"Files are now being processed by SleepHQ for Import ID: {id}")
    except requests.RequestException as e:
        print(f"Failed to process the imported files: {e}")
        print(f"But you can retry the process_files request again at a later time by calling: {url}")
        sys.exit(1)


# Check the Import processing of the uploaded files
def validate_import_to_shq(id, token):
    url = f"https://sleephq.com/api/v1/imports/{id}"
    headers = {
        'Authorization': token,
        'Accept': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        # Check if failed_reason from the json has any value
        if str(response.json()['data']['attributes']['failed_reason']):
            failed_reason = response.json().get("data", {}).get("attributes", {}).get("failed_reason")
            print(f"Processing failed: {failed_reason or 'No failure reason provided.'}")

    except requests.RequestException as e:
        print(f"Failed to process imported files: {e}")
        print(f"But you can try the process_files request again later by calling: {url}")
        sys.exit(1)

# Parse arguments
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Upload CPAP data to SleepHQ."
    )
    p.add_argument("--client-id", required=True, help='Client ID API Key')
    p.add_argument("--client-secret", required=True, help='Client Secret API Key')
    p.add_argument("--data-path", required=True, default="latestcpap", help='CPAP Data Directory')
    p.add_argument("--verbose", required=False, default = False, help='Display step-by-step processing')
    return p.parse_args()


def run_upload(clt_id, clt_sec, dpath, dspath, verbose) -> None:
    bearer = get_shq_access_token(clt_id, clt_sec)

    # get_files now returns a LIST of file dicts
    files_to_import = get_files(dpath, dspath)

    if verbose:
        print(f"Found {len(files_to_import)} files")
        if files_to_import:
            print("Sample file item:", files_to_import[0])

    user_team_id = get_shq_team_id(bearer)
    import_id = get_shq_import_req_id(user_team_id, bearer)

    if verbose:
        print("Uploading files to SleepHQ")

    post_files_to_shq(import_id, bearer, files_to_import)

    if verbose:
        print("Processing files")

    process_shq_imports(import_id, bearer)
    time.sleep(5)

    if verbose:
        print("Validating import")

    validate_import_to_shq(import_id, bearer)

    print("Upload completed successfully. Visit https://sleephq.com to view your updated data")


# Main runtime
def main():
    # Parse the Arguments from the CLI or wrapper call
    args = parse_args()
    client_id = args.client_id
    client_secret = args.client_secret
    
    # Get the current working directory. We are expecting the user CPAP data to be a subfolder of this directory
    exec_dir = os.getcwd()
    data_dir_path = exec_dir + os.sep + os.path.normpath(args.data_path)
    data_subdir_path = data_dir_path + os.sep

    # Run the upload logic routine
    run_upload(args.client_id,args.client_secret,data_dir_path,data_subdir_path,args.verbose)

if __name__ == "__main__":
    main()
