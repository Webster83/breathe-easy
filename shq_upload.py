'''
shq_upload.py is a Python script designed to facilitate the upload of CPAP data files to SleepHQ. It handles authentication, file discovery, uploading, and processing of the data through SleepHQ's API. 
The script can be run from the command line with appropriate arguments or called from another Python script as a wrapper function.

This script is desgined to be platform agnostic and should work on Windows, Mac, and Linux. It also includes logic to inject the system truststore into the SSL context on Windows to avoid SSL errors
for users in corporate environments with custom CAs. While only tested against Resmed CPAP data, it should work with any CPAP data that is imported from the sd card.

Author: BChap
Last Revision Date: 20260206
'''
import sys

# On Windows, inject the system truststore into the SSL context, this needs to be done before importing requests
# This will allow for any corporate or custom CAs to be recognized by requests module
if sys.platform.startswith("win"):
    try:
        import truststore
        truststore.inject_into_ssl()
    except Exception as e:
        print(f"""Could not inject truststore into SSL context, {e}. You will exeperience SSL errors if your system uses 
        custom or corporate CAs. Exit by typing Ctrl-C, or proceed to try.""")
        pass

import requests
import argparse
import hashlib
import os
import pathlib
import time
from pprint import pprint as pprint


def get_shq_access_token(client_id,client_secret)-> str:
    '''Obtain an access token from SleepHQ using the provided client_id and client_secret.
    Returns a string in the format 'Bearer <access_token>' if successful, or exits the program if there is an error.

    :param str client_id: The client ID for authentication
    :param str client_secret: The client secret for authentication
    :return str: A string containing the access token in the format 'Bearer <access_token>'
    '''

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

def get_shq_team_id(token) -> str:
    
    '''
    get_shq_team_id retrieves the current team ID associated with the authenticated user from SleepHQ using the provided access token.
    
    :param str token: The access token for authentication, in the format 'Bearer <token>'
    :return str: The current team ID associated with the authenticated user
    '''

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

def compute_sleephq_content_hash(filepath: str) -> str:
    """
    Calculates the SleepHQ content hash for a given file based on its bytes and filename as follows:
    SleepHQ content_hash = MD5(file_bytes + filename)

    :param str filepath: Path to the file
    :return str: Hexadecimal MD5 hash string
    
    """
    md5 = hashlib.md5()
    filename = os.path.basename(filepath).encode("utf-8")

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(chunk)

    md5.update(filename)
    return md5.hexdigest()

def get_files(dir_path, sub_path=None)-> list[dict]:
    """
    Walks through the given directory and its subdirectories to find all files to upload, that do not start with a dot.
    For each file, it computes the absolute directory path, filename, SleepHQ-style relative path, and content hash.

    :param str dir_path: The base directory to search for files (eg ./LatestCPAP)
    :param str sub_path: Optional subdirectory path within dir_path to search (eg "./ImportData/LatestCPAP")

    :return: List[dict]:
      A list of dictionaries, each containing the following keys for a file:
      str filepath: absolute directory path with trailing os.sep
      str filename: base filename
      Path path: SD-root relative directory like "./" or "./DATALOG/20230924/"
      str content_hash: MD5(file_bytes + filename)
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

def get_shq_import_req_id(id, token) -> str:

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

def post_files_to_shq(import_id, token, file_list, verbose=False):
    '''
    post_files_to_shq uploads files to SleepHQ for a given import reservation ID.
    
    :param str import_id: The import reservation ID obtained from SleepHQ API call
    :param token: The access token for authentication, in the format 'Bearer <token>'
    :param list[dict] file_list: List of file dictionaries returned by get_files()
    :param bool verbose: If True, prints detailed information during execution
    :return: None
    '''
    url = f"https://sleephq.com/api/v1/imports/{import_id}/files"

    headers = {
        "Authorization": token if token.lower().startswith("bearer ") else f"Bearer {token}",
        "Accept": "application/vnd.api+json, application/json;q=0.9, */*;q=0.8",
    }

    for file in file_list:
        if verbose:
            pprint(f"Current file:\n{file}")

        filepath = os.path.join(file["filepath"], file["filename"])
        if verbose:
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
            if verbose:
                print(f"File {file['filename']} has been imported successfully")

        except requests.RequestException as e:
            print(f"Failed to upload file {file['filename']}:\n*****-{e}")
            if response is not None:
                print(f"Response headers:{response.headers}")
                print(f"Response body:{response.text}")
            sys.exit(1)

        finally:
            print("All files have been uploaded to SleepHQ. Processing may take a few minutes.")
            time.sleep(1)


# Closes the Import and starts the processing of the uploaded files
def process_shq_imports(id, token)-> None:
    '''
    process_shq_imports sends a request to SleepHQ to start processing the uploaded files for a given import reservation ID.
    
    :param str id: The import reservation ID obtained from SleepHQ API call
    :param str token: The access token for authentication, in the format 'Bearer <token>'
    :return: None
    '''
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
def validate_import_to_shq(id, token)->None:
    '''
    validate_import_to_shq checks the status of the import processing for a given import reservation ID and prints the result.
    
    :param str id: The import reservation ID obtained from SleepHQ API call
    :param str token: The access token for authentication, in the format 'Bearer <token>'
    :return: None
    '''
    url = f"https://sleephq.com/api/v1/imports/{id}"
    headers = {
        'Authorization': token,
        'Accept': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        # Check if failed_reason from the json has any value
        failed_reason = response.json().get("data", {}).get("attributes", {}).get("failed_reason")
        if failed_reason:
            print(f"Processing failed: {failed_reason or 'No failure reason provided.'}")
        else:
            print("Import processed successfully.")
    except requests.RequestException as e:
        print(f"Failed to process imported files: {e}")
        print(f"But you can try the process_files request again later by calling: {url}")
        sys.exit(1)

def run_upload(clt_id, clt_sec, dpath, dspath, verbose) -> None:
    '''
    run_upload orchestrates the entire upload process to SleepHQ, including authentication, file discovery, uploading, processing, and validation.
    
    :param str clt_id: Client ID for authentication
    :param str clt_sec: Client Secret for authentication
    :param str dpath: Client Data Directory
    :param str dspath: Client Data Subdirectory Path
    :param bool verbose: Use verbose output for debugging and detailed information during execution
    :return: None
    '''
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

    post_files_to_shq(import_id, bearer, files_to_import, verbose)

    if verbose:
        print("Processing files")

    process_shq_imports(import_id, bearer)
    time.sleep(5)

    if verbose:
        print("Validating import")

    validate_import_to_shq(import_id, bearer)

    print("Upload completed successfully. Visit https://sleephq.com to view your updated data")

def parse_args() -> argparse.Namespace:
    '''
    parse_args uses argparse to parse command line arguments for the SleepHQ CPAP data upload script.
    
    :return Namespace: An argparse.Namespace object containing the parsed command line arguments:
    '''
    p = argparse.ArgumentParser(
        description="Upload CPAP data to SleepHQ."
    )
    p.add_argument("--client-id", required=True, help='Client ID API Key')
    p.add_argument("--client-secret", required=True, help='Client Secret API Key')
    p.add_argument("--data-path", required=True, default="latestcpap", help='CPAP Data Directory')
    p.add_argument("--verbose", required=False, default = False, help='Display step-by-step processing')
    return p.parse_args()

def main():
    '''
    This function serves as the main entry point for the SleepHQ CPAP data upload script. It parses command line arguments, sets up necessary paths, and orchestrates the upload process by calling the run_upload function
    While it exists, the script is designed to be run from the command line with the appropriate arguments, or called from another Python script as a wrapper function where the arguments can be passed directly to run_upload.
    '''
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
