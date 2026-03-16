"""
A classful implementation of the V1 API calls available as of 20260316
"""

from __future__ import annotations

import os
import sys
import time
import hashlib
import pathlib
from pprint import pprint
from datetime import datetime
from typing import Optional, TypedDict, List

# NotRequired is stdlib in Python 3.11+; provide fallback for <= 3.10
try:
    from typing import NotRequired  # type: ignore[attr-defined]
except RuntimeError:  # pragma: no cover
    from typing_extensions import NotRequired  # type: ignore

import requests


if sys.platform.startswith("win"):
    try:
        import truststore  # type: ignore
        truststore.inject_into_ssl()  # type: ignore[attr-defined]
    except ImportError as e:
        print(
            f"""Could not inject truststore into SSL context, {e}. You will experience SSL
errors if your system uses custom or corporate CAs. Exit by typing Ctrl-C,
or proceed to try."""
        )


class SleepHQ:
    """
    A SleepHQ connection class. This allows access to all the inner classes
    """

    def __init__(self, api_client: str, api_secret: str, verbose: bool = False) -> None:
        self.api_client = api_client
        self.api_secret = api_secret
        self.verbose = verbose

        self.auth_url = "https://sleephq.com/oauth/token"
        self.base_url = "https://sleephq.com/api/v1/"
        self.bearer = self.__get_bearer()
        self.me = SleepHQ.Me(self)
        self.team_id = self.me.current_team_id
        self.date_time = datetime.now().strftime("%Y%m%d")

        # Initialize as None so static analysis doesn't think it's a str
        self.import_req: Optional[SleepHQ.SHQImports] = None

    def create_upload(self) -> str:
        """Creates an import request and returns the import id"""
        self.import_req = SleepHQ.SHQImports(self)
        upload_req_id = self.import_req.create_import(f"Breathe_Easy {self.date_time}", self)
        return upload_req_id


    def process_upload(self) -> None:
        """Process the current import."""
        if self.import_req is None:
            raise RuntimeError("No import exists. Call create_upload() first.")
        self.import_req.process_upload(self)

    def validate_upload(self) -> None:
        """Process the current import."""
        if self.import_req is None:
            raise RuntimeError("No import exists. Call create_upload() first.")
        self.import_req.validate_upload(self)

    def add_files(self, file_collection: List["SleepHQ.SHQImports.FileSpec"]) -> None:
        """Adds files to existing import"""
        if self.import_req is None:
            raise RuntimeError("No import exists. Call create_upload() first.")
        # Pass the SleepHQ connection (self) into SHQImports
        self.import_req.add_files_to_import(self, file_collection)

    def __get_bearer(self) -> str:
        """
        Authenticates with the SleepHQ OAUTH using API key and secret

        :return str: A string in the format 'Bearer <access_token>'
        """
        payload = {
            "client_id": self.api_client,
            "client_secret": self.api_secret,
            "grant_type": "password",
            "scope": "read write delete",
        }

        try:
            response = requests.post(self.auth_url, data=payload, timeout=20)
            response.raise_for_status()
            if self.verbose:
                print("Authorization successful\n")
            token = response.json()["access_token"]
            return "Bearer " + token
        except requests.RequestException as e:
            print(f"Failed to get access token {e}")
            # Avoid printing secrets in logs
            sys.exit(1)

    def printbearer(self) -> None:
        """prints the bearer"""
        print(self.bearer)

    def __repr__(self) -> str:  # noqa: D401
        return f"{self.me.name}"

    # We always need a team id, and this can be found here
    class Me:
        """implements Me apis"""

        def __init__(self, connection_instance: "SleepHQ") -> None:
            # get the current "Me"
            self.myprofile = self.__get(connection_instance)
            self.id = self.myprofile["id"]
            self.email = self.myprofile["email"]
            self.current_team_id = self.myprofile["current_team_id"]
            self.profile_photo_url = self.myprofile["profile_photo_url"]
            self.owned_team_ids = self.myprofile["owned_team_ids"]
            self.name = self.myprofile["name"]

        def __get(self, connection_instance: "SleepHQ") -> dict:
            url = connection_instance.base_url + "me"
            headers = {
                "Authorization": connection_instance.bearer,
                "Accept": "application/json",
            }
            try:
                response = requests.request(
                    method="GET", url=url, headers=headers, timeout=20
                )
                response.raise_for_status()
                if connection_instance.verbose:
                    print(f"Received: {response.json()['data']}")
                return response.json()["data"]
            except requests.RequestException as e:
                print(f"Failed to get Me. {e}")
                sys.exit(1)

        def __repr__(self) -> str:
            return (
                f"Name:{self.name}\n"
                f"ID:{self.id}\n"
                f"Email:{self.email}\n"
                f"Current Team:{self.current_team_id}\n"
                f"Profile Photo:{self.profile_photo_url}\n"
                f"Owned Teams:{self.owned_team_ids}"
            )

    class SHQMachines:
        """implement Machines apis"""

        def __init__(self, outer: "SleepHQ") -> None:
            pass

    class SHQDevices:
        """implements Devices apis"""
        # TODO: implement

    class SHQTeams:
        """implements Team apis"""
        # TODO: implement

    # Imports are the parent. An import will have one:many files. For init we
    # just need to know the team id (in Me or Teams)
    class SHQImports:
        """Implements SleepHQ Imports APIs and local file helpers."""

        class FileSpec(TypedDict):
            """FileSpec class for SHQ-uploadable files. These files must contain:
            - filepath
            - filename
            - content_hash
            """

            # Required
            filepath: str         # Absolute directory path with trailing os.sep
            filename: str         # Base filename (e.g., 'foo.bin')
            content_hash: str     # MD5(file_bytes + filename), lowercase hex
            # Optional
            path: NotRequired[str]  # SleepHQ relative path like "./" or "./DATALOG/20230924/"

        def __init__(self, connection_instance: "SleepHQ") -> None:
            self.import_id: str = ""
            self.add_list_url = (
                connection_instance.base_url
                + f"teams/{connection_instance.team_id}/imports"
            )
            self.process_retrieve_delete_url = connection_instance.base_url + "imports/"

        def create_import(self, import_name: str, connection_instance: "SleepHQ") -> str:
            """Creates a new import collection on SleepHQ and stores the import_id."""
            headers = {
                "Authorization": connection_instance.bearer,
                "Accept": "application/json",
            }
            payload = {
                "programatic": "True",  # SleepHQ expects stringy form fields
                "name": import_name,
            }

            try:
                response = requests.post(
                    self.add_list_url, data=payload, headers=headers, timeout=20
                )
                response.raise_for_status()
                if connection_instance.verbose:
                    print(response.json()["data"])
                self.import_id = response.json()["data"]["id"]
                return self.import_id
            except requests.RequestException as e:
                print(f"Failed to reserve import ID: {e}")
                sys.exit(1)

        def list_imports(self, connection_instance: "SleepHQ") -> dict:
            """Lists import collections for the current team."""
            headers = {
                "Authorization": connection_instance.bearer,
                "Accept": "application/json",
            }
            try:
                resp = requests.get(self.add_list_url, headers=headers, timeout=20)
                resp.raise_for_status()
                data = resp.json()
                if connection_instance.verbose:
                    pprint(data)
                return data
            except requests.RequestException as e:
                print(f"Failed to list imports: {e}")
                sys.exit(1)

        def add_files_to_import(
            self,
            connection_instance: "SleepHQ",
            file_list: List["SleepHQ.SHQImports.FileSpec"],
        ) -> None:
            """Uploads files to the existing import collection (self.import_id)."""

            if not self.import_id:
                print("No import has been created yet. Call create_import() first.")
                sys.exit(1)

            # Defensive guard (useful if callers bypass type hints)
            for i, f in enumerate(file_list):
                for k in ("filepath", "filename", "content_hash"):
                    if k not in f or not f[k]:
                        raise ValueError(f"file_list[{i!r}] missing required key: {k}")

            url = f"https://sleephq.com/api/v1/imports/{self.import_id}/files"
            headers = {
                "Authorization": connection_instance.bearer,
                "Accept": "application/json",
            }

            total_files = len(file_list)
            print(f"Starting upload of {total_files} files to SleepHQ...")

            for idx, file in enumerate(file_list, start=1):
                if connection_instance.verbose:
                    pprint(f"Current file:\n{file}")

                # Build local path and read file
                filepath = os.path.join(file["filepath"], file["filename"])
                if connection_instance.verbose:
                    print(f"Filepath: {filepath}")

                shq_path = file.get("path", "./")
                md5_hash = file["content_hash"]

                form_data = {
                    "name": file["filename"],
                    "path": shq_path,
                    "content_hash": md5_hash,
                }

                response = None
                try:
                    with open(filepath, "rb") as f:
                        files = {
                            "file": (file["filename"], f, "application/octet-stream")
                        }
                        response = requests.post(
                            url,
                            headers=headers,
                            data=form_data,
                            files=files,
                            timeout=120,
                        )
                    response.raise_for_status()

                    if connection_instance.verbose:
                        print(f"File {file['filename']} has been imported successfully")

                except requests.RequestException as e:
                    print(f"Failed to upload file {file['filename']}:\n*****-{e}")
                    if response is not None:
                        print(f"Response headers: {response.headers}")
                        print(f"Response body: {response.text}")
                    sys.exit(1)

                finally:
                    if idx == total_files:
                        print(
                            "All files have been uploaded to SleepHQ. "
                            "Processing may take a few minutes."
                        )
                    time.sleep(0.25)

        def process_upload(self, connection_instance: "SleepHQ") -> None:
            """
            Sends a request to SleepHQ to start processing the uploaded files for
            this import (self.import_id).
            """
            if not self.import_id:
                print("No import has been created yet. Call create_import() first.")
                sys.exit(1)

            url = f"https://sleephq.com/api/v1/imports/{self.import_id}/process_files"
            headers = {
                "Authorization": connection_instance.bearer,
                "Accept": "application/json",
            }
            try:
                response = requests.post(url, headers=headers, timeout=20)
                response.raise_for_status()
                print(
                    f"Files are now being processed by SleepHQ for Import ID: {self.import_id}"
                )
            except requests.RequestException as e:
                print(f"Failed to process the imported files: {e}")
                print(
                    "But you can retry the process_files request again at a later time\n"
                    f"by calling: {url}"
                )
                sys.exit(1)

        def validate_upload(self, connection_instance: "SleepHQ") -> None:
            '''
            validate_upload checks the status of the import processing for a given import
            ID and prints the result.
    
            :return: None
            '''

            if not self.import_id:
                print("No import has been created yet. Call create_import() first.")
                sys.exit(1)

            url = f"https://sleephq.com/api.v1/imports/{self.import_id}"
            headers = {
                "Authorization": connection_instance.bearer,
                "Accept": "application/json"
            }
            try:
                response = requests.get(url=url,headers=headers,timeout=20)
                response.raise_for_status()

                failed_reason = response.json().get(
                    "data",{}).get("attributes", {}).get(
                        "failed_reason")

                if failed_reason:
                    print(f"Processing failed: {failed_reason or 'No failure reason provided.'}")
                else:
                    print("Import processed successfully.")

            except requests.RequestException as e:
                print(f"Failed to process imported files: {e}")
                print(f"But you can try the process_files request again later by calling: {url}")
                sys.exit(1)

        # Local helper functionality:

        @staticmethod
        def compute_sleephq_content_hash(filepath: str) -> str:
            """
            Calculates the SleepHQ content hash for a given file:
            SleepHQ content_hash = MD5(file_bytes + filename)

            :param filepath: Path to the file
            :return: Hexadecimal MD5 string
            """

            md5 = hashlib.md5()
            filename = os.path.basename(filepath).encode("utf-8")

            with open(filepath, "rb") as f:
                # Stream in 1 MiB chunks
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    md5.update(chunk)

            md5.update(filename)
            return md5.hexdigest()

        @staticmethod
        def get_files(dir_path: str) -> List["SleepHQ.SHQImports.FileSpec"]:
            """
            Walks directory tree and returns a list of SleepHQ-ready file dicts.

            Each dict:
            - 'filepath': absolute directory path with trailing os.sep
            - 'filename': base filename
            - 'path': SleepHQ-style relative path from dir_path root, 
            e.g. "./" or "./DATALOG/20230924/"
            - 'content_hash': MD5(file_bytes + filename) in lowercase hex
            """
            base = pathlib.Path(dir_path)
            file_items: List["SleepHQ.SHQImports.FileSpec"] = []

            for p in base.rglob("*"):
                if not p.is_file() or p.name.startswith("."):
                    continue

                abs_dir = str(p.parent.resolve()) + os.sep
                filename = p.name

                # path relative to base directory (SD root), in SleepHQ style
                rel_dir = p.parent.relative_to(base).as_posix()  # '' or 'DATALOG/20230924'
                shq_path = "./" if rel_dir in ("", ".") else f"./{rel_dir}/"

                fullpath = str(p.resolve())
                content_hash = SleepHQ.SHQImports.compute_sleephq_content_hash(fullpath)

                file_items.append(
                    {
                        "filepath": abs_dir,
                        "filename": filename,
                        "path": shq_path,
                        "content_hash": content_hash,
                    }
                )

            return file_items


def main() -> None:
    """Main CLI entry point"""
    key = os.getenv("SLEEPHQ_CLIENT_ID")
    secret = os.getenv("SLEEPHQ_CLIENT_SECRET")

    if not key or not secret:
        print("Missing SLEEPHQ_CLIENT_ID or SLEEPHQ_CLIENT_SECRET in environment.")
        sys.exit(1)

    shq = SleepHQ(key, secret, verbose=True)
    print(f"repr(shq): {repr(shq)}\n\n")

    # Create a new import
    import_id = shq.create_upload()
    print(f"Created import: {import_id}")

    # Add the base files directory, then add the files to the import
    files = shq.SHQImports.get_files('./LatestCPAP')
    shq.add_files(files)
    shq.process_upload()

    # now validate it
    shq.validate_upload()

    # Option A: Discover files from a directory (uncomment and set your path)
    # files = shq.SHQImports.get_files('./LatestCPAP')
    #
    # Option B: Provide a file list manually
    # Note: ensure `filepath` ends with os.sep if you construct it manually
    # example_fullpath = '/path/to/files/session-2026-03-15.edf'
    # files: List[SleepHQ.SHQImports.FileSpec] = [
    #    {
    #        'filepath': '/path/to/files' + os.sep,
    #        'filename': "session-2026-03-15.edf",
    #        'content_hash': SleepHQ.SHQImports.compute_sleephq_content_hash(example_fullpath),
    #        'path': './',
    #    }
    #]

    # Upload files to this import
    # shq.add_files(files)
    ###


if __name__ == "__main__":
    main()
