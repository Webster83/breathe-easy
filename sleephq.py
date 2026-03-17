'''
SleepHQ V1 API Python client
Written by BChap
V1 reference pulled 2026-03-16 from https://sleephq.com/api-docs/index.html
Last Updated 20260316
'''

# must be at the beginning:
from __future__ import annotations

import hashlib
import os
import pathlib
import sys
import time
from datetime import datetime
from typing import Optional, TypedDict, List

#Third party Imports
import requests

# NotRequired fallback (if installed Python < 3.10)
try:
    from typing import NotRequired
except ImportError:
    from typing_extensions import NotRequired

# Import Windows Truststore for Proxy/MITM DPI via something like NetSkope
if sys.platform.startswith("win"):
    try:
        import truststore  # type: ignore
        truststore.inject_into_ssl()  # type: ignore[attr-defined]
    except ImportError as e:
        print(f"Could not inject truststore: {e}")

class SleepHQ:
    '''
    High-level client for SleepHQ API.
    '''

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

        self.import_req: Optional[SleepHQ.SHQImports] = None
        self.files_to_upload: List[SleepHQ.SHQImports.FileSpec] = []

    def gather_files(self, dir_path: str) -> None:
        """Collects files via SHQImports.get_files and stores internally."""
        self.files_to_upload = SleepHQ.SHQImports.get_files(dir_path)
        if self.verbose:
            print(f"Collected {len(self.files_to_upload)} files from {dir_path}")

    def create_upload(self) -> str:
        """Creates an import request and stores the import object."""
        self.import_req = SleepHQ.SHQImports(self)
        upload_id = self.import_req.create_import(f"Breathe_Easy {self.date_time}", self)
        return upload_id

    def add_files(self,
                  file_collection: Optional[List["SleepHQ.SHQImports.FileSpec"]] = None
                  ) -> None:
        """
        Adds files to existing import.
        If file_collection is omitted, uses internally gathered files.
        """
        if self.import_req is None:
            raise RuntimeError("No import exists. Call create_upload() first.")

        if file_collection is None:
            file_collection = self.files_to_upload

        if not file_collection:
            raise RuntimeError("No files to upload. Call gather_files() first.")

        self.import_req.add_files_to_import(self, file_collection)

    def process_upload(self) -> None:
        """Triggers SleepHQ to process files for the current import."""
        if self.import_req is None:
            raise RuntimeError("No import exists. Call create_upload() first.")
        self.import_req.process_upload(self)

    def validate_upload(self) -> None:

        ''' validates SHQ Upload success'''

        if self.import_req is None:
            raise RuntimeError("No import exists. Call create_upload() first.")
        self.import_req.validate_upload(self)

    def __get_bearer(self) -> str:
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
                print("Authorization OK")
            return "Bearer " + response.json()["access_token"]
        except requests.RequestException as e:
            print(f"Failed to get access token: {e}")
            sys.exit(1)

    def refresh_token(self) -> None:

        '''Refreshes OAuth bearer token.'''

        self.bearer = self.__get_bearer()
        if self.verbose:
            print("Bearer token refreshed")

    def __repr__(self) -> str:
        return f"{self.me.name}"

    class Me:

        '''implements me api endpoints'''

        def __init__(self, outer: "SleepHQ") -> None:
            prof = self.__get(outer)
            self.id = prof["id"]
            self.email = prof["email"]
            self.current_team_id = prof["current_team_id"]
            self.profile_photo_url = prof["profile_photo_url"]
            self.owned_team_ids = prof["owned_team_ids"]
            self.name = prof["name"]

        def __get(self, outer: "SleepHQ") -> dict:
            url = outer.base_url + "me"
            headers = {"Authorization": outer.bearer, "Accept": "application/json"}
            try:
                r = requests.get(url, headers=headers, timeout=20)
                r.raise_for_status()
                return r.json()["data"]
            except requests.RequestException as e:
                print(f"Failed to get Me: {e}")
                sys.exit(1)

    class SHQImports:

        '''implements Imports api endpoints'''

        class FileSpec(TypedDict):

            '''FileSpec for SleepHQ-bound file uploads'''

            filepath: str
            filename: str
            content_hash: str
            path: NotRequired[str]

        def __init__(self, outer: "SleepHQ") -> None:
            self.import_id = ""
            self.add_list_url = f"{outer.base_url}teams/{outer.team_id}/imports"

        def create_import(self, import_name: str, outer: "SleepHQ") -> str:
            '''creates an import ID'''
            headers = {"Authorization": outer.bearer, "Accept": "application/json"}
            payload = {"programatic": "True", "name": import_name}
            try:
                r = requests.post(self.add_list_url, data=payload, headers=headers, timeout=20)
                r.raise_for_status()
                self.import_id = r.json()["data"]["id"]
                return self.import_id
            except requests.RequestException as e:
                print(f"Failed to create import: {e}")
                sys.exit(1)

        def add_files_to_import(
                self, outer: "SleepHQ",
                files: List["SleepHQ.SHQImports.FileSpec"]
                ) -> None:
            '''adds files to the import id to pend them for upload'''
            if not self.import_id:
                raise RuntimeError("Call create_import() first.")

            url = f"{outer.base_url}imports/{self.import_id}/files"
            headers = {"Authorization": outer.bearer, "Accept": "application/json"}

            print(f"Uploading {len(files)} files to SleepHQ...")

            max_retries = 3

            for idx, f in enumerate(files, start=1):
                local_path = os.path.join(f["filepath"], f["filename"])
                shq_path = f.get("path", "./")
                form_data = {
                    "name": f["filename"],
                    "path": shq_path,
                    "content_hash": f["content_hash"],
                }

                retries = 0
                while True:
                    try:
                        with open(local_path, "rb") as fh:
                            r = requests.post(
                                url,
                                headers=headers,
                                data=form_data,
                                files={"file": (f["filename"], fh, "application/octet-stream")},
                                timeout=120,
                            )

                        r.raise_for_status()
                        break  # SUCCESS → exit retry loop

                    except (requests.exceptions.ConnectionError,
                            requests.exceptions.ChunkedEncodingError,
                            ConnectionResetError) as e:

                        if retries < max_retries:
                            print(f"[WARN] Connection dropped while uploading {f['filename']}." \
                                "Retrying...")

                            # regenerate token
                            outer.refresh_token()

                            retries += 1
                            time.sleep(0.5 * (2 ** (retries - 1)))
                            continue  # retry upload

                        # Out of retries → give up
                        raise RuntimeError(
                            f"Upload failed after {max_retries} retries for {f['filename']}: {e}"
                        ) from e

                    except requests.RequestException as e:
                        # Non‑retryable errors (400/403/etc.)
                        raise RuntimeError(
                            f"Failed uploading {f['filename']} due to non-retryable error: {e}"
                        ) from e

                # end while True retry loop

                if idx == len(files):
                    print("All files uploaded successfully. SleepHQ will begin processing soon.")
                time.sleep(0.25)

        def process_upload(self, outer: "SleepHQ") -> None:
            ''' processes the uploads '''
            if not self.import_id:
                raise RuntimeError("Call create_import() first.")

            url = f"{outer.base_url}imports/{self.import_id}/process_files"
            headers = {"Authorization": outer.bearer, "Accept": "application/json"}

            try:
                r = requests.post(url, headers=headers, timeout=20)
                r.raise_for_status()
                print(f"SleepHQ is processing files for import {self.import_id}")
            except requests.RequestException as e:
                print(f"Failed to trigger processing: {e}")
                print(f"Retry later via: {url}")
                sys.exit(1)

        def validate_upload(self, outer: "SleepHQ") -> None:
            '''
            Validates the state of the import by querying /imports/{id}.
            Ensures HTTP request succeeded and failed_reason is null.
            '''

            if not self.import_id:
                raise RuntimeError("Call create_import() first before validate_upload().")

            url = f"{outer.base_url}imports/{self.import_id}"
            headers = {
                "Authorization": outer.bearer,
                "Accept": "application/json",
            }

            try:
                r = requests.get(url, headers=headers, timeout=20)
                r.raise_for_status()
            except requests.RequestException as e:
                raise RuntimeError(
                    f"Failed to retrieve import state for import {self.import_id}: {e}"
                ) from e

            # ---- Parse JSON ----
            try:
                data = r.json()["data"]
                attrs = data["attributes"]
            except Exception as e:
                raise RuntimeError(
                    f"Unexpected response format while validating import {self.import_id}: {e}"
                ) from e

            failed_reason = attrs.get("failed_reason")

            # ---- Validate state ----
            if failed_reason not in (None, "null"):
                raise RuntimeError(
                    f"Import {self.import_id} indicates failure: failed_reason={failed_reason}"
                )

            if outer.verbose:
                print(f"Import {self.import_id} validated successfully (no failure).")

        @staticmethod
        def compute_sleephq_content_hash(filepath: str) -> str:

            '''computes the file hash for SleepHQ file uploads'''

            md5 = hashlib.md5()
            fname = os.path.basename(filepath).encode("utf-8")
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    md5.update(chunk)
            md5.update(fname)
            return md5.hexdigest()


        @staticmethod
        def get_files(dir_path: str) -> List["SleepHQ.SHQImports.FileSpec"]:

            '''build a file collection of files to associate with the upload'''

            base = pathlib.Path(dir_path)
            results: List[SleepHQ.SHQImports.FileSpec] = []
            for p in base.rglob("*"):
                if not p.is_file() or p.name.startswith("."):
                    continue
                abs_dir = str(p.parent.resolve()) + os.sep
                fname = p.name
                rel = p.parent.relative_to(base).as_posix()
                shq_path = "./" if rel in ("", ".") else f"./{rel}/"
                full = str(p.resolve())
                h = SleepHQ.SHQImports.compute_sleephq_content_hash(full)
                results.append(
                    {"filepath": abs_dir,
                            "filename": fname,
                            "path": shq_path,
                            "content_hash": h
                            }
                        )
            return results

def main() -> None:

    '''main CLI (for testing)'''

    key = os.getenv("SLEEPHQ_CLIENT_ID")
    secret = os.getenv("SLEEPHQ_CLIENT_SECRET")
    if not key or not secret:
        print("Missing SleepHQ credentials in environment variables.")
        sys.exit(1)

    shq = SleepHQ(key, secret, verbose=True)
    print(f"Logged in as: {repr(shq)}")

    shq.create_upload()
    shq.gather_files("./LatestCPAP")
    shq.add_files()
    shq.process_upload()
    shq.validate_upload()

if __name__ == "__main__":
    main()
