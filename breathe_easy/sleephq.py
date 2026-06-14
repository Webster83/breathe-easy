'''
sleephq.py
A SleepHQ V1 API Python Library
V2.0 
Written by BChap - SleepHQ Community Forum Member
Sleep HQ API reference last pulled 
2026-05-30 from https://sleephq.com/api-docs/index.html
Last Updated 20260613

This represents a complete, ground-up re-write of code for interacting with sleephq endpoints. 
- HTTP session is re-used across all non-auth endpoints (OAuth is handled at a different base url)
- dataclasses are utilized to logically containerize representative data from the models. These are
 not complete models, but values contained are ones that are useful for performing data uploads 
 and setting preferences like default mask. Further work can be made to extend the dataclass for
 a more complete alignment with the data models provided for by the endpoints. This may be useful
 in building out analytic capabilities. A future #ToDo but will not break applications or scripts
 implementing the library as it exists today 
 - Logging is used throughout. If the library is called as an import, it will use existing logging
  provided by logger
 - Retries and reauthentication are handled gracefully by the library, rather than requiring the
  implementing application or script to handle these cases
 - Newly available mask endpoint support added

'''

# must be at the beginning:
from __future__ import annotations

import sys
import time
import logging
import hashlib
from typing import Optional, List
from datetime import datetime
from pathlib import Path

import requests
from requests.exceptions import RequestException, HTTPError, Timeout
from tqdm import tqdm

from .config import APIValues, HTTPValues, SleepHQClientConfig
from .models import (
    SleepHQAPIAuthCredentials,
    SleepHQFile,
    SleepHQImport,
    SleepHQProfile,
    SleepHQMask
)

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# Import Windows Truststore for Proxy/MITM DPI (NetSkope etc.)
if sys.platform.startswith("win"):
    try:
        import truststore  # type: ignore
        truststore.inject_into_ssl()  # type: ignore[attr-defined]
    except ImportError as e:
        logger.error("Could not inject truststore")
        print(f"Could not inject truststore: {e}")

# Configure logging unique to the execution if
# logging hasn't been set up by a script/application
# leveraging sleephq library

class SleepHQ:
    '''Client class for interacting with SleepHQ API endpoints'''

    def __init__(
        self,
        base_url: str,
        credentials: SleepHQAPIAuthCredentials,
        http_values: Optional[HTTPValues] = None,
        api_values: Optional[APIValues] = None,
        profile: Optional[SleepHQProfile] = None,
        debug: Optional[bool] = None
    ):
        if not base_url.startswith(("http://", "https://")):
            raise ValueError(f"Invalid base_url: {base_url}")

        self.config = SleepHQClientConfig(base_url=base_url.rstrip("/"),debug=bool(debug))
        self.credentials = credentials
        self.api_values = api_values or APIValues()
        self.http_values = http_values or HTTPValues()
        self.profile = profile
        self.session = requests.Session()


    # ----- Internal Methods -----

    def _calculate_hash(self, shq_file: SleepHQFile):

        '''Calculates the content hash for a given file
        writing the hash to the SleepHQFile instance'''

        md5 = hashlib.md5()

        with open(shq_file.file_path, "rb") as f:

            for chunk in iter(lambda: f.read(1024 * 1024), b""):

                md5.update(chunk)

        md5.update(shq_file.name.encode())
        return md5.hexdigest()

    def _send(self,
            method: str,
            url: str,
            *,
            headers=None,
            api: APIValues,
            http: HTTPValues
            ):

        if self.config.debug:
            logger.debug("SEND [%s] -> %s",method.upper(),url)
            logger.debug("API: %s",api)

        return self.session.request(method,
                                    url,
                                    headers=headers,
                                    timeout=http.timeout,
                                    params = api.params,
                                    data=api.data,
                                    json=api.json,
                                    files=api.files
                                    )

    def _unwrap(self, response):

        '''unwraps so that we can get to the payload'''
        return response.get("data") if isinstance(response,dict) else response

    def _reauthenticate_if_needed(self,
                                  response: requests.Response
                                  ) -> bool:

        '''
        Checks if response indicates expired/invalid token, and re-authenticates.
        '''
        if response.status_code == 401:
            logger.warning("401 Unauthorized - token likely expired. Performing reauthentication")
            self.authenticate()
            return True
        try:
            error_data = response.json()
            if "unknown bearer token" in error_data.get("error", "").lower():
                logger.warning("Bearer token expired. Re-authenticating...")
                self.authenticate()
                return True

        except ValueError:
            pass

        return False

    def _request_with_retries(self,
                              method: str,
                              endpoint: str,
                              *,
                              api:Optional[APIValues]=None,
                              http:Optional[HTTPValues]=None,
                              headers:Optional[dict]=None,
                              use_auth: bool = True
                            ):

        api = api or self.api_values
        http = http or self.http_values
        url = endpoint if endpoint.startswith("http") else \
        f"{self.config.base_url}/{endpoint.lstrip('/')}"

        if self.config.debug:
            logger.debug("REQUEST WITH RETRIES LAYER")
            logger.debug("Method: %s",method.upper())
            logger.debug("DATA: %s", api.data)

        req_headers = headers.copy() if headers else {}

        if use_auth and self.credentials.bearer_token:
            req_headers["Authorization"] = f"Bearer {self.credentials.bearer_token}"

        for attempt in range(1, http.max_retries + 1):
            try:
                logger.debug("%s %s (Attempt %s)", method.upper(), url, attempt)

                resp = self._send(method,
                                  url,
                                  headers=req_headers,
                                  api=api,
                                  http=http
                                  )

                if self._reauthenticate_if_needed(resp):
                    logger.info("Re-authenticated. Retrying request...")
                    req_headers["Authorization"] = f"Bearer {self.credentials.bearer_token}"
                    continue

                resp.raise_for_status()
                if self.config.debug:
                    logger.debug("RETURNING RESPONSE FROM: %s",method.upper())
                return resp

            except (RequestException, HTTPError, Timeout) as e:
                logger.error("Request error: %s", e)

                if attempt == http.max_retries:
                    raise RuntimeError(f"{method.upper()} failed after {attempt} attempts") from e

                sleep_time = http.backoff_factor ** attempt
                logger.info("Retrying in %.1fs...", sleep_time)
                time.sleep(sleep_time)

        raise RuntimeError("Unreachable")

    def _handle_response(
        self,
        response: requests.Response,
    ):
        '''
        Handles response, retries auth if needed, and returns parsed data.
        '''

        try:
            if response.text.strip():
                return response.json()
            return None
        except HTTPError as e:
            raise RuntimeError(f"HTTP {response.status_code}: {response.text}") from e
        except ValueError:
            return response.text

    # ----- Authentication -----

    def authenticate(self):

        '''Performs authentication to obtain bearer token and updates session headers
        for future requests'''

        logger.info("Authenticating with SleepHQ API...")

        resp = requests.post(self.credentials.auth_url,
            data={
                "client_id": self.credentials.connection_key,
                "client_secret": self.credentials.connection_secret,
                "grant_type": "password",
                "scope": "read write delete"
            },
            timeout=self.http_values.timeout
        )

        resp.raise_for_status()

        token = resp.json().get("access_token")
        if not token:
            raise RuntimeError("No access token returned")
        logger.info("Bearer token %s obtained successfully", token)
        self.credentials.bearer_token = token

        self.session.headers["Authorization"] = f"Bearer {token}"
        logger.info("Authentication successful")

    # ----- Public HTTP Methods -----

    def get(
        self,
        endpoint: str,
        *,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
    ):
        '''
        Performs GET request
        '''

        resp = self._request_with_retries(
            "get",
            endpoint,
            api=APIValues(params = params),
            headers=headers,
        )

        return self._handle_response(resp)

    def post(
        self,
        endpoint: str,
        *,
        data: Optional[dict] = None,
        files: Optional[dict]= None,
        headers: Optional[dict] = None,
        http: Optional[HTTPValues] = None
        ):

        '''constructs and sends a POST request'''

        api = APIValues(
            data = data if files else None,
            json = data if not files else None,
            files = files
        )

        resp = self._request_with_retries(
            "post",
            endpoint,
            api = api,
            headers=headers,
            http = http
        )

        if self.config.debug:
            logger.debug("=== CLIENT ACTUAL REQUEST ===")
            logger.debug("METHOD: %s", resp.request.method)
            logger.debug("URL: %s", resp.request.url)
            logger.debug("HEADERS: %s", dict(resp.request.headers))
            logger.debug("BODY: %s", resp.request.body)
            logger.debug("============================")

        return resp

    def put(
            self,
            endpoint: str,
            *,
            data=None,
            headers=None,
        ):

        '''
        Performs PUT request 
        '''

        resp = self._request_with_retries(
            "put",
            endpoint=endpoint,
            api=APIValues(data=data),
            headers=headers
            )

        return self._handle_response(resp)

    def delete(
            self,
            endpoint: str,
            *,
            headers = None
        ):

        '''
        Performs DELETE request with optional auth handling.
        '''

        resp = self._request_with_retries(
            "delete",
            endpoint,
            headers=headers
        )

        return self._handle_response(resp)

    # ----- Externally Callable Methods -----

    def get_profile(self) -> SleepHQProfile:

        '''Fetches user profile data and returns a SleepHQProfile instance'''

        data = self._unwrap(self.get("v1/me"))

        if not isinstance(data, dict):
            raise RuntimeError(f"Unexpected profile data format: {data}")

        name = data.get('name')
        team_id = data.get('current_team_id')
        mask_id = data.get('mask_id')
        if not isinstance(name,str):
            raise RuntimeError(f'Invalid name. Received: {name}')
        if not isinstance(team_id,int):
            raise RuntimeError(f'Invalid team id format. Received: {team_id}')
        if mask_id:
            if not isinstance(mask_id,int):
                raise RuntimeError('invalid mask id format. Received {type(mask_id)}')
        logger.info("get_profile() returned %s,%s,%s",name,team_id,mask_id)
        return self.set_profile(name=name,team_id=team_id,mask_id=mask_id)

    def set_profile(self,**kwargs) -> SleepHQProfile:

        '''sets the profile, either from an already sanitized get() or a 
        validated manual call, requiring kwargs of "name" and "team_id"
        '''
        name = kwargs.get('name')
        team_id = kwargs.get('team_id')
        mask_id = kwargs.get('mask_id')
        logger.info("set_profile call received: %s,%s,%s",name,team_id,mask_id)
        if isinstance(name, str) and isinstance(team_id, int):
            if isinstance(mask_id,int):
                return SleepHQProfile(name, team_id,user_default_mask_id=mask_id)
            return SleepHQProfile(user_name=name ,current_team_id=team_id)

        logger.error(
            "Insufficient or invalid arguments passed to create profile manually\n"
            "Getting programmatically"
        )
        return self.get_profile()

    def get_masks(self, profile: SleepHQProfile):

        '''gets the user's masks for the mask endpoint and updates the profile
        to reflect those masks'''

        data = self._unwrap(
            response=self.get(
                f"v1/teams/{profile.current_team_id}/masks"
            )
        )

        if not isinstance(data,list):
            raise RuntimeError(f"Unexpected data format: {data}")

        sorted_masks = self.build_sorted_masks(data)
        profile.user_all_masks = sorted_masks

    def build_sorted_masks(self,masks: list[dict]) -> List[SleepHQMask]:
        '''Builds a list of sorted SleepHQMask by date_last_used, reversed'''
        mask_list = []
        for mask in masks:
            mask = SleepHQMask(
                id=int(mask['id']),
                name=mask['attributes']['name'],
                last_used_on=mask['attributes']['last_used_on'],
                nickname=mask['attributes']['nickname']
            )
            mask_list.append(mask)

        mask_list.sort(key=lambda m: m.last_used_on,reverse=True)
        return mask_list

    def set_mask(self,profile:SleepHQProfile) -> bool:

        '''Displays a list of masks with index number, nickname (if set) else name,
        last used (sorted most recent at top) and prompts for user to enter 
        id for mask used (optionally set as default)'''

        masks = profile.user_all_masks
        if not masks:
            logger.info("No masks in profile")
            return False

        print("Available Masks:")
        valid_ids=set()

        for mask in masks:
            display_name = mask.nickname if mask.nickname else mask.name
            print(f"ID:{mask.id} | Name: {display_name} | Last Used: {mask.last_used_on}")
            valid_ids.add(mask.id)
        # Add the 'Default is no default' option to the valid set. This way a user can bypass this
        # if they would rather set manually
        valid_ids.update([-1,-2]) #add 'not this time' 'never ask'


        while True:
            try:
                choice = input(
                "Enter the ID of the mask to set as default."
                    "\n-1: 'Persistent No Default', set via SleepHQ.com"
                    " -2: 'I need to add a mask on SleepHQ (set via SleepHQ.com): ").strip()

                selected_id = int(choice)

                if selected_id in valid_ids:
                    print(f"Mask {selected_id} selected")

                    if selected_id == -2:
                        # no mask to set with import, keep as None
                        # for this import only, don't store
                        profile.user_default_mask_id = None
                        return False

                    if selected_id == -1:
                        profile.user_default_mask_id = -1
                        return True
                    else:
                        while True:
                            try:
                                default_it = input(f"Make {selected_id} your default mask? Y/N: ")

                                if default_it.upper().strip() == "Y":
                                    profile.user_default_mask_id = selected_id
                                    logger.info("Mask %s set as default", selected_id)
                                    print("Setting this as your default")
                                    return True

                                elif default_it.upper().strip() == "N":
                                    print(f"{selected_id} being used for this import only")
                                    return False

                                else:
                                    print("Invalid Y/N response. Please enter Y or N")
                                    # no break, force re-ask
                            except ValueError:
                                print("Invalid input. Please enter an alpha character of"\
                                " 'Y' or 'N'") 

                else:
                    print("Invalid ID. Please choose from the listed IDs")
            except ValueError:
                print("Invalid input. Please enter a numeric ID")

    def create_import(self,profile:SleepHQProfile):
        '''creates a SleepHQImport'''
        generate_name = f"Breathe_Easy_V2_{datetime.now().strftime('%Y%m%d-%H:%M')}"
        shq_import = SleepHQImport(profile.current_team_id,
                        name=generate_name,
                        mask_id=profile.user_default_mask_id,
                        programatic=True)
        if shq_import.mask_id == -1: # user doesn't want a default mask... EVER
            shq_import.mask_id = None # if there's any SleepHQ backend validation, it won't
                                      # understand a -tve value for mask_id. Fix it here
        return shq_import

    def get_import_id(self,imprt:SleepHQImport)->int:
        '''creates an import ID'''
        payload = {
            "programatic": imprt.programatic,
            "name": imprt.name,
            "mask_id": imprt.mask_id
        }

        headers = {
                "Accept": "application/json"
        }
        resp = self.post(f"v1/teams/{imprt.team_id}/imports",data=payload,headers=headers)

        if self.config.debug:
        # IMMEDIATELY inspect the POST response
            logger.debug("===== ISOLATED GET_IMPORT_ID RESPONSE =====")
            logger.debug("METHOD:%s", resp.request.method)
            logger.debug("URL:%s", resp.request.url)
            logger.debug("BODY:%s", resp.request.body)
            logger.debug("==============================================\n")

        data = resp.json()

        if self.config.debug:
            logger.debug("POST JSON:%s", data)

        imprt.import_id = int(data["data"]["id"])

        # We have an import ID, we can now safely execute next steps that require
        # an import ID

        self.config.valid_state["imp_id_exists"] = True
        logger.info("Created import ID %s", imprt.import_id)

        return imprt.import_id

    def create_file_queue(self,root_dir:str,
                          import_id: int
                          ) -> Optional[list[SleepHQFile]]:
        '''creates a list of SleepHQ File instances representing
        files to be uploaded. '''

        if not self.config.valid_state.get("imp_id_exists"):
            logger.error("Import ID must be created. Halting execution")
            print("Error, see log for details")
            sys.exit(1)

        file_queue: list[SleepHQFile] = []
        root_path = Path(root_dir)

        if not root_path.exists():
            raise ValueError(f"Root directory does not exist: {root_dir}")

        for path in root_path.rglob("*"):
            if not path.is_file():
                continue

            try:
                relative_path = path.relative_to(root_path)
                shq_file = SleepHQFile(
                    import_id = import_id,
                    name = path.name,
                    relative_path = str(relative_path),
                    file_path = str(path),
                    content_hash=""
                )

                shq_file.content_hash = self._calculate_hash(shq_file)
                file_queue.append(shq_file)
                logger.info("Added file to queue: %s (hash: %s)",
                            shq_file.relative_path, shq_file.content_hash)

            except (OSError, PermissionError, FileNotFoundError, RuntimeError) as e:
                logger.warning("Skipping file %s due to error: %s", path, e)

        logger.info("Built file queue with %d files", len(file_queue))
        self.config.valid_state["file_queue_created"] = True
        self.config.file_queue = file_queue

    def upload_files(self,imprt:SleepHQImport):

        '''Uploads the files associated with the given import.
        For each file in the payload, we POST the file to the upload endpoint'''

        if not self.config.valid_state.get("file_queue_created"):
            logger.error("File queue must be created before attemping upload")
            print("Error, see log for details")
            time.sleep(5)
            sys.exit(1)
        current_file = 1
        num_of_files = len(self.config.file_queue)

        for file in tqdm(self.config.file_queue, desc="Uploading", unit="files"):
            logger.info("Uploading file %s of %s: %s", current_file,num_of_files,file.name)
            with open(file.file_path,"rb") as f:
                self.post(
                            f"/v1/imports/{imprt.import_id}/files",
                            data={
                                "name":file.name,
                                "path":file.relative_path,
                                "content_hash":file.content_hash
                            },
                            files= {"file": (file.name,f)},
                            http=HTTPValues(max_retries = 5, backoff_factor = 2.0)
                        )
                current_file +=1

        print("All files uploaded successfully")
        self.config.valid_state['uploads_completed'] = True

    def process_import(self,imprt:SleepHQImport):
        '''Tells SleepHQ to process the import once all files
        are uploaded'''

        if not self.config.valid_state.get("uploads_completed"):
            logger.error("Files must be uploaded before processing import")
            print("Error, see log for details")
            time.sleep(5)
            sys.exit(1)

        self.post(f"/v1/imports/{imprt.import_id}/process_files")
        logger.info("Requested processing for import %s", imprt.import_id)
        self.config.valid_state['process_imported'] = True

    def validate_import(self,imprt:SleepHQImport):
        '''Validates the import to ensure all files were uploaded
        successfully and the import is ready for processing'''

        if not self.config.valid_state.get("process_imported"):
            logger.error("Uploads must be processed before validating the import")
            print("Error, see log for details")
            time.sleep(5)
            sys.exit(1)

        try:
            resp = self.get(f"v1/imports/{imprt.import_id}")
        except Exception as e:
            logger.error("Failed to validate import %s: %s", imprt.import_id, e)
            raise RuntimeError(
                f"Failed to validate import {imprt.import_id}: {e}") from e

        try:
            data = self._unwrap(resp)

            if not isinstance(data, dict):
                raise RuntimeError(f"Unexpected response format: {data}")

            attrs = data.get("attributes", {})
            if not isinstance(attrs, dict):
                raise RuntimeError(f"Invalid attributes format: {attrs}")

            failed_reason = attrs.get("failed_reason")

        except Exception as e:
            logger.error("Unexpected response format during validation: %s", e)
            raise RuntimeError(
                f"Unexpected response format while validating import {imprt.import_id}: {e}"
            ) from e

        if failed_reason not in (None, "null"):
            logger.error("Import %s failed validation: %s",imprt.import_id, failed_reason)
            raise RuntimeError(f"Import {imprt.import_id} indicates failure:"\
                               f" failed_reason: {failed_reason}"
        )

        logger.info("Import %s validated successfully", imprt.import_id)

    def is_valid_mask (self,mask_id:int,profile:SleepHQProfile)->bool:

        ''' checks if a valid mask'''

        self.get_masks(profile)
        masks = profile.user_all_masks
        valid_ids = set()
        if masks:
            valid_ids.update([-1,-2])
            for mask in masks:
                valid_ids.add(int(mask.id))

            if mask_id in valid_ids:
                return True
        logger.warning("%s is not found in %s",mask_id,valid_ids)
        return False


# ------------------------ Main / Testing ------------------------#
# This is a library, and as such is designed for instantiation    #
# via import from another script / application. The main is just  #
# example process logic for library development testing and a     #
# "springboard" to build an application using this library        #
###################################################################

def main():

    '''
    See Main/Testing block comment above
    '''

    # ----- Create a credentials object and client instance -----

    connection_key = input("Enter SleepHQ Client ID Key: ")
    connection_secret = input("Enter SleepHQ Client Secret: ")
    creds = SleepHQAPIAuthCredentials(
        connection_key,
        connection_secret
    )

    client = SleepHQ(base_url="https://sleephq.com/api", credentials=creds)

    # ----- Authenticate to obtain bearer token -----

    client.authenticate()

    # ----- Create user profile dataclass instance -----
    # Note:efficient usage calls for this to be obtained only upon
    # 1st execution, then stored in a file for future use. This should be
    # implemented at the application/script level for flexibility

    profile = client.get_profile()

    client.get_masks(profile)

    # ----- set default mask -----
    # Again, efficient usage calls for this to be obtained only upon
    # 1st execution, unless the default mask changes or becomes
    # invalid. Safeguarding should be done to make sure the
    # default_mask is still a valid mask, since the user can
    # delete a mask at any time

    client.set_mask(profile) # we could have captured the return
                                     # value, but since we don't store
                                     # this profile in testing, no point

    # ----- build the import object -----
    # get the import id, build the upload
    # queue, upload the queue, perform
    # upload validation then finalize

    shq_import = client.create_import(profile)
    shq_import.import_id = client.get_import_id(shq_import)

    root_dir = input("Enter relative path of folder with xPAP data (eg LatestCPAP):")

    print("Creating the Upload Queue")
    client.create_file_queue(root_dir,import_id=shq_import.import_id)

    if client.config.debug:
        logger.debug("file_queue contents:")
        for f in client.config.file_queue:
            logger.debug("%s",f)

    print("Uploading files...")
    client.upload_files(shq_import)

    print("Proccessing import...")
    client.process_import(shq_import)

    print("Validating import...")
    client.validate_import(shq_import)

if __name__ == "__main__":
    main()
