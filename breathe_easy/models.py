'''defines data models used'''

from dataclasses import dataclass
from typing import Optional, List


@dataclass
class SleepHQAPIAuthCredentials:

    '''Data class representing the authentication parameters
    used by SleepHQ'''

    connection_key: str
    connection_secret: str
    auth_url: str = "https://sleephq.com/oauth/token"
    bearer_token: Optional[str] = None


@dataclass
class SleepHQProfile:

    '''Data class representing a SleepHQ user profile, the 
    current team_id is tied to much of the post request calls'''

    user_name: str
    current_team_id: int
    user_all_masks: Optional[List["SleepHQMask"]] = None
    user_default_mask_id: Optional[int] = None


@dataclass
class SleepHQMask:

    '''Represents data associated with a specific user mask in SleepHQ'''

    id: int
    name: str
    last_used_on: str
    nickname: Optional[str] = None


@dataclass
class SleepHQFile:

    '''Data class of a SleepHQ file that is a payload of a 
    post file. A list of SleepHQFile is the upload_queue for a
    specific import '''

    import_id: int
    name: str
    relative_path: str
    file_path: str
    content_hash: str


@dataclass
class SleepHQImport:

    '''Describes the parameters used to create an import for SleepHQ'''

    team_id: int    # the individual's team_id (from profile)
    name: str       # the import name
    device_id: Optional[int] = None # the ID of the device originating the data
    mask_id: Optional[int] = None   # the mask ID to associate with the import (default mask)
    programatic: bool = False # While deprecated, still used to flag if the import is programatic
    import_id: Optional[int] = None # Once the import_id is requested from post of the
                                    # Import request with the above data, the import_id is stored
                                    # along with the import, for later usage