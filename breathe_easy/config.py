'''config.py'''

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from .models import SleepHQFile

@dataclass
class HTTPValues:

    ''' stores values for HTTP arguments '''
    timeout: int = 10
    max_retries: int = 3
    backoff_factor: float = 1.5


@dataclass
class APIValues:

    ''' stores arguments commonly used in
    API calls '''

    params: Optional[Dict[str, Any]] = None
    data: Optional[Dict[str, Any]] = None
    json: Optional[Dict[str, Any]] = None
    files: Optional[Dict[str, Any]] = None

@dataclass
class SleepHQClientConfig:

    ''' Stores the SleepHQ class config '''

    base_url: str
    debug: bool = False
    file_queue: List[SleepHQFile] = field(default_factory=list)
    valid_state: Dict[str, bool] = field(default_factory=lambda: {
        "imp_id_exists": False,
        "file_queue_created": False,
        "uploads_completed": False,
        "import_processed": False,
        "import_validated": False
    })
