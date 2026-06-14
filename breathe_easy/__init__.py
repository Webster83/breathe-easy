
"""
breathe_easy package public API
"""

# ---- Models
from .models import (
    SleepHQAPIAuthCredentials,
    SleepHQProfile,
    SleepHQImport,
    SleepHQFile,
    SleepHQMask,
)

# ---- Config
from .config import (
    HTTPValues,
    APIValues,
    SleepHQClientConfig,
)

# ---- Core API
from .sleephq import SleepHQ

# ---- Utilities (SAFE: no top-level circular imports)
from .ezshare_getter import run_ezshare
from .connect_wifi_windows import connect_wifi

__all__ = [
    # Core
    "SleepHQ",

    # Models
    "SleepHQAPIAuthCredentials",
    "SleepHQProfile",
    "SleepHQImport",
    "SleepHQFile",
    "SleepHQMask",

    # Config
    "HTTPValues",
    "APIValues",
    "SleepHQClientConfig",

    # Utilities
    "run_ezshare",
    "connect_wifi",
]
