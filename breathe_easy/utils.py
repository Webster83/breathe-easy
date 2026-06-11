from datetime import datetime

def parse_ts(ts: str):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))