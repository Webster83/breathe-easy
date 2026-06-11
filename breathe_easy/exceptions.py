
class SleepHQError(Exception):
    """Base exception"""


class AuthenticationError(SleepHQError):
    pass


class RequestError(SleepHQError):
    pass
