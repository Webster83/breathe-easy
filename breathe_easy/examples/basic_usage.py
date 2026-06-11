'''basic_usage.py'''

from breathe_easy.sleephq import SleepHQ
from breathe_easy.models import SleepHQAPIAuthCredentials

creds = SleepHQAPIAuthCredentials(
    connection_key="your_key",
    connection_secret="your_secret"
)

client = SleepHQ(
    base_url="https://sleephq.com/api",
    credentials=creds
)

client.authenticate()

print(client.get("v1/me"))
