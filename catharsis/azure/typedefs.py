from typing import TypeAlias, NamedTuple

class AzureSub(NamedTuple):
  id: str    # /subscriptions/GUID
  guid: str  # GUID
  name: str  # Name
  raw: dict  # Original data


class AzureMG(NamedTuple):
  id: str    # /providers/...
  name: str  # name
  raw: dict  # Original data