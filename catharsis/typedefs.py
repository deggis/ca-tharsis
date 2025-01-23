from enum import Enum, auto
from typing import List, Optional, TypeAlias, NamedTuple, Any
import argparse

RunConf: TypeAlias = argparse.Namespace

from typing import TypeAlias, NamedTuple


class AzureSub(NamedTuple):
  id: str    # /subscriptions/GUID
  guid: str  # GUID
  raw: dict  # Original data

class UserTargetingDefinition(NamedTuple):
  included_users: List[str]
  included_groups: List[str]
  included_roles: List[str]
  includeGuestsOrExternalUsers: List[str]
  excluded_users: List[str]
  excluded_groups: List[str]
  excluded_roles: List[str]
  excludeGuestsOrExternalUsers: List[str]

class PolicyModel(NamedTuple):
  id: str
  # General information to help reporting
  name: str
  members: Any
  enabled: bool
  targeting_definition: Any
  # Conditions
  condition_usergroups: Any
  condition_applications: Any
  condition_application_user_action: Any
  condition_client_app_types: Any
  condition_signin_risk_levels: Any
  condition_user_risk_levels: Any
  # Controls
  grant_operator: Any # And, Or, Block, None
  grant_controls: Any
  grant_authentication_strength: Any
  session_controls: Any

class GeneralInfo(NamedTuple):
  disjoint_artificial_user_groups: Any
  disjoint_artificial_app_groups: Any
  seen_grant_controls: Any
  seen_session_controls: Any
  seen_app_user_actions: Any
  users_count: Any
  apps_count: Any

class PrincipalType(Enum):
  User = auto()
  ServicePrincipal = auto()
  Unknown = auto()

  def __repr__(self) -> str:
    return str(self.value)

class ServicePrincipalType(Enum):
  # https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals?tabs=browser#service-principal-object
  ManagedIdentity = 'ManagedIdentity'
  Application = 'Application'
  Legacy = 'Legacy'
  # https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0
  # For 'internal use'
  SocialIdp = 'SocialIdp'
  Unknown = 'Unknown'

class ServicePrincipalDetails(NamedTuple):
  servicePrincipalType: ServicePrincipalType

class UserPrincipalDetails(NamedTuple):
  upn: str   # User principal name

class Principal(NamedTuple):
  id: str                 # GUID
  displayName: str
  accountEnabled: bool
  raw: dict               # Raw data
  usertype: PrincipalType # User or SP
  spDetails: Optional[ServicePrincipalDetails] = None
  userDetails: Optional[UserPrincipalDetails] = None

  def __repr__(self) -> str:
    return principal_to_string(self)

def principal_to_string(o: Principal) -> str:
  if o.usertype == PrincipalType.User:
    return f"User: {o.displayName}"
  elif o.usertype == PrincipalType.ServicePrincipal:
    spType = o.spDetails.servicePrincipalType.value if o.spDetails else '!'
    return f"SP/{spType}: {o.displayName}"
  else:
    raise Exception('Unknown principal type')