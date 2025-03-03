import math
import os

from typing import Iterable, Set

from catharsis.typedefs import PrincipalGuid, RunConf
from catharsis.graph_query import get_group_transitive_members, get_role_transitive_members

import catharsis.typedefs as CT
import catharsis.graph_query as queries


def ensure_cache_and_workdir(args: RunConf):
  if args.persist_cache_dir and not os.path.exists(args.persist_cache_dir):
    os.makedirs(args.persist_cache_dir)
  
  if args.report_dir and not os.path.exists(args.report_dir):
    os.makedirs(args.report_dir)


def count_s(a, b):
  frac = math.floor(a / b * 100)
  return '%d of %d / %s %%' % (a,b,frac)


async def list_ca_referred_groups_roles(args):
  groups, roles = [], []
  ca_defs = await queries.get_ca_policy_defs(args)
  for ca_policy in ca_defs:
    user_targeting = ca_policy['conditions']['users']
    groups.extend(user_targeting.get('includeGroups', []))
    roles.extend(user_targeting.get('includeRoles', []))
    groups.extend(user_targeting.get('excludeGroups', []))
    roles.extend(user_targeting.get('excludeRoles', []))
    # TODO: include/excludeGuestsOrExternalUsers missing

  return set(groups), set(roles)


async def prefetch_ca_memberships_with_query(args):
  groups, roles = await list_ca_referred_groups_roles(args)

  for role_id in roles:
    await get_role_transitive_members(args, role_id)

  for group_id in groups:
    await get_group_transitive_members(args, group_id)


def principal_to_principal_id(principal: CT.Principal) -> PrincipalGuid:
  return principal.id


def principals_to_id_set(principals: Iterable[CT.Principal]) -> Set[PrincipalGuid]:
  return set([p.id for p in principals])


def assignedmembers_to_id_set(members: Iterable[CT.AssignedMember]) -> Set[PrincipalGuid]:
  return set([p.principalId for p in members])


def principal_dict_to_id_set(principals: dict[str, CT.Principal]) -> Set[PrincipalGuid]:
  return principals_to_id_set(principals.values())


def is_principal_account_enabled(principal: CT.Principal):
  return principal.accountEnabled


def is_user_external(principal: CT.Principal):
  assert principal.usertype == CT.PrincipalType.User  # Can't answer this for SPs
  if principal.userDetails:
    return '#EXT#@' in principal.userDetails.upn


def filter_ca_defs(args, ca_defs):
  if not args.include_report_only:
    return [ca for ca in ca_defs if ca['state'] == 'enabled']
  else:
    return ca_defs

def is_cache_persisted(args: RunConf):
  return args.persist_cache_dir is not None

def tenant_to_str(tenant: CT.Tenant):
  return f'{tenant.displayName}: {tenant.defaultDomain} ({tenant.tenantId})'


def prepare_debug():
  import debugpy
  debugpy.listen(5678)
  print("Waiting for debugger attach")
  debugpy.wait_for_client()
  debugpy.breakpoint()
  print('break on this line')