import os
from typing import List, Tuple, Callable, Mapping, TypeAlias, Set

from catharsis.graph_query import cached_query, ensure_cache_matches, get_group_transitive_members, get_msgraph_client
from catharsis.ms_credential import get_ms_credential
from catharsis.typedefs import RunConf
from azure.mgmt.resourcegraph.models import QueryRequest
from azure.mgmt.resourcegraph.models import QueryRequestOptions
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.resourcegraph import ResourceGraphClient

import catharsis.typedefs as CT
import catharsis.cached_get as c

import logging
logger = logging.getLogger('catharsis.azure.azure_resource_graph_queries')
logger.setLevel(logging.INFO)

# ResultPathResolver: TypeAlias = Callable[[str], str]
# ALL_QUERIES: List[Tuple[ResultPathResolver, str]] = []

get_az_result_path: Callable[[RunConf, str], str] = lambda runconf, fn: os.path.join(runconf.work_dir, fn)


async def get_azrm_client(args: RunConf):
  credential = get_ms_credential(args)
  client = ResourceGraphClient(credential=credential, subscription_id=args.subscription_id)
  await ensure_cache_matches(args)
  return client

async def get_azmgmt_client(args: RunConf):
  credential = get_ms_credential(args)
  client = ResourceManagementClient(credential=credential, subscription_id=args.subscription_id)
  await ensure_cache_matches(args)
  return client

async def get_az_auth_mgmt_client(args: RunConf):
  credential = get_ms_credential(args)
  client = AuthorizationManagementClient(credential=credential, subscription_id=args.subscription_id)
  await ensure_cache_matches(args)
  return client

# Resource containers
ALL_QUERIES: List[Tuple[str, str]] = []

SUBSCRIPTIONS_FILE = "azure_subscriptions.json"
SUBSCRIPTIONS_QUERY = 'resourcecontainers | where type == "microsoft.resources/subscriptions" | project id, name, tenantId, subscriptionId, tags, properties'
def subscription_formatter(obj) -> Tuple[CT.SubGuid, CT.AzureSub]:
  sub_id = obj['id']
  sub_guid = sub_id.split('/')[-1]
  sub = CT.AzureSub(id=sub_id, guid=sub_guid, name=obj['name'], raw=obj)
  return sub_guid, sub

ALL_QUERIES.append((SUBSCRIPTIONS_FILE, SUBSCRIPTIONS_QUERY))


MANAGEMENT_GROUPS_FILE = "azure_managementgroups.json"
MANAGEMENT_GROUPS_QUERY = 'resourcecontainers | where type == "microsoft.management/managementgroups" | project id, name, tenantId, tags, properties'
ALL_QUERIES.append((MANAGEMENT_GROUPS_FILE, MANAGEMENT_GROUPS_QUERY))
def managementgroup_formatter(obj) -> Tuple[CT.MGName, CT.AzureMG]:
  mg_name = obj['name'].lower()
  mg = CT.AzureMG(id=obj['id'], name=mg_name, displayName=obj['properties']['displayName'], raw=obj)
  return mg_name, mg


async def resource_graph_query(args: RunConf, kql_query: str):
  client = await get_azrm_client(args)
  query = QueryRequest(query=kql_query)
  query.options = QueryRequestOptions(top=1000)
  result = []
  logger.info('Querying KQL: %s ..', kql_query[:50])
  resp = client.resources(query)
  result.extend(resp.data)
  while resp.skip_token:
    query = QueryRequest(query=SUBSCRIPTIONS_QUERY)
    logger.info('Querying for with skip_token: %s...', resp.skip_token[:50])
    query.options = QueryRequestOptions(skip_token=resp.skip_token)
    resp = client.resources(query)
    result.extend(resp.data)
  return result


async def _cached_get(args: RunConf, cache_key_fn: Callable, kql_query: str, formatter_fn: Callable) -> Mapping:
  cache_key = cache_key_fn(args)
  async def fn():
    query_results = await resource_graph_query(args, kql_query)
    results = {}
    for obj in query_results:
      key, item = formatter_fn(obj)
      results[key] = item
    return results
  return await cached_query(args, cache_key, fn)

async def get_subscriptions(args: RunConf) -> CT.AzureSubs:
  return await _cached_get(args, c.mk_azure_subs, SUBSCRIPTIONS_QUERY, subscription_formatter)

async def get_managementgroups(args: RunConf) -> Mapping[CT.MGName, CT.AzureMG]:
  return await _cached_get(args, c.mk_azure_mgs, MANAGEMENT_GROUPS_QUERY, managementgroup_formatter)

def map_rbac_assignment(role_assignment) -> CT.AzureRBACAssignment:
  principal_type = role_assignment.principal_type
  if principal_type == 'ServicePrincipal':
    principal_type = 'SP'
  principal_type_type = CT.PrincipalType(principal_type)
  role_guid = role_assignment.role_definition_id.split('/')[-1]
  return CT.AzureRBACAssignment(
    id=role_assignment.id,
    principalId=role_assignment.principal_id,
    principalType=principal_type_type,
    roleGuid=role_guid,
    roleName=' '
  )

def map_assignments(assignments):
  results = []
  for a in assignments:
    if a.principal_type == 'ForeignGroup':
      logger.warning('Skipping ForeignGroup %s assignment for scope %s', a.principal_id, a.scope)
      continue
    results.append(map_rbac_assignment(a))
  return results

async def get_mg_raw_assignments(args: RunConf, mg: CT.AzureMG) -> List[CT.AzureRBACAssignment]:
  async def fn():
    client = await get_az_auth_mgmt_client(args)
    online_assignments = client.role_assignments.list_for_scope(mg.id)
    return map_assignments(online_assignments)
  return await cached_query(args, c.mk_azure_mg_assignment_raw_path(args, mg.name), fn)


async def get_sub_raw_assignments(args: RunConf, sub: CT.AzureSub) -> List[CT.AzureRBACAssignment]:
  async def fn():
    client = await get_az_auth_mgmt_client(args)
    # This actually gets roles that are assigned above sub. Nice.
    online_assignments = client.role_assignments.list_for_scope(sub.id)
    return map_assignments(online_assignments)
  return await cached_query(args, c.mk_azure_sub_assignment_raw_path(args, sub.guid), fn)


async def get_transitive_rbac_members(args, raw_assignments: List[CT.AzureRBACAssignment]) -> Tuple[CT.AzureContainerRoles, CT.AssignedMemberCollection]:
  members_excl_groups: dict[CT.PrincipalGuid, Set[CT.AzureRBACRoleGuid]] = {}
  assigned_members: dict[CT.PrincipalGuid, CT.AssignedMember] = {}

  def rbac_assignment_to_assignedmember(assignment: CT.AzureRBACAssignment) -> CT.AssignedMember:
    return CT.AssignedMember(principalId=assignment.principalId, principalType=assignment.principalType)
  
  for assignment in raw_assignments:
    if assignment.principalType == CT.PrincipalType.Group:
      group_members = await get_group_transitive_members(args, assignment.principalId)
      for group_membership in group_members:
        members_excl_groups.setdefault(group_membership.principalId, set()).add(assignment.roleGuid)
        if group_membership.principalId not in assigned_members:
          assigned_members[group_membership.principalId] = group_membership
    elif assignment.principalType == CT.PrincipalType.User:
      members_excl_groups.setdefault(assignment.principalId, set()).add(assignment.roleGuid)
      if assignment.principalId not in assigned_members:
        assigned_members[assignment.principalId] = rbac_assignment_to_assignedmember(assignment)
    elif assignment.principalType == CT.PrincipalType.ServicePrincipal:
      members_excl_groups.setdefault(assignment.principalId, set()).add(assignment.roleGuid)
      if assignment.principalId not in assigned_members:
        assigned_members[assignment.principalId] = rbac_assignment_to_assignedmember(assignment)
    else:
      raise Exception('Unknown referenced principal type: %s' % str(assignment.principalType))
  return members_excl_groups, assigned_members
