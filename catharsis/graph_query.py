import subprocess
import json
import os
from typing import List
from collections.abc import Callable, Awaitable

# Graph SDK stuff 

from msgraph import GraphServiceClient
from msgraph.generated.models.user import User as MSGUser
from msgraph.generated.models.service_principal import ServicePrincipal as MSGServicePrincipal
from msgraph.generated.models.unified_role_assignment import UnifiedRoleAssignment as MSGUnifiedRoleAssignment
from msgraph.generated.models.o_data_errors.o_data_error import ODataError

from msgraph.generated.role_management.entitlement_management.role_assignments.role_assignments_request_builder import RoleAssignmentsRequestBuilder
from msgraph.generated.users.users_request_builder import UsersRequestBuilder
from kiota_abstractions.native_response_handler import NativeResponseHandler
from kiota_http.middleware.options import ResponseHandlerOption
from kiota_abstractions.base_request_configuration import RequestConfiguration
from azure.identity import AzureCliCredential

from catharsis.typedefs import RunConf
import catharsis.typedefs as CT
import catharsis.cached_get as c

import logging
logger = logging.getLogger('catharsis.graph_query')
logger.setLevel(logging.INFO)

# Deprecated 'Use graph sdk'
def run_cmd(cmd_string, parse=False):
  print(f'run_cmd {cmd_string}')
  r = subprocess.run(cmd_string, shell=True, capture_output=True)
  if r.returncode != 0:
    err = r.stderr.decode('utf-8')
    print('run_cmd (%s), got error: %s' % (cmd_string, err))
    raise Exception(err)
  if parse:
    return json.loads(r.stdout.decode('utf-8'))
  else:
    return r.stdout

def do_az_graph_query(query, sub_ids=None, count=1000, skip_token=None, mgmt_group_guid=None):
    sub_filter = (' -s "%s"' % sub_ids) if sub_ids else ''
    mgmt_group = (' -m "%s"' % mgmt_group_guid) if mgmt_group_guid else ''

    command = "az graph query -q '%s' --first %d %s %s" % (query, count, sub_filter, mgmt_group)
    if skip_token:
        command += " --skip-token '%s'" % skip_token
    r = subprocess.run(command, shell=True, capture_output=True)
    return r

def fetch_az_graph_query(query, sub_ids=None, mgmt_group_guid=None):
    previous_skip_token = None
    fetches = 0
    fetched_records = 0
    total_records = None
    query_results = []
    while True:
        fetches += 1
        r = do_az_graph_query(query, sub_ids, skip_token=previous_skip_token, mgmt_group_guid=mgmt_group_guid)
        if r.stderr:
            raise(str(r.stderr))
        data = json.loads(r.stdout)
        query_results.append(data)

        if total_records is None:
            total_records = data['total_records']
        fetched_records += data['count']
        print('Fetched %d/%d' % (fetched_records, total_records), file=sys.stderr)

        previous_skip_token = data['skip_token']
        if not previous_skip_token:
            print('Done.', file=sys.stderr)
            if fetched_records != total_records:
                print('Done but fetched and total records does not match!', file=sys.stderr)
            break

    result_items = []
    for qr in query_results:
        result_items.extend(qr['data'])
    results = {
        'count': len(result_items),
        'data': result_items,
        'total_records': total_records
    }
    return results

def _run_graph_user_query(args, result_path, initial_url):
  temp_file = result_path+'_temp'
  all_users = []

  if os.path.exists(result_path):
    return

  run = True
  next_link = None
  result_missing = False

  while run:
    url = next_link if next_link else initial_url
    cmd = f"az rest --uri \"{url}\" > {temp_file}"

    try:
      run_cmd(cmd)
      with open(temp_file) as in_f:
        result = json.load(in_f)
        print('Allright: Cmd: %s' % cmd)
        next_link = result.get('@odata.nextLink')
        if next_link:
          next_link = next_link.replace('$', '\\$')  # TODO: get rid of shell
        for user in result['value']:
          all_users.append(user)

        if not next_link:
          run = False
    except Exception as e:
      if 'does not exist or one of its queried reference-property objects are not present' in str(e):
        run = False
        result_missing = True
      else:
        raise e

  if not os.path.exists(temp_file):
    os.remove(temp_file)

  if not result_missing:
    with open(result_path, 'w') as out_f:
      # Emulate Graph response structure with 'value': {}
      json.dump({'value': all_users}, out_f)
  else:
    with open(result_path, 'w') as out_f:
      # Emulate Graph response structure with 'value': {}
      # TODO: add warnings of these
      json.dump({'value': [], 'resource_was_deleted': True}, out_f)



# Graph SDK


def get_msgraph_client(args: RunConf):
  credential = AzureCliCredential()
  scopes = ['https://graph.microsoft.com/.default']
  return GraphServiceClient(credentials=credential, scopes=scopes)


async def do_msgraph_sdk_graph_query(request_builder, initial_method_name='get', req_conf=None):
   # https://github.com/microsoftgraph/msgraph-sdk-python?tab=readme-ov-file#32-pagination
  result = []

  # members.get?
  fn = getattr(request_builder, initial_method_name)
  params = {}
  if req_conf:
    params['request_configuration'] = req_conf

  response = await fn(**params)
  for o in response.value:
    result.append(o)
    
  while response is not None and response.odata_next_link is not None:
    response = await request_builder.with_url(response.odata_next_link).get()
    for o in response.value:
      result.append(o)
  
  return result


async def _get_msgraph_ca_policy_json(client: GraphServiceClient):
  req_config = client.identity.conditional_access.policies.PoliciesRequestBuilderGetRequestConfiguration(options=[ResponseHandlerOption(NativeResponseHandler())], )
  response = await client.identity.conditional_access.policies.get(request_configuration=req_config)
  if response:
    return response.json()
  else:
    raise Exception('Cannot get CA conf')

def fetch_ca_policy_gsdk(args: RunConf):
    pass

async def _get_msgraph_group_transitive_members(client: GraphServiceClient, group_id: str):
  """ https://graph.microsoft.com/v1.0/groups/{group_id}/transitiveMembers """
  return await do_msgraph_sdk_graph_query(client.groups.by_group_id(group_id=group_id).transitive_members)


async def _get_msgraph_all_users(client: GraphServiceClient) -> List[MSGUser]:
  """ https://graph.microsoft.com/beta/users?select=id,accountenabled,userPrincipalName """
  query_params = UsersRequestBuilder.UsersRequestBuilderGetQueryParameters(
    select = ['id', 'userPrincipalName', 'accountenabled', 'displayName']
  )
  request_configuration = RequestConfiguration(query_parameters=query_params)
  return await do_msgraph_sdk_graph_query(client.users, req_conf=request_configuration)


async def _get_msgraph_all_service_principals(client: GraphServiceClient) -> List[MSGServicePrincipal]:
  """ https://graph.microsoft.com/beta/users?select=id,accountenabled,userPrincipalName """
  return await do_msgraph_sdk_graph_query(client.service_principals)

def graph_api_stuff():
  """
    
    - https://graph.microsoft.com/beta/users?select=id,accountenabled,userPrincipalName
    - https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\\$filter=roleDefinitionId+eq+'{role_id}'&\\$expand=Principal
    - https://graph.microsoft.com/v1.0/users/{user_id}/licenseDetails
  """
  pass

async def _get_msgraph_role_assignment(client: GraphServiceClient, role_id: str):
    query_params = RoleAssignmentsRequestBuilder.RoleAssignmentsRequestBuilderGetQueryParameters(
      filter = f"roleDefinitionId eq '{role_id}'",
	  	expand = ["principal"]  # Big expansion to get principal type
    )
    request_configuration = RequestConfiguration(query_parameters=query_params)
    result = await client.role_management.directory.role_assignments.get(request_configuration = request_configuration)
    assert result.odata_next_link == None
    return result

# Utils on top of fetchers


def take_value_from_dict(obj):
   return obj['value']

def take_value_from_object(obj):
   return obj.value

async def cached_query(args: RunConf, cache_key: str, getter_function: Awaitable):
  cached = c.get_cached(cache_key)
  if cached is not None:
    return cached
  else:
    result = await getter_function()
    c.set_cached(cache_key, result)
    return result

async def get_ca_policy_defs(args: RunConf):
  """ Returns the original CA response """
  key = c.mk_ca_path(args)
  async def fn():
    result = await _get_msgraph_ca_policy_json(get_msgraph_client(args))
    return result['value']
  return await cached_query(args, key, fn)

async def get_unresolved_role_assignments(args: RunConf, role_id: str) -> List[CT.AssignedMember]:
  def role_assignment_to_type(assignment: MSGUnifiedRoleAssignment) -> CT.AssignedMember:
    assert assignment.principal.odata_type != None
    return CT.AssignedMember(principalId=assignment.principal_id, principalType=CT.map_odata_type_to_principaltype(assignment.principal.odata_type))
  key = c.mk_role_assignment_raw_path(args, role_id)
  async def fn():
    result = await _get_msgraph_role_assignment(get_msgraph_client(args), role_id)
    assignments = [role_assignment_to_type(a) for a in result.value]
    return assignments
  return await cached_query(args, key, fn)


async def get_all_users(args: RunConf) -> dict[CT.PrincipalGuid, CT.Principal]:
  def msgraph_user_to_principal(u: MSGUser) -> CT.Principal:
    return CT.Principal(
      id=u.id,
      displayName=u.display_name,
      accountEnabled=u.account_enabled,
      raw={},
      usertype=CT.PrincipalType.User,
      userDetails=CT.UserPrincipalDetails(upn=u.user_principal_name)
    )
  key = c.mk_all_users_path(args)
  async def fn():
    result = await _get_msgraph_all_users(get_msgraph_client(args))
    principals: dict[str, CT.Principal] = {u.id:msgraph_user_to_principal(u) for u in result}
    return principals
  return await cached_query(args, key, fn)


async def get_group_transitive_members(args: RunConf, group_id: str) -> List[CT.AssignedMember]:
  key = c.mk_group_result_transitive_path(args, group_id)
  async def fn():
    try:
      result = await _get_msgraph_group_transitive_members(get_msgraph_client(args), group_id)
      mapped = [CT.AssignedMember(principalId=p.id, principalType=CT.map_odata_type_to_principaltype(p.odata_type)) for p in result]
      excl_devices = [p for p in mapped if p.principalType != CT.PrincipalType.Device]
      return excl_devices
    except Exception as e:
      if isinstance(e, ODataError) and e.response_status_code == 404:
        logger.warning('Group %s is referenced but not present in directory anymore.', group_id)
        # TODO: Create warning if that group was used in exclusion groups
        return []
      raise e
  return await cached_query(args, key, fn)


async def get_role_transitive_members(args: RunConf, role_id: str) -> List[CT.AssignedMember]:
  key = c.mk_role_result_transitive_path(args, role_id)
  async def fn():
    assignments: List[CT.AssignedMember] = await get_unresolved_role_assignments(args, role_id)
    members_excl_groups: dict[str, CT.AssignedMember] = {}
    for assignment in assignments:
      if assignment.principalType == CT.PrincipalType.Group:
        group_members: List[CT.AssignedMember] = await get_group_transitive_members(args, assignment.principalId)
        for group_membership in group_members:
          members_excl_groups[group_membership.principalId] = group_membership
      elif assignment.principalType == CT.PrincipalType.User:
        members_excl_groups[assignment.principalId] = assignment
      elif assignment.principalType == CT.PrincipalType.ServicePrincipal:
        members_excl_groups[assignment.principalId] = assignment
      else:
        raise Exception('Unknown referenced principal type: %s' % str(assignment.principalType))
    return list(members_excl_groups.values())
  return await cached_query(args, key, fn)


async def get_all_service_principals(args: RunConf) -> dict[CT.PrincipalGuid, CT.Principal]:
  def map_service_principal_type(sp_type):
    return CT.ServicePrincipalType(sp_type)

  def try_get_display_name_for_sp(sp: MSGServicePrincipal):
    if sp.display_name:
      return sp.display_name
    else:
      raise Exception('Cannot get display name for sp')

  def try_get_resource_location(sp: MSGServicePrincipal):
    for alt_name in sp.alternative_names:
      if alt_name and alt_name.startswith('/subscriptions'):
        return alt_name
    return None

  def try_get_verified_publisher(sp: MSGServicePrincipal):
    if sp.verified_publisher:
      return sp.verified_publisher.display_name
    return None

  def msgraph_sp_to_principal(u: MSGServicePrincipal) -> CT.Principal:
    return CT.Principal(
      id=u.id,
      displayName=try_get_display_name_for_sp(u),
      accountEnabled=u.account_enabled,
      raw={},
      spDetails=CT.ServicePrincipalDetails(
        servicePrincipalType=map_service_principal_type(u.service_principal_type),
        resourceLocation=try_get_resource_location(u),
        verifiedPublisher=try_get_verified_publisher(u)
      ),
      usertype=CT.PrincipalType.ServicePrincipal
    )

  key = c.mk_all_service_principals_path(args)
  async def fn():
    result = await _get_msgraph_all_service_principals(get_msgraph_client(args))
    principals: dict[str, CT.Principal] = {u.id:msgraph_sp_to_principal(u) for u in result}
    return principals
  return await cached_query(args, key, fn)

async def get_all_principals(args: RunConf) -> dict[CT.PrincipalGuid, CT.Principal]:
  result = {}
  sps = await get_all_service_principals(args)
  for principalId, principal in sps.items():
    result[principalId] = principal
  users = await get_all_users(args)
  for principalId, principal in users.items():
    result[principalId] = principal
  return result