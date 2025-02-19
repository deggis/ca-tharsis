import subprocess
import json
import os
from typing import List

# Graph SDK stuff 

from msgraph import GraphServiceClient
from msgraph.generated.models.user import User as MSGUser
from kiota_abstractions.native_response_handler import NativeResponseHandler
from kiota_http.middleware.options import ResponseHandlerOption
from azure.identity import AzureCliCredential

from catharsis.typedefs import RunConf
import catharsis.typedefs as CatharsisTypes
import catharsis.cached_get as c

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


async def do_msgraph_sdk_graph_query(request_builder):
   # https://github.com/microsoftgraph/msgraph-sdk-python?tab=readme-ov-file#32-pagination
  result = []

  # members.get?
  response = await request_builder.get()
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


async def _get_msgraph_all_users(client: GraphServiceClient):
  """ https://graph.microsoft.com/beta/users?select=id,accountenabled,userPrincipalName """
  return await do_msgraph_sdk_graph_query(client.users)


def graph_api_stuff():
  """
    
    - https://graph.microsoft.com/beta/users?select=id,accountenabled,userPrincipalName
    - https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\\$filter=roleDefinitionId+eq+'{role_id}'&\\$expand=Principal
    - https://graph.microsoft.com/v1.0/users/{user_id}/licenseDetails
  """
  pass


# Utils on top of fetchers

async def get_ca_policy_defs(args: RunConf) -> dict:
    """ Returns the original CA response """
    key = c.mk_ca_path(args)
    if cached := c.get_cached(key):
        return cached
    else:
        result = await _get_msgraph_ca_policy_json(get_msgraph_client(args))
        value = result['value']
        c.set_cached(key, value)
        return value

def msgraph_user_to_principal(u: MSGUser) -> CatharsisTypes.Principal:
   return CatharsisTypes.Principal(
      id=u.id,
      displayName=u.display_name,
      accountEnabled=u.account_enabled,
      raw={},
      usertype=CatharsisTypes.PrincipalType.User,
      userDetails=CatharsisTypes.UserPrincipalDetails(upn=u.user_principal_name)
   )

async def get_all_users(args: RunConf) -> List[CatharsisTypes.Principal]:
    """ Returns the original CA response """
    key = c.mk_all_users_path(args)
    if cached := c.get_cached(key):
        principals = [CatharsisTypes.Principal(**ud) for ud in cached]
        return principals
    else:
        result = await _get_msgraph_all_users(get_msgraph_client(args))
        # value = result['value']
        principals: List[CatharsisTypes.Principal] = [msgraph_user_to_principal(u) for u in result]
        c.set_cached(key, principals)
        return principals