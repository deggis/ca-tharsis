import json
from os import path as os_path
from os import remove as os_remove

from catharsis.ca import list_referred_groups_roles
from catharsis.typedefs import RunConf
from catharsis.utils import get_members, run_cmd
from catharsis.settings import mk_ca_path, mk_role_result_raw_path, mk_group_result_path, mk_role_result_resolved_path, mk_all_users_path

def _run_graph_user_query(args, result_path, initial_url):
  temp_file = result_path+'_temp'
  all_users = []

  if os_path.exists(result_path):
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

  if not os_path.exists(temp_file):
    os_remove(temp_file)

  if not result_missing:
    with open(result_path, 'w') as out_f:
      # Emulate Graph response structure with 'value': {}
      json.dump({'value': all_users}, out_f)
  else:
    with open(result_path, 'w') as out_f:
      # Emulate Graph response structure with 'value': {}
      # TODO: add warnings of these
      json.dump({'value': [], 'resource_was_deleted': True}, out_f)

def fetch_ca_policy(args):
  result_file = mk_ca_path(args)
  if not os_path.exists(result_file):
    print('Fetching CA policy')
    run_cmd(f'az rest --uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" > {result_file}')

def fetch_group_members(args: RunConf, group_id: str):
    group_result_file = mk_group_result_path(args, group_id)
    if not os_path.exists(group_result_file):
        group_url = f'https://graph.microsoft.com/v1.0/groups/{group_id}/transitiveMembers'
        _run_graph_user_query(args, group_result_file, group_url)

def resolve_memberships_with_query(args):
  groups, roles = list_referred_groups_roles(args)

  for role_id in roles:
    # Check raw role files
    role_result_file = mk_role_result_raw_path(args, role_id)

    # Step 1: Get raw role assignment data
    if not os_path.exists(role_result_file):
      # https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0&tabs=http#example-1-request-using-a-filter-on-roledefinitionid-and-expand-the-principal-object
      role_url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\\$filter=roleDefinitionId+eq+'{role_id}'&\\$expand=Principal"
      _run_graph_user_query(args, role_result_file, role_url)

    # Step 2: Check if role assignment references groups
    with open(role_result_file) as in_f:
      content = json.load(in_f)['value']
      for assignment in content:
        assigned_object_type = assignment['principal']['@odata.type']
        if assigned_object_type == '#microsoft.graph.group':
          groups.add(assignment['principalId'])
        elif assigned_object_type == '#microsoft.graph.user':
          pass
        elif assigned_object_type == '#microsoft.graph.servicePrincipal':
          pass
        else:
          raise Exception('Unknown referenced principal type: %s' % assigned_object_type)

  for group_id in groups:
    fetch_group_members(args, group_id)

  for role_id in roles:
    role_resolved_result_fn = mk_role_result_resolved_path(args, role_id)
    if os_path.exists(role_resolved_result_fn):
      continue
  
    role_raw_result_fn = mk_role_result_raw_path(args, role_id)
    with open(role_raw_result_fn) as in_f:
      content = json.load(in_f)['value']
    principals = []

    for assignment in content:
      assigned_object_type = assignment['principal']['@odata.type']
      if assigned_object_type == '#microsoft.graph.group':
        for member in get_members(mk_group_result_path(args, assignment['principalId'])):
          principals.append({'principalId': member})
      elif assigned_object_type == '#microsoft.graph.user':
        principals.append({'principalId': assignment['principalId']})
      elif assigned_object_type == '#microsoft.graph.servicePrincipal':
        principals.append({'principalId': assignment['principalId']})
      else:
        raise Exception('Unknown referenced principal type: %s' % assigned_object_type)

    with open(role_resolved_result_fn, 'w') as out_f:
      resolved_result = {'value': principals}
      json.dump(resolved_result, out_f)

def fetch_all_users(args):
  _run_graph_user_query(args, mk_all_users_path(args), 'https://graph.microsoft.com/beta/users?select=id,accountenabled,userPrincipalName')