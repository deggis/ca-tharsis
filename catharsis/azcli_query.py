from functools import cache
import json
import subprocess
import os
from typing import List

# from catharsis.settings import mk_all_users_path, mk_group_result_path, mk_all_service_principals_path
from catharsis.typedefs import PrincipalType, RunConf
from catharsis.cached_get import *
from catharsis.graph_query import run_cmd

from os import path as os_path

from catharsis.typedefs import RunConf

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

# Deprecated Use get_msgraph_ca_policy_json instead
def fetch_ca_policy_azcli(args):
  result_file = mk_ca_path(args)
  if not os_path.exists(result_file):
    print('Fetching CA policy')
    run_cmd(f'az rest --uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" > {result_file}')


# deprecated Use graph SDK version
def fetch_all_users_azcli(args):
  _run_graph_user_query(args, mk_all_users_path(args), 'https://graph.microsoft.com/beta/users?select=id,accountenabled,userPrincipalName')


def fetch_group_members_azcli(args: RunConf, group_id: str):
    group_result_file = mk_group_result_transitive_path(args, group_id)
    if not os_path.exists(group_result_file):
        group_url = f'https://graph.microsoft.com/v1.0/groups/{group_id}/transitiveMembers'
        _run_graph_user_query(args, group_result_file, group_url)

def get_role_azcli(args, role_key, role_id):
  if cached := get_cached(role_key):
    return cached
  else:
    # https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0&tabs=http#example-1-request-using-a-filter-on-roledefinitionid-and-expand-the-principal-object
    role_url = f"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\\$filter=roleDefinitionId+eq+'{role_id}'&\\$expand=Principal"
    _run_graph_user_query(args, role_key, role_url)



@cache
def _get_all_prefetched_members(users_path):
  with open(users_path) as in_f:
    data = json.load(in_f)
  result = {}
  for item in data['value']:
    result[item['id']] = item
  return result

def get_all_prefetched_members(args):
  return _get_all_prefetched_members(mk_all_users_path(args))


graph_user_types = {
   '#microsoft.graph.user': PrincipalType.User,
   '#microsoft.graph.servicePrincipal': PrincipalType.ServicePrincipal,
}

def get_members_azcli(path, req_user_active=False, req_user_guest=False, req_user_internal=False):
  def user_filter(u):
    if req_user_active and not u['accountEnabled']:
      return False
    if req_user_internal and '#EXT#@' in u['userPrincipalName']:
      return False
    if req_user_guest and '#EXT#@' not in u['userPrincipalName']:
      return False
    return True

  with open(path) as in_f:
    user_data = json.load(in_f)

    if 'role_' in path:
      return set([v['principalId'] for v in user_data['value']])
    else:
      return set([v['id'] for v in user_data['value'] if user_filter(v)])


def group_members(args: RunConf, group_id: str) -> List[Principal]:
  path = mk_group_result_transitive_path(args, group_id)
  members: List[Principal] = []
  principals = get_principals(args)

  with open(path) as in_f:
    member_data = json.load(in_f)

    member_ids = set()
    for principal in member_data['value']:
        odata_type = principal['@odata.type']
        if odata_type == '#microsoft.graph.group':
           # We can skip group members: transitional members resolved
           continue
        member_id = principal['id']
        principal = principals.get(member_id)
        if principal:
           if member_id in member_ids:
              raise Exception('Group members have two entries for same id: %s' % member_id)
           members.append(principal)
           member_ids.add(member_id)
        else:
           # Principal removed?
           pass
  return members


def get_licenses(args):
  """
  No bulk download option in API for all users at once?
  This is slow.
  """

  users_licenses_path = mk_users_licenses(args)
  users_licenses_path_temp = users_licenses_path+'_temp'

  users_licenses = {}
  if os_path.exists(users_licenses_path):
    with open(users_licenses_path) as in_f:
      users_licenses = json.load(in_f)

  def save():
    with open(users_licenses_path, 'w') as out_f:
      json.dump(users_licenses, out_f)

  all_users = get_members_azcli(mk_all_users_path(args))
  fetched = 0
  c_users = len(all_users)
  for i, user_id in enumerate(all_users):
    if i % 50 == 0:
      print('Licenses checked for users: %d/%d' % (i, c_users))
    if user_id in users_licenses:
      continue
    url = f'https://graph.microsoft.com/v1.0/users/{user_id}/licenseDetails'
    reply = run_cmd(f"az rest --uri \"{url}\"", parse=True)
    users_licenses[user_id] = reply['value']
    fetched += 1

    if fetched % 10 == 0:
      print('Licenses fetched: %d' % fetched)
      save()
  
  save()
  return users_licenses