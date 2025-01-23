from functools import cache
import json
import math
import subprocess
import os
import sys
from typing import List

from catharsis.common_apps import common_apps

from catharsis.settings import mk_all_users_path, mk_group_result_path, mk_all_service_principals_path
from catharsis.typedefs import PrincipalType, RunConf, Principal, ServicePrincipalDetails, ServicePrincipalType, UserPrincipalDetails


def count_s(a, b):
  frac = math.floor(a / b * 100)
  return '%d of %d / %s %%' % (a,b,frac)


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

graph_user_types = {
   '#microsoft.graph.user': PrincipalType.User,
   '#microsoft.graph.servicePrincipal': PrincipalType.ServicePrincipal,
}

def get_members(path, req_user_active=False, req_user_guest=False, req_user_internal=False):
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


@cache
def _get_all_members(users_path):
  with open(users_path) as in_f:
    data = json.load(in_f)
  result = {}
  for item in data['value']:
    result[item['id']] = item
  return result

def get_all_members(args):
  return _get_all_members(mk_all_users_path(args))

def ensure_workdir(args: RunConf) -> str:
  workdir_path = args.work_dir
  if not os.path.exists(workdir_path):
    os.makedirs(workdir_path)
  return workdir_path
  

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


@cache
def _get_user_principals(path: str) -> dict[str, Principal]:
    result = {}
    with open(path) as in_f:
      service_principals = json.load(in_f)
      for item in service_principals['value']:
        user_id = item['id']
        result[user_id] = Principal(
          id=user_id,
          displayName=item['userPrincipalName'],
          accountEnabled=item['accountEnabled'],
          raw=item,
          usertype=PrincipalType.User,
          userDetails=UserPrincipalDetails(upn=item['userPrincipalName'])
        )
    return result

def get_user_principals(args: RunConf) -> dict[str, Principal]:
  return _get_user_principals(mk_all_users_path(args))

@cache
def _get_service_principals(path: str) -> dict[str, Principal]:
    result = {}
    with open(path) as in_f:
      service_principals = json.load(in_f)
      for item in service_principals:
        sp_id = item['id']
        sp_type = item['servicePrincipalType']
        result[sp_id] = Principal(
          id=sp_id,
          displayName=item['displayName'],
          accountEnabled=item['accountEnabled'],
          raw=item,
          usertype=PrincipalType.ServicePrincipal,
          spDetails=ServicePrincipalDetails(
              ServicePrincipalType(sp_type)
          )
        )
    return result

def get_service_principals(args: RunConf) -> dict[str, Principal]:
  return _get_service_principals(mk_all_service_principals_path(args))

def get_principals(args: RunConf) -> dict[str, Principal]:
  """
  Principals indexed by object id
  """
  @cache
  def _get_principals(user_path: str, sp_path: str):
    sps = _get_service_principals(sp_path)
    users = _get_user_principals(user_path)
    results = sps.copy()
    results.update(users)
    return results
  return _get_principals(mk_all_users_path(args), mk_all_service_principals_path(args))

def group_members(args: RunConf, group_id: str) -> List[Principal]:
  path = mk_group_result_path(args, group_id)
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