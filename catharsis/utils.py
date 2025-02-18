from functools import cache
import asyncio
import json
import math

import os
import sys
from typing import List

from catharsis.common_apps import common_apps

# from catharsis.settings import mk_all_users_path, mk_group_result_path, mk_all_service_principals_path
from catharsis.typedefs import PrincipalType, RunConf, Principal, ServicePrincipalDetails, ServicePrincipalType, UserPrincipalDetails
from catharsis.cached_get import *
from catharsis.graph_query import _run_graph_user_query, run_cmd

from azure.identity import AzureCliCredential

from os import path as os_path
from os import remove as os_remove

from catharsis.typedefs import RunConf



def count_s(a, b):
  frac = math.floor(a / b * 100)
  return '%d of %d / %s %%' % (a,b,frac)


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
def _get_all_prefetched_members(users_path):
  with open(users_path) as in_f:
    data = json.load(in_f)
  result = {}
  for item in data['value']:
    result[item['id']] = item
  return result

def get_all_prefetched_members(args):
  return _get_all_prefetched_members(mk_all_users_path(args))

def ensure_cache_and_workdir(args: RunConf):
  if args.cache_dir and not os.path.exists(args.cache_dir):
    os.makedirs(args.cache_dir)
  
  if args.create_ca_summary and not os.path.exists(args.report_dir):
    os.makedirs(args.report_dir)


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



# Deprecated Use get_msgraph_ca_policy_json instead
def fetch_ca_policy_azcli(args):
  result_file = mk_ca_path(args)
  if not os_path.exists(result_file):
    print('Fetching CA policy')
    run_cmd(f'az rest --uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" > {result_file}')


# deprecated Use graph SDK version
def fetch_all_users_azcli(args):
  _run_graph_user_query(args, mk_all_users_path(args), 'https://graph.microsoft.com/beta/users?select=id,accountenabled,userPrincipalName')


def fetch_group_members(args: RunConf, group_id: str):
    group_result_file = mk_group_result_path(args, group_id)
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


def list_referred_groups_roles(args):
  groups, roles = [], []
  for ca_policy in get_raw_policy_defs(args):
    user_targeting = ca_policy['conditions']['users']
    groups.extend(user_targeting.get('includeGroups', []))
    roles.extend(user_targeting.get('includeRoles', []))
    groups.extend(user_targeting.get('excludeGroups', []))
    roles.extend(user_targeting.get('excludeRoles', []))
    # TODO: include/excludeGuestsOrExternalUsers missing

  return set(groups), set(roles)


def resolve_memberships_with_query(args):
  groups, roles = list_referred_groups_roles(args)

  for role_id in roles:
    # Check raw role files
    # Step 1: Get raw role assignment data

    # role_key = path
    role_key = mk_role_result_raw_path(args, role_id)
    get_role_azcli(args, role_key, role_id)

    # Step 2: Check if role assignment references groups
    content = get_cached(role_key)['value']
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



