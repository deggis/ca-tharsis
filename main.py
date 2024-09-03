import argparse
import glob
import json
import csv
from os.path import join as path_join
import subprocess
import os
from functools import cache, reduce
from typing import List
from enum import Enum, auto
import operator
import math
import itertools

solver_imports_available = True
try:
  import cpmpy as cp
  from cpmpy.solvers.ortools import OrtSolutionPrinter
except ImportError:
  cp = None
  OrtSolutionPrinter = None
  solver_imports_available = False

import pandas as pd

from disjoint_sets import split_to_disjoint_sets, GroupMembers
from collections import namedtuple
from common_apps import common_apps


PolicyModel = namedtuple('PolicyModel', [
  'id',
  # General information to help reporting
  'name',
  'members',
  'enabled',
  # Conditions
  'condition_usergroups',
  'condition_applications',
  'condition_application_user_action',
  'condition_client_app_types',
  'condition_signin_risk_levels',
  'condition_user_risk_levels',
  # Controls
  'grant_operator', # And, Or, Block, None
  'grant_controls',
  'grant_authentication_strength',
  'session_controls'
])

GeneralInfo = namedtuple('GeneralInfo', [
  'disjoint_artificial_user_groups',
  'disjoint_artificial_app_groups',
  'seen_grant_controls',
  'seen_session_controls',
  'seen_app_user_actions',
  'users_count',
  'apps_count'
])

# Conditional Access Constraint Solver for Gaps
# CACSFG

parser = argparse.ArgumentParser(
  prog='CA Policy Gap Analyzer',
  description='What the program does',
  epilog='Text at the bottom of help')
parser.add_argument('work_dir', type=str)
parser.add_argument('--include-report-only', action='store_true')
parser.add_argument('--create-queries', action='store_true')
parser.add_argument('--get-licenses-from-graph', action='store_true', help='Get assigned licenses from Graph API, user per user (slow)')
parser.add_argument('--number-of-solutions', type=int, default=5)
parser.add_argument('--use-solver', action='store_true')

mk_ca_path = lambda args: os.path.join(args.work_dir, 'ca.json')
mk_group_result_path = lambda args, group_id: os.path.join(args.work_dir, f'group_{group_id}.json')
mk_role_result_raw_path = lambda args, role_id: os.path.join(args.work_dir, f'role_{role_id}_raw.json')
mk_role_result_resolved_path = lambda args, role_id: os.path.join(args.work_dir, f'role_{role_id}_resolved.json')
mk_all_users_path = lambda args: os.path.join(args.work_dir, 'all_users.json')
mk_users_licenses = lambda args: os.path.join(args.work_dir, 'licenses.json')
mk_summary_report_path = lambda args: os.path.join(args.work_dir, 'summary_of_ca.html')
mk_report_csv_path = lambda args, report, ug_name: os.path.join(args.work_dir, f'report_{report}_group_{ug_name}_members.csv')
mk_report_ca_coverage_path = lambda args, report: os.path.join(args.work_dir, f'report_{report}_coverage.csv')
mk_solutions_report_path = lambda args: os.path.join(args.work_dir, 'summary_solutions.html')


META_APP_ALL_UNMETIONED_APPS = "RestOfTheApps"
MICROSOFT_ADMIN_PORTALS_APP = "MicrosoftAdminPortals"

ALL_CLIENT_APP_TYPES = ['browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other']
ALL_USER_RISK_LEVELS = ['high', 'medium', 'low', 'none']
ALL_SIGNIN_RISK_LEVELS = ['high', 'medium', 'low', 'none']

UNUSED_VARIABLE_COST=1

def get_policy_defs(args):
  with open(mk_ca_path(args)) as in_f:
    ca = json.load(in_f)
    policy_objects = ca['value']
    if args.include_report_only:
      return policy_objects
    else:
      return [p for p in policy_objects if p['state'] == 'enabled']

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

def fetch_ca_policy(args):
  result_file = mk_ca_path(args)
  if not os.path.exists(result_file):
    print('Fetching CA policy')
    run_cmd(f'az rest --uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" > {result_file}')

def list_referred_groups_roles(args):
  groups, roles = [], []
  for ca_policy in get_policy_defs(args):
    user_targeting = ca_policy['conditions']['users']
    groups.extend(user_targeting.get('includeGroups', []))
    roles.extend(user_targeting.get('includeRoles', []))
    groups.extend(user_targeting.get('excludeGroups', []))
    roles.extend(user_targeting.get('excludeRoles', []))
    # TODO: include/excludeGuestsOrExternalUsers missing

  return set(groups), set(roles)

def get_licenses(args):
  """
  No bulk download option in API for all users at once?
  This is slow.
  """

  users_licenses_path = mk_users_licenses(args)
  users_licenses_path_temp = users_licenses_path+'_temp'

  users_licenses = {}
  if os.path.exists(users_licenses_path):
    with open(users_licenses_path) as in_f:
      users_licenses = json.load(in_f)

  def save():
    with open(users_licenses_path, 'w') as out_f:
      json.dump(users_licenses, out_f)

  all_users = get_members(mk_all_users_path(args))
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
        next_link = result.get('@odata.nextLink').replace('$', '\\$')  # TODO: get rid of shell
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

def resolve_memberships_with_query(args):
  groups, roles = list_referred_groups_roles(args)

  for role_id in roles:
    # Check raw role files
    role_result_file = mk_role_result_raw_path(args, role_id)

    # Step 1: Get raw role assignment data
    if not os.path.exists(role_result_file):
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
        else:
          raise Exception('Unknown referenced principal type: %s' % assigned_object_type)

  for group_id in groups:
    group_result_file = mk_group_result_path(args, group_id)
    if not os.path.exists(group_result_file):
      group_url = f'https://graph.microsoft.com/v1.0/groups/{group_id}/transitiveMembers'
      _run_graph_user_query(args, group_result_file, group_url)

  for role_id in roles:
    role_resolved_result_fn = mk_role_result_resolved_path(args, role_id)
    if os.path.exists(role_resolved_result_fn):
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
      else:
        raise Exception('Unknown referenced principal type: %s' % assigned_object_type)

    with open(role_resolved_result_fn, 'w') as out_f:
      resolved_result = {'value': principals}
      json.dump(resolved_result, out_f)

def fetch_all_users(args):
  _run_graph_user_query(args, mk_all_users_path(args), 'https://graph.microsoft.com/beta/users?select=id,accountenabled,userPrincipalName')

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
def translate_app_guid(app_id):
  translation = common_apps.get(app_id)
  if translation:
    return translation
  else:
    return app_id

def get_translated_app_conds(conds, key):
  return set([translate_app_guid(aid) for aid in conds[key] if aid not in ['All', 'None']])

def get_all_referenced_apps(args):
  apps = set()
  for ca_policy in get_policy_defs(args):
    app_conds = ca_policy['conditions']['applications']
    apps.update(get_translated_app_conds(app_conds, 'excludeApplications'))
    apps.update(get_translated_app_conds(app_conds, 'includeApplications'))
  if 'All' in apps:
    apps.remove('All')
  if 'None' in apps:
    apps.remove('None')
  return apps

def resolve_members_for_policy_objects(args, user_selection):
  # policy_id guid: set of user guids (lowercase)
  memberships = {}

  for ca_policy in get_policy_defs(args):
    user_targeting = ca_policy['conditions']['users']
    included = set()
    if user_targeting['includeUsers'] == ['All']:
      included = user_selection.copy()
    else:
      for includedRoleId in user_targeting['includeRoles']:
        included |= get_members(mk_role_result_resolved_path(args, includedRoleId))
      for includedGroupId in user_targeting['includeGroups']:
        included |= get_members(mk_group_result_path(args, includedGroupId))
      for includedUserId in user_targeting['includeUsers']:
        included.add(includedUserId)
      # FIXME: check includeGuestsOrExternalUsers

    for excludedRoleId in user_targeting['excludeRoles']:
      for excludedMember in get_members(mk_role_result_resolved_path(args, excludedRoleId)):
        if excludedMember in included:
          included.remove(excludedMember)
    for excludedGroupId in user_targeting['excludeGroups']:
      for excludedMember in get_members(mk_group_result_path(args, excludedGroupId)):
        if excludedMember in included:
          included.remove(excludedMember)
    for excludedUserId in user_targeting['excludeUsers']:
      # User can be already excluded through previous methods
      if excludedUserId in included:
        included.remove(excludedUserId)
    # FIXME: check excludeGuestsOrExternalUsers

    if user_selection:
      memberships[ca_policy['id']] = included & user_selection
    else:
      memberships[ca_policy['id']] = included
    
  return memberships

def resolve_apps_for_policy_objects(args, all_apps):
  memberships = {}

  for ca_policy in get_policy_defs(args):
    app_conds = ca_policy['conditions']['applications']
    included = set()
    if app_conds['includeApplications'] == ['All']:
      # if includeApplications==All, we include all referenced + META_APP_ALL_UNMETIONED_APPS
      included = all_apps
    elif app_conds['includeApplications'] == ['None']:
      # should maybe warn here. this is not useful.
      included = set()
    if app_conds['includeApplications']:
      included |= get_translated_app_conds(app_conds, 'includeApplications')
    if app_conds.get('excludeApplications'):
      included |= get_translated_app_conds(app_conds, 'excludeApplications')
    memberships[ca_policy['id']] = included
  return memberships  

def translate_session_controls(session_control_list):
  if not session_control_list:
    return []
  session_controls = []
  for control, state in session_control_list.items():
    if state is not None:
      session_controls.append('session_%s' % control)
  return session_controls



def create_policymodels(args, user_selection):
  # Users
  policy_user_memberships = resolve_members_for_policy_objects(args, user_selection)
  policy_user_memberships['all_meta'] = user_selection.copy()

  users_task = [GroupMembers(name=policy_id, members=members)
      for policy_id, members in policy_user_memberships.items()]
  policy_user_groups, dja_user_groups = split_to_disjoint_sets(users_task)

  # Applications
  all_apps = get_all_referenced_apps(args)
  all_apps.add(META_APP_ALL_UNMETIONED_APPS)
  all_apps.add(MICROSOFT_ADMIN_PORTALS_APP)  # make sure this is in separately
  policy_app_memberships = resolve_apps_for_policy_objects(args, all_apps)
  apps_task = [GroupMembers(name=policy_id, members=members)
      for policy_id, members in policy_app_memberships.items()]
  policy_app_groups, dja_app_groups = split_to_disjoint_sets(apps_task)

  seen_grant_controls = set()
  seen_session_controls = set()
  seen_app_user_actions = set()

  # Create models
  policyModels = []
  for ca_policy in get_policy_defs(args):
    enabled = ca_policy['state'] == 'enabled'
    policy_id = ca_policy['id']

    if not policy_user_groups[policy_id]:
      # Policy targets nobody. Does even less than audit mode.
      continue
    
    # Grant controls
    ca_grant_controls = ca_policy['grantControls']
    grant_operator = None  # only session controls if this is none
    if ca_grant_controls:
      #elif grant_controls['operator'] in ["OR", "AND"]:
      grant_operator = ca_grant_controls['operator']
      grant_controls = ca_grant_controls['builtInControls']
      seen_grant_controls.update(grant_controls)
   
    authenticationStrength = None
    if ca_grant_controls:
      if strength := ca_grant_controls.get('authenticationStrength'):
        authenticationStrength = strength

    # Session controls
    session_controls = translate_session_controls(ca_policy['sessionControls'])
    seen_session_controls.update(session_controls)

    conditions = ca_policy['conditions']

    user_actions = set()
    if ua := conditions['applications'].get('includeUserActions'):
      user_actions = set(ua)
      seen_app_user_actions |= user_actions

    client_app_types = set()
    all_app_types = ALL_CLIENT_APP_TYPES
    if conditions['clientAppTypes'] == ['all']:
      client_app_types = set(all_app_types)
    else:
      client_app_types = set(conditions['clientAppTypes'])

    signin_risk_levels = set(conditions['signInRiskLevels'])
    user_risk_levels = set(conditions['userRiskLevels'])

    policyModels.append(PolicyModel(
      id=policy_id,
      name=ca_policy['displayName'],
      enabled=enabled,
      members=policy_user_memberships[policy_id],
      condition_usergroups=policy_user_groups[policy_id],
      condition_applications=policy_app_groups[policy_id],
      condition_application_user_action=user_actions,
      condition_client_app_types=client_app_types,
      condition_signin_risk_levels=signin_risk_levels,
      condition_user_risk_levels=user_risk_levels,
      grant_operator=grant_operator,
      grant_controls=grant_controls,
      grant_authentication_strength=authenticationStrength,
      session_controls=session_controls
    ))
  
  generalInfo = GeneralInfo(
    disjoint_artificial_user_groups=dja_user_groups,
    disjoint_artificial_app_groups=dja_app_groups,
    seen_grant_controls=seen_grant_controls,
    seen_session_controls=seen_session_controls,
    seen_app_user_actions=seen_app_user_actions,
    users_count=len(user_selection),
    apps_count=len(all_apps)
  )

  return policyModels, generalInfo


mk_html5_doc = lambda title, body_content: """
<html>
  <head>
    <style type="text/css">
      .mystyle {
        font-size: 11pt; 
        font-family: Arial;
        border-collapse: collapse; 
        border: 1px solid silver;
      }
      .mystyle td, th {
        padding: 5px;
      }
      .mystyle tr:nth-child(even) {
        background: #E0E0E0;
      }
      .mystyle tr:hover {
        background: silver;
        cursor: pointer;
      }
    </style>
    <title>%s</title>
  </head>

  <body>
  <h1>%s</h1>
  %s
  </body>
""" % (title, title, body_content)

def get_all_members(args):
  with open(mk_all_users_path(args)) as in_f:
    data = json.load(in_f)
  result = {}
  for item in data['value']:
    result[item['id']] = item
  return result

def create_additional_section(args, policyModels, generalInfo:GeneralInfo):
  users_by_ids = get_all_members(args)

  s = '<ul>'
  s += '<li>Total users in section: %s</li>' % generalInfo.users_count
  for ug_id, user_ids in generalInfo.disjoint_artificial_user_groups.items():
    example_user = sorted(list(user_ids))[0]
    s += '<li>User group %d: Users: %d. Example user: %s</li>' % (ug_id, len(user_ids), users_by_ids[example_user]['userPrincipalName'])
  s += '</ul>'
  return s


def create_report_section(args, policyModels:List[PolicyModel], generalInfo:GeneralInfo, title):
  pms = sorted(policyModels, key=lambda x: (not x.enabled, x.name))

  d = {
     'Name': [p.name for p in pms],
     'On': [str(p.enabled) for p in pms],
     'Users': [len(p.members) for p in pms]
  }
  def x(b):
    return 'X' if b else ''

  for ug, members in generalInfo.disjoint_artificial_user_groups.items():
    u_count = len(members)
    d['UG%s/ %d' % (ug, u_count)] = [x(ug in p.condition_usergroups) for p in pms]

  for ag, apps in generalInfo.disjoint_artificial_app_groups.items():
    if len(apps) == 1:
      ag_id = 'AG%s %s' % (ag, list(apps)[0])
    else:
      ag_id = 'AG%s (%d apps)' % (ag, len(apps))
    d[ag_id] = [x(ag in p.condition_applications) for p in pms]

  for action in sorted(list(generalInfo.seen_app_user_actions)):
    d['Action: %s' % action] = [x(action in p.condition_application_user_action) for p in pms]

  d['C:operator'] = [p.grant_operator for p in pms]

  for control in sorted(list(generalInfo.seen_grant_controls)):
    d['GC:%s' % control] = [x(control in p.grant_controls) for p in pms]

  for control in sorted(list(generalInfo.seen_session_controls)):
    d['SC:%s' % control] = [x(control in p.session_controls) for p in pms]

  df = pd.DataFrame(data=d)

  additional = create_additional_section(args, policyModels, generalInfo)

  body_part = ''
  body_part += f'<h2>{title}</h2>'
  body_part += df.to_html(classes='mystyle')
  body_part += additional


  title_fn = title.replace(' ', '_').replace('&', '-')

  with open(mk_all_users_path(args)) as in_f:
    user_data = {}
    for member in json.load(in_f)['value']:
      user_data[member['id']] = member

  for ug, members in generalInfo.disjoint_artificial_user_groups.items():
    if '(' in title_fn:
      title_fn = title_fn[:title_fn.index('(')]
    fn = mk_report_csv_path(args, report=title_fn, ug_name='UG%s' % ug)
    with open(fn, 'w') as out_f:
      fieldnames = ['id', 'upn', 'accountEnabled', 'roles']
      writer = csv.DictWriter(out_f, fieldnames=fieldnames, dialect=csv.excel)
      writer.writeheader()
      for member in members:
        user = user_data[member]
        writer.writerow({
          'id': user['id'],
          'upn': user['userPrincipalName'],
          'accountEnabled': user['accountEnabled'],
          'roles': ''
        })
    
  with open(mk_report_ca_coverage_path(args, title_fn), 'w') as out_f:
    fieldnames = ['ca_name', 'assigned_users']
    writer = csv.DictWriter(out_f, fieldnames=fieldnames, dialect=csv.excel)
    writer.writeheader()
    for pm in pms:
      writer.writerow({
        'ca_name': pm.name,
        'assigned_users': len(pm.members)
      })

  return body_part

class VarType(Enum):
    CONDITION_USER_GROUP = auto()
    CONDITION_APPLICATION_GROUP = auto()
    CONDITION_APP_USER_ACTION = auto()
    CONDITION_CLIENT_APP_TYPE = auto()
    CONDITION_USER_RISK_LEVEL = auto()
    CONDITION_SIGNIN_RISK_LEVEL = auto()
    BUILTIN_CONTROL = auto()

@cache
def _get_boolvar(name):
  return cp.boolvar(name=name)

def get_boolvar(vtype:VarType, id_:str, policyModels:List[PolicyModel], generalInfo:GeneralInfo):
  """
  Cache the answers to be able to return same instances.
  """

  match vtype:
    case VarType.CONDITION_USER_GROUP:
      return _get_boolvar('UG%s' % id_)
    case VarType.CONDITION_APPLICATION_GROUP:
      return _get_boolvar('AG%s' % id_)
    case VarType.CONDITION_APP_USER_ACTION:
      return _get_boolvar('UserAction:%s' % id_)
    case VarType.CONDITION_CLIENT_APP_TYPE:
      return _get_boolvar('ClientAppType:%s' % id_)
    case VarType.BUILTIN_CONTROL:
      return _get_boolvar('Control:%s' % id_)
    case VarType.CONDITION_SIGNIN_RISK_LEVEL:
      return _get_boolvar('SigninRisk:%s' % id_)
    case VarType.CONDITION_USER_RISK_LEVEL:
      return _get_boolvar('UserRisk:%s' % id_)

def get_all_vars_for_display(all_vars):
  var_types = [
    VarType.CONDITION_USER_GROUP,
    VarType.CONDITION_APPLICATION_GROUP,
    VarType.CONDITION_APP_USER_ACTION,
    VarType.CONDITION_CLIENT_APP_TYPE,
    VarType.CONDITION_USER_RISK_LEVEL,
    VarType.CONDITION_SIGNIN_RISK_LEVEL,
    VarType.BUILTIN_CONTROL
  ]

  vars = []
  for vtype in var_types:
    for key in sorted(all_vars.get(vtype, {}).keys()):
      vars.append(all_vars[vtype][key])
  return vars

def solutions_to_table(args, solutions, displayed_vars):
  d = {}
  def x(b):
    return 'X' if b else ''

  for i in range(0, len(displayed_vars)):
    d[displayed_vars[i].name] = [x(s[i]) for s in solutions]

  df = pd.DataFrame(data=d)
  with open(mk_solutions_report_path(args), 'w') as out_f:
    out_f.write(mk_html5_doc("Solutions summary", df.to_html(classes='mystyle')))

def get_uag_cost(args, uag_id, generalInfo:GeneralInfo):
  users_in_group = len(generalInfo.disjoint_artificial_user_groups[uag_id])
  return math.floor((users_in_group / generalInfo.users_count) * 100)

def get_aag_cost(args, aag_id, generalInfo:GeneralInfo):
  apps_in_group = len(generalInfo.disjoint_artificial_app_groups[aag_id])
  # FIXME: differentiate apps
  return math.floor((apps_in_group / generalInfo.apps_count) * 10)

def get_builtin_control_cost(args, builtin_control_name, generalInfo:GeneralInfo):
  # FIXME
  costs = {
    'mfa': 10,
    'compliantDevice': 6,
    'domainJoinedDevice': 4,
    'passwordChange': 8
  }
  return costs.get(builtin_control_name, 5)

def get_signin_risk_cost(args, level):
  return {
    'none': 10,
    'low': 5,
    'medium': 3,
    'high': 1
  }[level]

def get_client_app_type_cost(args, client_app):
  return {
    'browser': 1,
    'mobileAppsAndDesktopClients': 3,
    'other': 4,
    'exchangeActiveSync': 5
  }[client_app]

def get_user_risk_cost(args, level):
  return get_signin_risk_cost(args, level)

def translate_policymodels_to_task(args, policyModels:List[PolicyModel], generalInfo:GeneralInfo):
  requirements = []
  all_vars: dict = {}
  def getvar(vtype, id_:str):
    bv = get_boolvar(vtype, id_, policyModels, generalInfo)
    type_catalog = all_vars.setdefault(vtype, {})
    if id_ not in type_catalog:
      type_catalog[id_] = bv
    return bv

  mfa = getvar(VarType.BUILTIN_CONTROL, 'mfa')
  block = getvar(VarType.BUILTIN_CONTROL, 'block')
  # authStrength = getvar(VarType.BUILTIN_CONTROL, 'authStrength')

  # pre-create some content
  for client_app in ALL_CLIENT_APP_TYPES:
    _ = getvar(VarType.CONDITION_CLIENT_APP_TYPE, client_app)
  
  # Minimize variables a bit: Add SignInRisk=none only if sign-in risk used anywhere
  # Same with user-risk.
  if any([bool(pm.condition_signin_risk_levels) for pm in policyModels]):
    _ = getvar(VarType.CONDITION_SIGNIN_RISK_LEVEL, 'none')
  if any([bool(pm.condition_user_risk_levels) for pm in policyModels]):
    _ = getvar(VarType.CONDITION_USER_RISK_LEVEL, 'none')

  _seen_builtin_controls = sorted(generalInfo.seen_grant_controls)
  builtin_controls_without_block = [c for c in _seen_builtin_controls if c!='block']
  cost_user = cp.intvar(0, 100)
  cost_vector = cp.intvar(0,10, shape=5+len(builtin_controls_without_block))  # take block out
  cost_app = cost_vector[0]
  cost_auth_strength = cost_vector[1]
  cost_signin_risk = cost_vector[2]
  cost_user_risk = cost_vector[3]
  cost_client_app_type = cost_vector[4]

  next_cost_i = 5
  control_costs = {}
  for i, n in enumerate(builtin_controls_without_block):
    control_costs[n] = cost_vector[next_cost_i+i]

  for pm in policyModels:
    # Users: User selections
    user_selection = cp.any([getvar(VarType.CONDITION_USER_GROUP, str(gid)) for gid in pm.condition_usergroups])

    # Target Resources: App selections
    app_selection = cp.any([getvar(VarType.CONDITION_APPLICATION_GROUP, str(aid)) for aid in pm.condition_applications])

    # CA Conditions (the above are also similarly conditions but ok)

    conditions = True  # satisfied if nothing configured

    # Client apps
    if len(pm.condition_client_app_types) != 4:
      # Assumption: Selecting all 4 possible app types is equal to not selecting any
      conditions &= cp.any([getvar(VarType.CONDITION_CLIENT_APP_TYPE, capp) for capp in pm.condition_client_app_types])
    if pm.condition_user_risk_levels:
      conditions &= cp.any([getvar(VarType.CONDITION_USER_RISK_LEVEL, level) for level in pm.condition_user_risk_levels])
    if pm.condition_signin_risk_levels:
      conditions &= cp.any([getvar(VarType.CONDITION_SIGNIN_RISK_LEVEL, level) for level in pm.condition_signin_risk_levels])

    # Grant controls
    grant_combinator = cp.any if pm.grant_operator == 'OR' else cp.all
    grant_controls = [getvar(VarType.BUILTIN_CONTROL, c) for c in pm.grant_controls if c != 'block']
    if pm.grant_authentication_strength:
      pass # skip for now
      # grant_controls.append(authStrength)
    control_requirement = grant_combinator(grant_controls)

    # Only one usergroup 
    policy = (user_selection & app_selection & conditions).implies(control_requirement)
    print(pm.name)
    print(str(policy))

    # All ready for this policy
    requirements.append(policy)

  # Selection requirements: in a solution one user should be accessing one app. These are represented by groups.
  def there_can_be_only_one(var_type):
    bin_vars = list(all_vars[var_type].values())
    for i in range(0, len(bin_vars)):
      all_except_i = [bin_vars[j] for j in range(0, len(bin_vars)) if j!=i]
      one_i = bin_vars[i]
      # rule 1: if one true, no other can be
      requirements.append(one_i.implies(~cp.any(all_except_i)))
    # rule 2: at least one must be true
    requirements.append(cp.any(bin_vars))

  there_can_be_only_one(VarType.CONDITION_USER_GROUP)         # Require 1 user group
  there_can_be_only_one(VarType.CONDITION_APPLICATION_GROUP)  # Require 1 app group
  there_can_be_only_one(VarType.CONDITION_CLIENT_APP_TYPE)    # Require 1 client app type

  if all_vars.get(VarType.CONDITION_SIGNIN_RISK_LEVEL):
    there_can_be_only_one(VarType.CONDITION_SIGNIN_RISK_LEVEL)
  if all_vars.get(VarType.CONDITION_USER_RISK_LEVEL):
    there_can_be_only_one(VarType.CONDITION_USER_RISK_LEVEL)

  # General task requirements
  requirements.append(~block)

  # cost vector, cost-to-attack
  for uag_id in sorted(generalInfo.disjoint_artificial_user_groups.keys()):
    # uag_binvar = all_vars[VarType.CONDITION_USER_GROUP][str(uag_id)]
    # Exception: What? An UAG was created but no policy referenced it? Bug in a policy or here?
    uag_binvar = getvar(VarType.CONDITION_USER_GROUP, str(uag_id))
    cost = get_uag_cost(args, uag_id, generalInfo)
    if cost is None:
      print('No cost?')
    requirements.append(uag_binvar.implies(cost_user==cost))

  for aag_id in sorted(generalInfo.disjoint_artificial_app_groups.keys()):
    aag_binvar = all_vars[VarType.CONDITION_APPLICATION_GROUP][str(aag_id)]
    cost = get_aag_cost(args, aag_id, generalInfo)
    requirements.append(aag_binvar.implies(cost_app==cost))

  for built_in_control_name in builtin_controls_without_block:
    control_binvar = all_vars[VarType.BUILTIN_CONTROL][built_in_control_name]
    cost_var = control_costs[built_in_control_name]
    cost = get_builtin_control_cost(args, built_in_control_name, generalInfo)
    requirements.append(control_binvar.implies(cost_var==cost))
    requirements.append((~control_binvar).implies(cost_var==UNUSED_VARIABLE_COST))

  if client_app_types := all_vars.get(VarType.CONDITION_CLIENT_APP_TYPE):
    for client_app_type, bvar in client_app_types.items():
      cost = get_client_app_type_cost(args, client_app_type)
      requirements.append(bvar.implies(cost_client_app_type==cost))
      requirements.append((~bvar).implies(cost_client_app_type==UNUSED_VARIABLE_COST))
  else:
    requirements.append(cost_client_app_type==UNUSED_VARIABLE_COST)

  if signin_risk_used := all_vars.get(VarType.CONDITION_SIGNIN_RISK_LEVEL):
    for sign_in_risk_level, bvar in signin_risk_used.items():
      cost = get_signin_risk_cost(args, sign_in_risk_level)
      requirements.append(bvar.implies(cost_signin_risk==cost))
  else:
    requirements.append(cost_signin_risk==UNUSED_VARIABLE_COST)

  if user_risk_used := all_vars.get(VarType.CONDITION_USER_RISK_LEVEL):
    for user_risk_level, bvar in user_risk_used.items():
      cost = get_user_risk_cost(args, user_risk_level)
      requirements.append(bvar.implies(cost_user_risk==cost))
  else:
    requirements.append(cost_user_risk==UNUSED_VARIABLE_COST)

  # for now
  requirements.append(cost_auth_strength==UNUSED_VARIABLE_COST)

  displayed_vars = get_all_vars_for_display(all_vars)

  solutions = []

  for i in range(0, args.number_of_solutions):
    model = cp.Model(*requirements)

    solver = cp.SolverLookup.get('ortools', model)
    total_cost = cost_user * reduce(operator.mul, cost_vector)
    solver.objective(total_cost, minimize=True)
    solver.solve()

    if not(any([x.value() for x in displayed_vars])):
      print('This is not actually a solution')
      break

    solutions.append([x.value() for x in displayed_vars])

    # Ban the current solution from appearing again
    requirements.append(~cp.all(x == x.value() for x in displayed_vars))

    # Print solution
    vars = ', '.join([x.name for x in displayed_vars if x.value()])
    result = cost_user.value() * reduce(operator.mul, [v.value() for v in cost_vector])
    cost_parts = '*'.join([str(v.value()) for v in itertools.chain([cost_user], cost_vector)])
    print('Solution #%d: %s cost=%d (%s)' % (i, vars, result, cost_parts))

  # solutions_to_table(args, solutions, displayed_vars)

def count_s(a, b):
  frac = math.floor(a / b * 100)
  return '%d of %d / %s %%' % (a,b,frac)

def display_warnings(args):
  # https://learn.microsoft.com/en-us/entra/identity/conditional-access/migrate-approved-client-app
  pass

def main():
  args = parser.parse_args()

  if args.use_solver and not solver_imports_available:
    raise Exception("cpmpy related libraries are not available!")

  if not os.path.exists(args.work_dir):
    os.makedirs(args.work_dir)
  fetch_ca_policy(args)
  resolve_memberships_with_query(args)
  fetch_all_users(args)
  if args.get_licenses_from_graph:
    get_licenses(args)

  body_content = ''
  all_users = get_members(mk_all_users_path(args))
  # create pre-model separately and translate it later to cpmpy
  policy_models, generalInfo = create_policymodels(args, user_selection=all_users)
  body_content += create_report_section(args, policy_models, generalInfo, 'All users')

  users = get_members(mk_all_users_path(args), req_user_active=True)
  policy_models, generalInfo = create_policymodels(args, user_selection=users)
  body_content += create_report_section(args, policy_models, generalInfo, 'All active users (%s)' % count_s(len(users), len(all_users)))

  users = get_members(mk_all_users_path(args), req_user_active=True, req_user_internal=True)
  policy_models, generalInfo = create_policymodels(args, user_selection=users)
  body_content += create_report_section(args, policy_models, generalInfo, 'All active & internal (%s)' % count_s(len(users), len(all_users)))

  users = get_members(mk_all_users_path(args), req_user_active=True, req_user_guest=True)
  policy_models, generalInfo = create_policymodels(args, user_selection=users)
  body_content += create_report_section(args, policy_models, generalInfo, 'All active & guest (%s)' % count_s(len(users), len(all_users)))

  with open(mk_summary_report_path(args), 'w') as out_f:
    out_f.write(mk_html5_doc('CA report', body_content))


  # create model
  if args.use_solver:
    translate_policymodels_to_task(args, policy_models, generalInfo)

  # display warnings

if __name__ == '__main__':
  main()
