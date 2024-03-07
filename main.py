import argparse
import glob
import json
from os.path import join as path_join
import subprocess
import os
from functools import cache, reduce
from typing import List
from enum import Enum, auto
import operator
import math
import itertools

import cpmpy as cp
from cpmpy.solvers.ortools import OrtSolutionPrinter
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
  'grant_builtin_controls',
  'grant_authentication_strength'
])

GeneralInfo = namedtuple('GeneralInfo', [
  'disjoint_artificial_user_groups',
  'disjoint_artificial_app_groups',
  'seen_builtin_controls',
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
parser.add_argument('--number-of-solutions', type=int, default=5)

mk_ca_path = lambda args: os.path.join(args.work_dir, 'ca.json')
mk_group_result_path = lambda args, group_id: os.path.join(args.work_dir, f'group_{group_id}.json')
mk_role_result_path = lambda args, role_id: os.path.join(args.work_dir, f'role_{role_id}.json')
mk_all_users_path = lambda args: os.path.join(args.work_dir, 'all_users.json')
mk_summary_report_path = lambda args: os.path.join(args.work_dir, 'summary_of_ca.html')
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

def run_cmd(cmd_string):
  subprocess.run(cmd_string, shell=True, capture_output=True)

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

def resolve_memberships_with_query(args):
  groups, roles = list_referred_groups_roles(args)

  for group_id in groups:
    group_result_file = mk_group_result_path(args, group_id)
    if not os.path.exists(group_result_file):
      run_cmd(f'az rest --uri https://graph.microsoft.com/v1.0/groups/{group_id}/transitiveMembers > {group_result_file}')

  for role_id in roles:
    role_result_file = mk_role_result_path(args, role_id)
    if not os.path.exists(role_result_file):
      run_cmd(f"az rest --uri https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$filter=roleDefinitionId+eq+'{role_id}' > {role_result_file}")

def fetch_all_users(args):
  all_users_result_path = mk_all_users_path(args)
  if not os.path.exists(all_users_result_path):
    run_cmd(f"az rest --uri https://graph.microsoft.com/v1.0/users > {all_users_result_path}")

def get_members(path):
  with open(path) as in_f:
    user_data = json.load(in_f)

    if 'role_' in path:
      return set([v['principalId'] for v in user_data['value']])
    else:
      return set([v['id'] for v in user_data['value']])

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

def resolve_members_for_policy_objects(args, all_users):
  # policy_id guid: set of user guids (lowercase)
  memberships = {}

  for ca_policy in get_policy_defs(args):
    user_targeting = ca_policy['conditions']['users']
    included = set()
    if user_targeting['includeUsers'] == ['All']:
      included = all_users.copy()
    else:
      for includedRoleId in user_targeting['includeRoles']:
        included |= get_members(mk_role_result_path(args, includedRoleId))
      for includedGroupId in user_targeting['includeGroups']:
        included |= get_members(mk_group_result_path(args, includedGroupId))
      for includedUserId in user_targeting['includeUsers']:
        included.add(includedUserId)
      # FIXME: check includeGuestsOrExternalUsers
    
    for excludedRoleId in user_targeting['excludeRoles']:
      for excludedMember in get_members(mk_role_result_path(args, excludedRoleId)):
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

def create_policymodels(args):
  # Users
  all_users = get_members(mk_all_users_path(args))
  policy_user_memberships = resolve_members_for_policy_objects(args, all_users)
  policy_user_memberships['all_meta'] = all_users.copy()

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

  seen_builtin_controls = set()
  seen_app_user_actions = set()

  # Create models
  policyModels = []
  for ca_policy in get_policy_defs(args):
    enabled = ca_policy['state'] == 'enabled'
    policy_id = ca_policy['id']
    grant_controls = ca_policy['grantControls']
    if not grant_controls:
      continue

    if not policy_user_groups[policy_id]:
      # Policy targets nobody. Does even less than audit mode.
      continue
    
    # Grant controls
    grant_controls = ca_policy['grantControls']
    grant_operator = None  # only session controls if this is none
    grant_builtin_controls = None
    if grant_controls:
      #elif grant_controls['operator'] in ["OR", "AND"]:
      grant_operator = grant_controls['operator']
      grant_builtin_controls = grant_controls['builtInControls']
      seen_builtin_controls.update(grant_builtin_controls)

    authenticationStrength = None
    if strength := grant_controls.get('authenticationStrength'):
      authenticationStrength = strength

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
      grant_builtin_controls=grant_builtin_controls,
      grant_authentication_strength=authenticationStrength
    ))
  
  generalInfo = GeneralInfo(
    disjoint_artificial_user_groups=dja_user_groups,
    disjoint_artificial_app_groups=dja_app_groups,
    seen_builtin_controls=seen_builtin_controls,
    seen_app_user_actions=seen_app_user_actions,
    users_count=len(all_users),
    apps_count=len(all_apps)
  )

  return policyModels, generalInfo


mk_html5_doc = lambda title, table: """
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
  </head>
  <body>
  <h1>%s</h1>

  %s
  </body>
""" % (title, table)

def create_report(args, policyModels:List[PolicyModel], generalInfo:GeneralInfo):
  pms = sorted(policyModels, key=lambda x: (not x.enabled, x.name))

  d = {
     'Name': [p.name for p in pms],
     'Enabled': [str(p.enabled) for p in pms]
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

  for builtin in sorted(list(generalInfo.seen_builtin_controls)):
    d['C:%s' % builtin] = [x(builtin in p.grant_builtin_controls) for p in pms]

  df = pd.DataFrame(data=d)

  with open(mk_summary_report_path(args), 'w') as out_f:
    out_f.write(mk_html5_doc("Policy summary", df.to_html(classes='mystyle')))

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
  all_vars = {}
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

  _seen_builtin_controls = sorted(generalInfo.seen_builtin_controls)
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
    grant_controls = [getvar(VarType.BUILTIN_CONTROL, c) for c in pm.grant_builtin_controls if c != 'block']
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
    uag_binvar = all_vars[VarType.CONDITION_USER_GROUP][str(uag_id)]
    cost = get_uag_cost(args, uag_id, generalInfo)
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

    solutions.append([x.value() for x in displayed_vars])

    # Ban the current solution from appearing again
    requirements.append(~cp.all(x == x.value() for x in displayed_vars))

    # Print solution
    vars = ', '.join([x.name for x in displayed_vars if x.value()])
    result = cost_user.value() * reduce(operator.mul, [v.value() for v in cost_vector])
    cost_parts = '*'.join([str(v.value()) for v in itertools.chain([cost_user], cost_vector)])
    print('Solution #%d: %s cost=%d (%s)' % (i, vars, result, cost_parts))

  # solutions_to_table(args, solutions, displayed_vars)

def main():
  args = parser.parse_args()
  if not os.path.exists(args.work_dir):
    os.makedirs(args.work_dir)
  fetch_ca_policy(args)
  resolve_memberships_with_query(args)
  fetch_all_users(args)

  # create pre-model separately and translate it later to cpmpy
  policy_models, generalInfo = create_policymodels(args)
  create_report(args, policy_models, generalInfo)

  # create model
  translate_policymodels_to_task(args, policy_models, generalInfo)

if __name__ == '__main__':
  main()
