import cpmpy as cp
import argparse
import glob
import json
from os.path import join as path_join
import subprocess
import os

# Conditional Access Constraint Solver for Gaps
# CACSFG

parser = argparse.ArgumentParser(
  prog='CA Policy Gap Analyzer',
  description='What the program does',
  epilog='Text at the bottom of help')
parser.add_argument('work_dir', type=str)
parser.add_argument('--include-report-only', action='store_true')
parser.add_argument('--create-queries', action='store_true')

mk_ca_path = lambda args: os.path.join(args.work_dir, 'ca.json')
mk_group_result_path = lambda args, group_id: os.path.join(args.work_dir, f'group_{group_id}.json')
mk_role_result_path = lambda args, role_id: os.path.join(args.work_dir, f'role_{role_id}.json')
mk_all_users_path = lambda args: os.path.join(args.work_dir, 'all_users.json')

def old():
  mfaRequired = cp.boolvar(name='MFARequired')
  controlApplied = cp.boolvar(name='ControlApplied')

  userA = cp.boolvar(name='UserA')
  userB = cp.boolvar(name='UserB')
  macOS = cp.boolvar(name='macOS')
  teams = cp.boolvar(name='Teams')
  compliantDevice = cp.boolvar(name='CompliantDevice')

  m = cp.Model(
    (macOS & ~teams).implies(mfaRequired | compliantDevice),

    mfaRequired.implies(controlApplied),
    compliantDevice.implies(controlApplied),
    ~controlApplied
  )

def read_policy_file(args, path):
  with open(path) as in_f:
    policy = json.load(in_f)
    if policy['state'] == 'enabledForReportingButNotEnforced' and not args.include_report_only:
      print(f'{path} is set to report only, skipping. Use --include-report-only to include.')
    return policy

def run_cmd(cmd_string):
  subprocess.run(cmd_string, shell=True, capture_output=True)

def fetch_ca_policy(args):
  result_file = mk_ca_path(args)
  if not os.path.exists(result_file):
    print('Fetching CA policy')
    run_cmd(f'az rest --uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies" > {result_file}')

def list_referred_groups_roles(args):
  groups, roles = [], []
  with open(mk_ca_path(args)) as in_f:
    ca = json.load(in_f)
    ca_policy_defs = ca['value']

    for ca_policy in ca_policy_defs:
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

def resolve_members_for_policy_objects(args):
  # policy_id guid: set of user guids (lowercase)
  memberships = {}
  all_users = get_members(mk_all_users_path(args))

  with open(mk_ca_path(args)) as in_f:
    ca = json.load(in_f)
    ca_policy_defs = ca['value']
    for ca_policy in ca_policy_defs:
      user_targeting = ca_policy['conditions']['users']
      included = set()
      if user_targeting['includeUsers'] == ['All']:
        included = all_users
      else:
        for includedRoleId in user_targeting['includeRoles']:
          included = included | get_members(mk_role_result_path(args, includedRoleId))
        for includedGroupId in user_targeting['includeGroups']:
          included = included | get_members(mk_group_result_path(args, includedGroupId))
        for includedUserId in user_targeting['includeUsers']:
          included.add(includedUserId)
        # FIXME: check includeGuestsOrExternalUsers
      
      for excludedRoleId in user_targeting['excludeRoles']:
        included = included - get_members(mk_role_result_path(args, excludedRoleId))
      for excludedGroupId in user_targeting['excludeGroups']:
        included = included - get_members(mk_group_result_path(args, excludedGroupId))
      for excludedUserId in user_targeting['excludeUsers']:
        # User can be already excluded through previous methods
        if excludedUserId in included:
          included.remove(excludedUserId)
      # FIXME: check excludeGuestsOrExternalUsers

      memberships[ca_policy['id']] = included
  return memberships

def main():
  args = parser.parse_args()
  if not os.path.exists(args.work_dir):
    os.makedirs(args.work_dir)
  fetch_ca_policy(args)
  resolve_memberships_with_query(args)
  fetch_all_users(args)
  memberships = resolve_members_for_policy_objects(args)

  import IPython; IPython.embed()
  # print(policy_set)


if __name__ == '__main__':
  main()


# n = m.solveAll(display=[macOS,teams,compliantDevice,controlApplied,mfaRequired], solution_limit=7)