from typing import List, Tuple, Set
from functools import cache
from catharsis.common_apps import common_apps
from catharsis.disjoint_sets import GroupMembers, split_to_disjoint_sets_ordered
from catharsis.typedefs import CAGuid, GeneralInfo, PolicyModel, PrincipalGuid, UserTargetingDefinition, principal_to_string
from catharsis import utils

from catharsis.utils import assignedmembers_to_id_set, filter_ca_defs
from catharsis.settings import ALL_CLIENT_APP_TYPES, META_APP_ALL_UNMETIONED_APPS, MICROSOFT_ADMIN_PORTALS_APP

import catharsis.graph_query as queries


@cache
def translate_app_guid(app_id):
  translation = common_apps.get(app_id)
  if translation:
    return translation
  else:
    return app_id


def get_translated_app_conds(conds, key):
  return set([translate_app_guid(aid) for aid in conds[key] if aid not in ['All', 'None']])

def get_all_referenced_apps(ca_defs):
  apps = set()
  for ca_policy in ca_defs:
    app_conds = ca_policy['conditions']['applications']
    apps.update(get_translated_app_conds(app_conds, 'excludeApplications'))
    apps.update(get_translated_app_conds(app_conds, 'includeApplications'))
  if 'All' in apps:
    apps.remove('All')
  if 'None' in apps:
    apps.remove('None')
  return apps

async def create_targeting_definition(args, ca_policy) -> UserTargetingDefinition:
  udef = ca_policy['conditions']['users']

  # TODO: Include also service principals
  principals_by_ids = await queries.get_all_users(args)

  def get_user_upns(udef):
    if udef == ['All']:
      uids = principals_by_ids.keys()
    else:
      uids = udef
    result = []
    for uid in uids:
      principal = principals_by_ids.get(uid)
      if principal:
        result.append(principal_to_string(principal))
      else:
        result.append('Principal removed? %s' % uid)
    return result

  utd = UserTargetingDefinition(
    included_users=get_user_upns(udef['includeUsers']),
    included_groups=udef['includeGroups'],
    included_roles=udef['includeRoles'],
    includeGuestsOrExternalUsers=udef['includeGuestsOrExternalUsers'],
    excluded_users=get_user_upns(udef['excludeUsers']),
    excluded_groups=udef['excludeGroups'],
    excluded_roles=udef['excludeRoles'],
    excludeGuestsOrExternalUsers=udef['excludeGuestsOrExternalUsers'],
  )
  return utd

async def resolve_members_for_policy_objects(args, user_selection) -> dict[CAGuid, Set[PrincipalGuid]]:
  # policy_id guid: set of user guids (lowercase)
  memberships = {}

  to_set = assignedmembers_to_id_set

  ca_defs = await queries.get_ca_policy_defs(args)
  ca_defs = filter_ca_defs(args, ca_defs)
  for ca_policy in ca_defs:
    user_targeting = ca_policy['conditions']['users']
    included: Set[PrincipalGuid] = set()
    if user_targeting['includeUsers'] == ['All']:
      included = user_selection.copy()
    else:
      for includedRoleId in user_targeting['includeRoles']:
        included |= to_set(await queries.get_role_transitive_members(args, includedRoleId))
      for includedGroupId in user_targeting['includeGroups']:
        included |= to_set(await queries.get_group_transitive_members(args, includedGroupId))
      for includedUserId in user_targeting['includeUsers']:
        included.add(includedUserId)
      # FIXME: check includeGuestsOrExternalUsers

    for excludedRoleId in user_targeting['excludeRoles']:
      for excludedMember in to_set(await queries.get_role_transitive_members(args, excludedRoleId)):
        if excludedMember in included:
          included.remove(excludedMember)
    for excludedGroupId in user_targeting['excludeGroups']:
      for excludedMember in to_set(await queries.get_group_transitive_members(args, excludedGroupId)):
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

def resolve_apps_for_policy_objects(args, all_apps, ca_defs):
  memberships = {}
  for ca_policy in ca_defs:
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


async def create_policymodels(args, principal_selection) -> Tuple[List[PolicyModel], GeneralInfo]:
  principal_ids: Set[str] = utils.principals_to_id_set(principal_selection)

  # Users
  policy_user_memberships = await resolve_members_for_policy_objects(args, principal_ids)
  policy_user_memberships['all_meta'] = principal_ids.copy()

  users_task = [GroupMembers(name=policy_id, members=members)
      for policy_id, members in policy_user_memberships.items()]
  policy_user_groups, dja_user_groups = split_to_disjoint_sets_ordered(users_task)
  
  ca_defs = await queries.get_ca_policy_defs(args)
  ca_defs = filter_ca_defs(args, ca_defs)

  # Applications
  all_apps = get_all_referenced_apps(ca_defs)
  all_apps.add(META_APP_ALL_UNMETIONED_APPS)
  all_apps.add(MICROSOFT_ADMIN_PORTALS_APP)  # make sure this is in separately
  policy_app_memberships = resolve_apps_for_policy_objects(args, all_apps, ca_defs)
  apps_task = [GroupMembers(name=policy_id, members=members)
      for policy_id, members in policy_app_memberships.items()]
  policy_app_groups, dja_app_groups = split_to_disjoint_sets_ordered(apps_task)

  seen_grant_controls = set()
  seen_session_controls = set()
  seen_app_user_actions = set()

  # Create models
  policyModels = []
  for ca_policy in ca_defs:
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
    else:
      grant_controls = []

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

    targeting_definition = await create_targeting_definition(args, ca_policy)

    policyModels.append(PolicyModel(
      id=policy_id,
      name=ca_policy['displayName'],
      enabled=enabled,
      targeting_definition=targeting_definition,
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
    users_count=len(principal_ids),
    apps_count=len(all_apps)
  )

  return policyModels, generalInfo