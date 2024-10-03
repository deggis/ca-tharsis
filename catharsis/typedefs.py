from collections import namedtuple

UserTargetingDefinition = namedtuple('UserTargetingDefinition', [
  'included_users',
  'included_groups',
  'included_roles',
  'includeGuestsOrExternalUsers',
  'excluded_users',
  'excluded_groups',
  'excluded_roles',
  'excludeGuestsOrExternalUsers'
])


PolicyModel = namedtuple('PolicyModel', [
  'id',
  # General information to help reporting
  'name',
  'members',
  'enabled',
  'targeting_definition',
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