from enum import Enum, auto
from functools import cache
import itertools
import math
from typing import List
from functools import cache, reduce
import operator

from catharsis.settings import ALL_CLIENT_APP_TYPES
from catharsis.typedefs import GeneralInfo, PolicyModel

try:
  import cpmpy as cp
  from cpmpy.solvers.ortools import OrtSolutionPrinter
except ImportError:
  cp = None
  OrtSolutionPrinter = None

UNUSED_VARIABLE_COST=1

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

def get_uag_cost(args, uag_id, generalInfo:GeneralInfo):
  users_in_group = len(generalInfo.disjoint_artificial_user_groups[uag_id])
  return math.floor((users_in_group / generalInfo.users_count) * 100)

def get_aag_cost(args, aag_id, generalInfo:GeneralInfo):
  apps_in_group = len(generalInfo.disjoint_artificial_app_groups[aag_id])
  # FIXME: differentiate apps
  return math.floor((apps_in_group / generalInfo.apps_count) * 10)


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