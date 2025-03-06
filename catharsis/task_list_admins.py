from catharsis.azure.azure_fetcher import get_privileged_azure_principals
from catharsis.azure.watchlist import put_principals_to_watchlist, WatchlistPrincipal
from catharsis.ca import create_policymodels
from catharsis.solver import translate_policymodels_to_task
from catharsis.typedefs import RunConf
from catharsis.graph_query import get_all_users, get_role_transitive_members
from catharsis import utils
import catharsis.typedefs as CT
import catharsis.settings as S


import logging
logger = logging.getLogger('catharsis.list_admins')
logger.setLevel(logging.INFO)


async def do_task_list_admins(args: RunConf):
  watchlist_principals: dict[CT.PrincipalGuid, WatchlistPrincipal] = {}

  if args.include_azure_admins:
    principal_sub_roles, subs, seen_members = await get_privileged_azure_principals(args)
    for principal_id, subs_to_roles in principal_sub_roles.items():
      wl_principal = watchlist_principals.setdefault(principal_id, WatchlistPrincipal(principal_id))
      wl_principal.principal_type = seen_members[principal_id].principalType
      wl_principal.azure_roles = '%d subs' % len(subs_to_roles.keys())

  if args.include_entra_roles:
    entra_role_guids_to_check = set()
    if args.include_entra_roles == 'default':
      entra_role_guids_to_check = set(S.ENTRA_ADMIN_ROLES.keys())
    else:
      for given_guid in args.include_entra_roles.split(','):
        entra_role_guids_to_check.add(given_guid)

    for role_guid in entra_role_guids_to_check:
      role_members = await get_role_transitive_members(args, role_guid)
      for role_member in role_members:
        principal_id = role_member.principalId
        wl_principal = watchlist_principals.setdefault(principal_id, WatchlistPrincipal(principal_id))
        wl_principal.principal_type = role_member.principalType
        entra_role_name = S.ENTRA_ALL_ROLES.get(role_guid) or ('CUSTOM_ROLE?%s' % role_guid)
        wl_principal.entra_roles.append(entra_role_name)

  if len(watchlist_principals.keys()) > 0:
    await put_principals_to_watchlist(args, watchlist_principals)
  else:
    logger.warning('No principals found. Skipping updating the watchlist.')
  # create model
  logger.info('Task ready.')


def add_list_admins_subparser(subparsers):
  list_admins_parser = subparsers.add_parser('list-admins')
  list_admins_parser.set_defaults(task_func=do_task_list_admins)
  list_admins_parser.add_argument('--subscription-id')
  list_admins_parser.add_argument('--include-entra-roles', help='Comma separated list of Entra role GUIDs to include. "default" includes a default set of Entra admin role GUIDs (isPrivileged=true).')
  list_admins_parser.add_argument('--include-azure-admins', action='store_true', help='Include Azure admin memberships.')
  # add_argument --include-graphapi-admins

  list_admins_parser.add_argument('--skip-existing-watchlist-deletion', action='store_true', help='Do not delete previous watchlist. If it is not deleted, old items will exist and new items are appended.')
  list_admins_parser.add_argument('--to-watchlist', help="WATCHLIST_RG:WATCHLIST_WSNAME:WATCHLIST_DISPLAYNAME:WATCHLIST_ALIAS")
