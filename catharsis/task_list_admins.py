from catharsis.azure.azure_fetcher import get_privileged_azure_principals
from catharsis.azure.watchlist import put_principals_to_watchlist
from catharsis.ca import create_policymodels
from catharsis.solver import translate_policymodels_to_task
from catharsis.typedefs import RunConf
from catharsis.graph_query import get_all_users
from catharsis import utils

import logging
logger = logging.getLogger('catharsis.list_admins')
logger.setLevel(logging.INFO)


async def do_task_list_admins(args: RunConf):
  principal_guids = await get_privileged_azure_principals(args)
  await put_principals_to_watchlist(args, principal_guids)

  # create model
  logger.info('Task ready.')


def add_list_admins_subparser(subparsers):
  list_admins_parser = subparsers.add_parser('list-admins')
  list_admins_parser.set_defaults(task_func=do_task_list_admins)
  list_admins_parser.add_argument('--subscription-id')
  list_admins_parser.add_argument('--to-watchlist', help="WATCHLIST_RG:WATCHLIST_WSNAME:WATCHLIST_DISPLAYNAME:WATCHLIST_ALIAS")
