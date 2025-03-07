from typing import List, Mapping, Optional
from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights
from azure.mgmt.securityinsight.models import Watchlist
from azure.core.exceptions import ResourceNotFoundError

from catharsis.graph_query import get_all_service_principals, get_all_users
from catharsis.ms_credential import get_ms_credential
from catharsis.typedefs import RunConf, principal_to_string
import catharsis.typedefs as CT

import csv
import io
from itertools import islice

import logging
logger = logging.getLogger('catharsis.watchlist')
logger.setLevel(logging.INFO)


def chunk(it, size):
    it = iter(it)
    return iter(lambda: tuple(islice(it, size)), ())

class WatchlistPrincipal(object):
  def __init__(self, principal_id):
    self.principal_id: CT.PrincipalGuid = principal_id
    self.principal_type: Optional[CT.PrincipalType] = None
    self.principal_displayname: str = ''
    self.entra_roles: List[str] = []
    self.azure_roles: str = ''

async def put_principals_to_watchlist(args: RunConf, watchlist_items: Mapping[CT.PrincipalGuid, WatchlistPrincipal]):
  cred = get_ms_credential(args)
  sentinel = SecurityInsights(cred, args.subscription_id)

  watchlist_rg, watchlist_wsname, watchlist_displayname, watchlist_alias = args.to_watchlist.split(':')

  # Resolve displayNames
  if True:
    user_ids = [wi.principal_id for wi in watchlist_items.values() if wi.principal_type == CT.PrincipalType.User]
    sp_ids = [wi.principal_id for wi in watchlist_items.values() if wi.principal_type == CT.PrincipalType.ServicePrincipal]

    # TODO: move this to graph_query
    for user_id_chunk in chunk(user_ids, 15):
      user_chunk = await get_all_users(args, user_id_chunk)
      for principal_id, principal in user_chunk.items():
        watchlist_items[principal_id].principal_displayname = principal_to_string(principal)

    for app_id_chunk in chunk(sp_ids, 15):
      app_chunk = await get_all_service_principals(args, app_id_chunk)
      for principal_id, principal in app_chunk.items():
        watchlist_items[principal_id].principal_displayname = principal_to_string(principal)

  csv_file = io.StringIO()
  fieldnames = 'User AAD Object Id,principal_type,User Principal Name,entra_roles,azure_roles'.split(',')
  writer = csv.DictWriter(f=csv_file, fieldnames=fieldnames)
  writer.writeheader()
  for watchlist_principal in sorted(watchlist_items.values(), key=lambda o: o.principal_id):
    writer.writerow({
      'User AAD Object Id': watchlist_principal.principal_id,
      'principal_type': watchlist_principal.principal_type.name if watchlist_principal.principal_type else '',
      'User Principal Name': watchlist_principal.principal_displayname,
      'entra_roles': watchlist_principal.entra_roles,
      'azure_roles': watchlist_principal.azure_roles
    })

  # User AAD Object Id,principal_type,User Principal Name,entra_roles,azure_roles
  raw_watchlist_data = csv_file.getvalue()


  watchlist = Watchlist(
    display_name=watchlist_displayname,
    raw_content=raw_watchlist_data,
    items_search_key="User AAD Object Id",
    provider="ca-tharsis",
    source="ca-tharsis",
    content_type="text/csv",
    number_of_lines_to_skip=0
  )

  if not args.skip_existing_watchlist_deletion:
    logger.info('Removing previous watchlist %s' % watchlist_alias)
    try:
      sentinel.watchlists.delete(watchlist_rg, watchlist_wsname, watchlist_alias)
    except ResourceNotFoundError:
      # Good. Nothing to clear from our way.
      pass

  # https://learn.microsoft.com/en-us/azure/sentinel/watchlists-manage#bulk-update-a-watchlist
  # When you have many items to add to a watchlist, use bulk update.
  # A bulk update of a watchlist appends items to the existing watchlist.
  # Then, it de-duplicates the items in the watchlist where all the value
  # in each column match.
  logger.info('Putting new watchlist (%s) in place with %d entries.' % (watchlist_alias, len(watchlist_items)))
  sentinel.watchlists.create_or_update(watchlist_rg, watchlist_wsname, watchlist_alias, watchlist)