from azure.identity import DefaultAzureCredential
from azure.mgmt.securityinsight import SecurityInsights
from azure.mgmt.securityinsight.models import Watchlist

from catharsis.typedefs import RunConf

import csv
import io


async def put_principals_to_watchlist(args: RunConf, principal_ids):
  cred = DefaultAzureCredential()
  sentinel = SecurityInsights(cred, args.subscription_id)

  if args.to_watchlist:
    watchlist_rg, watchlist_wsname, watchlist_displayname, watchlist_alias = args.to_watchlist.split(':')

    csv_file = io.StringIO()
    fieldnames = 'User AAD Object Id,principal_type,User Principal Name,entra_roles,azure_roles'.split(',')
    writer = csv.DictWriter(f=csv_file, fieldnames=fieldnames)
    writer.writeheader()
    for principalId in principal_ids:
      writer.writerow({
        'User AAD Object Id': principalId,
        'principal_type': '?',
        'User Principal Name': '?',
        'entra_roles': '?',
        'azure_roles': 'yes'
      })

    # User AAD Object Id,principal_type,User Principal Name,entra_roles,azure_roles
    raw_watchlist_data = csv_file.getvalue()

    watchlist = Watchlist(
      display_name=watchlist_displayname,
      raw_content=raw_watchlist_data,
      items_search_key="User AAD Object Id",
      provider="Test",
      source="ca-tharsis",
      content_type="text/csv",
      number_of_lines_to_skip=0
    )
    sentinel.watchlists.create_or_update(watchlist_rg, watchlist_wsname, watchlist_alias, watchlist)