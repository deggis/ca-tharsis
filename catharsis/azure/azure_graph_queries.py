import os
from typing import List, Tuple, Callable, TypeAlias

from catharsis.typedefs import RunConf

# ResultPathResolver: TypeAlias = Callable[[str], str]
# ALL_QUERIES: List[Tuple[ResultPathResolver, str]] = []

get_az_result_path: Callable[[RunConf, str], str] = lambda runconf, fn: os.path.join(runconf.work_dir, fn)

ALL_QUERIES: List[Tuple[str, str]] = []



# Resource containers

SUBSCRIPTIONS_FILE = "azure_subscriptions.json"
SUBSCRIPTIONS_QUERY = 'resourcecontainers | where type == "microsoft.resources/subscriptions" | project id, name, tenantId, subscriptionId, tags, properties'
ALL_QUERIES.append((SUBSCRIPTIONS_FILE, SUBSCRIPTIONS_QUERY))

MANAGEMENT_GROUPS_FILE = "azure_managementgroups.json"
MANAGEMENT_GROUPS_QUERY = 'resourcecontainers | where type == "microsoft.management/managementgroups" | project id, name, tenantId, tags, properties'
ALL_QUERIES.append((MANAGEMENT_GROUPS_FILE, MANAGEMENT_GROUPS_QUERY))