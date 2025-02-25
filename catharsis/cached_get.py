from catharsis.typedefs import RunConf
from os import path as os_path
import os
import json
import typing
from functools import cache

from catharsis.typedefs import PrincipalType, RunConf, Principal, ServicePrincipalDetails, ServicePrincipalType, UserPrincipalDetails, CatharsisEncoder, catharsis_decoder

import logging
logger = logging.getLogger('catharsis.cached_get')
logger.setLevel(logging.INFO)

# Common: get data with runconf, translated to catharsis-models

IN_MEM_CACHE_PREFIX = 'mem:'
mk_path = lambda args: args.persist_cache_dir or IN_MEM_CACHE_PREFIX

mk_ca_path = lambda args: os_path.join(mk_path(args), 'ca.json')
mk_group_result_transitive_path = lambda args, group_id: os_path.join(mk_path(args), f'group_{group_id}.json')
mk_role_assignment_raw_path = lambda args, role_id: os_path.join(mk_path(args), f'role_{role_id}_raw.json')
mk_role_result_transitive_path = lambda args, role_id: os_path.join(mk_path(args), f'role_{role_id}_resolved.json')
mk_all_users_path = lambda args: os_path.join(mk_path(args), 'all_users.json')
mk_all_service_principals_path = lambda args: os_path.join(mk_path(args), 'all_service_principals.json')  # az_ad_sp_list --all
mk_users_licenses = lambda args: os_path.join(mk_path(args), 'licenses.json')

_IN_MEMORY_CACHE: dict[str, typing.Any] = {}

def get_cached(key: str) -> typing.Any:
    if key.startswith(IN_MEM_CACHE_PREFIX):
        cached = _IN_MEMORY_CACHE.get(key)
        if not cached:
            logger.info('Cache miss with key=%s', key)
        return cached
    else:
        if os.path.exists(key):
            # Cache this
            with open(key) as in_f:
                return json.load(in_f, object_hook=catharsis_decoder)
        logger.info('Cache miss with key=%s', key)
        return None

def set_cached(key: str, value: typing.Any) -> typing.Any:
    if key.startswith(IN_MEM_CACHE_PREFIX):
        _IN_MEMORY_CACHE[key] = value
    else:
        with open(key, 'w') as out_f:
            return json.dump(value, out_f, cls=CatharsisEncoder)


@cache
def _get_user_principals(path: str) -> dict[str, Principal]:
    result = {}
    with open(path) as in_f:
      service_principals = json.load(in_f)
      for item in service_principals['value']:
        user_id = item['id']
        result[user_id] = Principal(
          id=user_id,
          displayName=item['userPrincipalName'],
          accountEnabled=item['accountEnabled'],
          raw=item,
          usertype=PrincipalType.User,
          userDetails=UserPrincipalDetails(upn=item['userPrincipalName'])
        )
    return result

def get_user_principals(args: RunConf) -> dict[str, Principal]:
  return _get_user_principals(mk_all_users_path(args))



@cache
def _get_service_principals(path: str) -> dict[str, Principal]:
    result = {}
    with open(path) as in_f:
      service_principals = json.load(in_f)
      for item in service_principals:
        sp_id = item['id']
        sp_type = item['servicePrincipalType']
        result[sp_id] = Principal(
          id=sp_id,
          displayName=item['displayName'],
          accountEnabled=item['accountEnabled'],
          raw=item,
          usertype=PrincipalType.ServicePrincipal,
          spDetails=ServicePrincipalDetails(
              ServicePrincipalType(sp_type)
          )
        )
    return result

def get_service_principals(args: RunConf) -> dict[str, Principal]:
  return _get_service_principals(mk_all_service_principals_path(args))

def get_principals(args: RunConf) -> dict[str, Principal]:
  """
  Principals indexed by object id
  """
  @cache
  def _get_principals(user_path: str, sp_path: str):
    sps = _get_service_principals(sp_path)
    users = _get_user_principals(user_path)
    results = sps.copy()
    results.update(users)
    return results
  return _get_principals(mk_all_users_path(args), mk_all_service_principals_path(args))



