from os.path import join as path_join
import os
from typing import List
from enum import Enum, auto
import asyncio

from catharsis.ca import create_policymodels
from catharsis.licenses import get_licenses
from catharsis.reporting import create_report_section, mk_html5_doc
from catharsis.settings import catharsis_parser, mk_summary_report_path
from catharsis.solver import translate_policymodels_to_task
from catharsis.utils import count_s, get_members, ensure_cache_and_workdir, fetch_all_users_azcli, fetch_ca_policy_azcli, resolve_ca_memberships_with_query
from catharsis.cached_get import mk_all_users_path
from catharsis.graph_query import get_all_users
from catharsis.typedefs import CatharsisEncoder, catharsis_decoder
import json


solver_imports_available = True
try:
  import cpmpy as cp
  from cpmpy.solvers.ortools import OrtSolutionPrinter
except ImportError:
  cp = None
  OrtSolutionPrinter = None
  solver_imports_available = False

def display_warnings(args):
  # https://learn.microsoft.com/en-us/entra/identity/conditional-access/migrate-approved-client-app
  pass

async def main():
  args = catharsis_parser.parse_args()

  if args.use_solver and not solver_imports_available:
    raise Exception("cpmpy related libraries are not available!")

  if True:
    import debugpy
    # 5678 is the default attach port in the VS Code debug configurations. Unless a host and port are specified, host defaults to 127.0.0.1
    debugpy.listen(5678)
    print("Waiting for debugger attach")
    debugpy.wait_for_client()
    debugpy.breakpoint()
    print('break on this line')

  ensure_cache_and_workdir(args)
  await get_all_users(args)
  await resolve_ca_memberships_with_query(args)
  
  if args.create_ca_summary:

    body_content = ''
    all_users = get_members(mk_all_users_path(args))
    # create pre-model separately and translate it later to cpmpy
    policy_models, generalInfo = create_policymodels(args, user_selection=all_users)
    body_content += create_report_section(args, policy_models, generalInfo, 'All users')

    users = get_members(mk_all_users_path(args), req_user_active=True)
    policy_models, generalInfo = create_policymodels(args, user_selection=users)
    body_content += create_report_section(args, policy_models, generalInfo, 'All active users (%s)' % count_s(len(users), len(all_users)))

    users = get_members(mk_all_users_path(args), req_user_active=True, req_user_internal=True)
    policy_models, generalInfo = create_policymodels(args, user_selection=users)
    body_content += create_report_section(args, policy_models, generalInfo, 'All active & internal (%s)' % count_s(len(users), len(all_users)))

    users = get_members(mk_all_users_path(args), req_user_active=True, req_user_guest=True)
    policy_models, generalInfo = create_policymodels(args, user_selection=users)
    body_content += create_report_section(args, policy_models, generalInfo, 'All active & guest (%s)' % count_s(len(users), len(all_users)))

    with open(mk_summary_report_path(args), 'w') as out_f:
      out_f.write(mk_html5_doc('CA report', body_content))

  # create model
  if args.use_solver:
    translate_policymodels_to_task(args, policy_models, generalInfo)

  # display warnings

if __name__ == '__main__':
  asyncio.run(main())
