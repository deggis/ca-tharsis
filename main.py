from os.path import join as path_join
import os
import shutil
from typing import List
from enum import Enum, auto
import asyncio

from catharsis.ca import create_policymodels
from catharsis.licenses import get_licenses
from catharsis.reporting import create_report_section, mk_html5_doc
from catharsis.settings import catharsis_parser, mk_summary_report_path, mk_summary_report_aux_path
from catharsis.solver import translate_policymodels_to_task
from catharsis.utils import count_s, get_members_azcli, ensure_cache_and_workdir, fetch_all_users_azcli, fetch_ca_policy_azcli, prefetch_ca_memberships_with_query
from catharsis.cached_get import mk_all_users_path
from catharsis.graph_query import get_all_users, get_all_service_principals
from catharsis.typedefs import CatharsisEncoder, catharsis_decoder
from catharsis.graph_query import get_unresolved_role_assignments
from catharsis import utils
import logging
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

  if True:
    import debugpy
    # 5678 is the default attach port in the VS Code debug configurations. Unless a host and port are specified, host defaults to 127.0.0.1
    debugpy.listen(5678)
    print("Waiting for debugger attach")
    debugpy.wait_for_client()
    debugpy.breakpoint()
    print('break on this line')

  logging.basicConfig(encoding='utf-8', level=logging.INFO)
  logging.getLogger('azure.identity._internal.decorators').setLevel(logging.WARN)
  rootlogger = logging.getLogger()
  rootlogger.handlers = []
  ch = logging.StreamHandler()
  ch.setLevel(logging.INFO)
  # create formatter
  formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  # add formatter to ch
  ch.setFormatter(formatter)
  # add ch to logger
  rootlogger.addHandler(ch)

  if args.use_solver and not solver_imports_available:
    raise Exception("cpmpy related libraries are not available!")

  ensure_cache_and_workdir(args)
  await get_all_users(args)
  await get_all_service_principals(args)
  await prefetch_ca_memberships_with_query(args)
  
  if args.create_ca_summary:

    body_content = ''
    all_users = list((await get_all_users(args)).values())
    # create pre-model separately and translate it later to cpmpy
    policy_models, generalInfo = await create_policymodels(args, all_users)
    body_content += await create_report_section(args, policy_models, generalInfo, 'All users')

    active = [u for u in all_users if utils.is_principal_account_enabled(u)]
    policy_models, generalInfo = await create_policymodels(args, active)
    body_content += await create_report_section(args, policy_models, generalInfo, 'All active users (%s)' % count_s(len(active), len(all_users)))

    active_internal = [u for u in active if not utils.is_user_external(u)]
    policy_models, generalInfo = await create_policymodels(args, active_internal)
    body_content += await create_report_section(args, policy_models, generalInfo, 'All active & internal (%s)' % count_s(len(active_internal), len(all_users)))

    active_external = [u for u in active if utils.is_user_external(u)]
    policy_models, generalInfo = await create_policymodels(args, active_external)
    body_content += await create_report_section(args, policy_models, generalInfo, 'All active & guest (%s)' % count_s(len(active_external), len(all_users)))

    # TODO Add Service Principals

    with open(mk_summary_report_path(args), 'w') as out_f:
      out_f.write(mk_html5_doc('CA report', body_content))
    dirname, _ = os.path.split(os.path.abspath(__file__))
    shutil.copy(os.path.join(dirname, 'static', 'app.js'), mk_summary_report_aux_path(args, 'app.js'))
    shutil.copy(os.path.join(dirname, 'static', 'style.css'), mk_summary_report_aux_path(args, 'style.css'))

  # create model
  if args.use_solver:
    translate_policymodels_to_task(args, policy_models, generalInfo)

  # display warnings

if __name__ == '__main__':
  asyncio.run(main())
