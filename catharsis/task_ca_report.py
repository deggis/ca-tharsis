import os
import shutil

from catharsis.ca import create_policymodels
from catharsis.reporting import create_report_section, mk_html5_doc
from catharsis.settings import mk_summary_report_path, mk_summary_report_aux_path
from catharsis.typedefs import RunConf
from catharsis.utils import count_s, ensure_cache_and_workdir, prefetch_ca_memberships_with_query
from catharsis.graph_query import get_all_users, get_all_service_principals
from catharsis import utils


import logging
logger = logging.getLogger('catharsis.task_ca_report')
logger.setLevel(logging.INFO)

"""
TODO: Warnings
- https://learn.microsoft.com/en-us/entra/identity/conditional-access/migrate-approved-client-app
"""

async def do_task_ca_report(args: RunConf):
  ensure_cache_and_workdir(args)
  await get_all_users(args)
  await get_all_service_principals(args)
  await prefetch_ca_memberships_with_query(args)
  
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

  report_path = mk_summary_report_path(args)
  logger.info('Writing CA summary report to: %s', report_path)
  with open(report_path, 'w') as out_f:
    out_f.write(mk_html5_doc('CA report', body_content))
  dirname, _ = os.path.split(os.path.abspath(__file__))
  shutil.copy(os.path.join(dirname, '..', 'static', 'app.js'), mk_summary_report_aux_path(args, 'app.js'))
  shutil.copy(os.path.join(dirname, '..', 'static', 'style.css'), mk_summary_report_aux_path(args, 'style.css'))
  logger.info('Task ready.')

def add_ca_report_subparser(subparsers):
  ca_report_parser = subparsers.add_parser('ca-report')
  ca_report_parser.add_argument('report_dir', type=str)
  ca_report_parser.set_defaults(task_func=do_task_ca_report)