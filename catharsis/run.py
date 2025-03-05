import argparse

from catharsis.settings import setup_logging
from catharsis.task_ca_report import add_ca_report_subparser
from catharsis.task_list_admins import add_list_admins_subparser
from catharsis.task_solver import add_solver_subparser
from catharsis import utils


async def main(arg_string=None):
  catharsis_parser = argparse.ArgumentParser(
    prog='ca-tharsis',
    description='CA stuff',
    epilog='')
  catharsis_parser.add_argument('--persist-cache-dir', type=str, help='Optional: persist cache as files to directory.')
  catharsis_parser.add_argument('--debug', action='store_true', help='Enable debugpy debugging.')
  catharsis_parser.add_argument('--include-report-only', action='store_true', help='CA: Include report-only CA policies.')
  catharsis_parser.add_argument('--get-licenses-from-graph', action='store_true', help='Get assigned licenses from Graph API, user per user (slow)')
  catharsis_parser.add_argument('--auth', choices=['azcli', 'systemassignedmanagedidentity'], default='azcli', help='Configure what credentials are used: AzCliCredentials or a Managed Identity. Default: azcli')
  catharsis_parser.add_argument('--log-output', choices=['stdout', 'defaulthandler'], default='stdout', help='Configure logging.')


  subparsers = catharsis_parser.add_subparsers(required=True)
  add_ca_report_subparser(subparsers)
  add_solver_subparser(subparsers)
  add_list_admins_subparser(subparsers)
  args = catharsis_parser.parse_args(arg_string)
  setup_logging(args)

  if args.debug:
    utils.prepare_debug()
  args._tenant_id_checked = False
  utils.ensure_cache_and_workdir(args)
  await args.task_func(args)