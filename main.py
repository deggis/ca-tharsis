import asyncio
import argparse

from catharsis.task_ca_report import add_ca_report_subparser
from catharsis.task_solver import add_solver_subparser
from catharsis import utils


async def main():
  catharsis_parser = argparse.ArgumentParser(
    prog='ca-tharsis',
    description='CA stuff',
    epilog='')
  catharsis_parser.add_argument('--persist-cache-dir', type=str, help='Optional: persist cache as files to directory.')
  catharsis_parser.add_argument('--debug', action='store_true', help='Enable debugpy debugging.')
  catharsis_parser.add_argument('--include-report-only', action='store_true', help='CA: Include report-only CA policies.')
  catharsis_parser.add_argument('--get-licenses-from-graph', action='store_true', help='Get assigned licenses from Graph API, user per user (slow)')

  subparsers = catharsis_parser.add_subparsers(required=True)
  add_ca_report_subparser(subparsers)
  add_solver_subparser(subparsers)
  args = catharsis_parser.parse_args()

  if args.debug:
    utils.prepare_debug()
  await args.task_func(args)

if __name__ == '__main__':
  asyncio.run(main())
