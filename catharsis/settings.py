import argparse
from os import path as os_path

catharsis_parser = argparse.ArgumentParser(
  prog='CA Policy Gap Analyzer',
  description='What the program does',
  epilog='Text at the bottom of help')
catharsis_parser.add_argument('--cache-dir', type=str)
catharsis_parser.add_argument('--cache-mem', action='store_true')
catharsis_parser.add_argument('--report-dir', type=str)
catharsis_parser.add_argument('--create-ca-summary', action='store_true')
catharsis_parser.add_argument('--include-report-only', action='store_true')
catharsis_parser.add_argument('--get-licenses-from-graph', action='store_true', help='Get assigned licenses from Graph API, user per user (slow)')
catharsis_parser.add_argument('--number-of-solutions', type=int, default=5)
catharsis_parser.add_argument('--use-solver', action='store_true')

mk_report_path = lambda args: args.report_dir
mk_solutions_report_path = lambda args: os_path.join(args.work_dir, 'summary_solutions.html')
mk_summary_report_path = lambda args: os_path.join(mk_report_path(args), 'summary_of_ca.html')
mk_report_csv_path = lambda args, report, ug_name: os_path.join(mk_report_path(args), f'report_{report}_group_{ug_name}_members.csv')
mk_report_ca_coverage_path = lambda args, report: os_path.join(mk_report_path(args), f'report_{report}_coverage.csv')


META_APP_ALL_UNMETIONED_APPS = "RestOfTheApps"
MICROSOFT_ADMIN_PORTALS_APP = "MicrosoftAdminPortals"

ALL_CLIENT_APP_TYPES = ['browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other']
ALL_USER_RISK_LEVELS = ['high', 'medium', 'low', 'none']
ALL_SIGNIN_RISK_LEVELS = ['high', 'medium', 'low', 'none']