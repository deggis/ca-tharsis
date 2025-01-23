import argparse
from os import path as os_path

catharsis_parser = argparse.ArgumentParser(
  prog='CA Policy Gap Analyzer',
  description='What the program does',
  epilog='Text at the bottom of help')
catharsis_parser.add_argument('work_dir', type=str)
catharsis_parser.add_argument('--include-report-only', action='store_true')
catharsis_parser.add_argument('--create-queries', action='store_true')
catharsis_parser.add_argument('--get-licenses-from-graph', action='store_true', help='Get assigned licenses from Graph API, user per user (slow)')
catharsis_parser.add_argument('--number-of-solutions', type=int, default=5)
catharsis_parser.add_argument('--use-solver', action='store_true')

mk_ca_path = lambda args: os_path.join(args.work_dir, 'ca.json')
mk_group_result_path = lambda args, group_id: os_path.join(args.work_dir, f'group_{group_id}.json')
mk_role_result_raw_path = lambda args, role_id: os_path.join(args.work_dir, f'role_{role_id}_raw.json')
mk_role_result_resolved_path = lambda args, role_id: os_path.join(args.work_dir, f'role_{role_id}_resolved.json')
mk_all_users_path = lambda args: os_path.join(args.work_dir, 'all_users.json')
mk_all_service_principals_path = lambda args: os_path.join(args.work_dir, 'all_service_principals.json')  # az_ad_sp_list --all
mk_users_licenses = lambda args: os_path.join(args.work_dir, 'licenses.json')
mk_summary_report_path = lambda args: os_path.join(args.work_dir, 'summary_of_ca.html')
mk_report_csv_path = lambda args, report, ug_name: os_path.join(args.work_dir, f'report_{report}_group_{ug_name}_members.csv')
mk_report_ca_coverage_path = lambda args, report: os_path.join(args.work_dir, f'report_{report}_coverage.csv')
mk_solutions_report_path = lambda args: os_path.join(args.work_dir, 'summary_solutions.html')


META_APP_ALL_UNMETIONED_APPS = "RestOfTheApps"
MICROSOFT_ADMIN_PORTALS_APP = "MicrosoftAdminPortals"

ALL_CLIENT_APP_TYPES = ['browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other']
ALL_USER_RISK_LEVELS = ['high', 'medium', 'low', 'none']
ALL_SIGNIN_RISK_LEVELS = ['high', 'medium', 'low', 'none']