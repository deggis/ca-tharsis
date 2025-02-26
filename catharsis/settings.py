import logging
from os import path as os_path

from catharsis.typedefs import RunConf


def setup_logging(args: RunConf):
  logging.basicConfig(encoding='utf-8', level=logging.INFO)
  logging.getLogger('azure.identity._internal.decorators').setLevel(logging.WARN)
  logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.WARN)
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


mk_report_path = lambda args: args.report_dir
mk_solutions_report_path = lambda args: os_path.join(args.work_dir, 'summary_solutions.html')
mk_summary_report_path = lambda args: os_path.join(mk_report_path(args), 'summary_of_ca.html')
mk_summary_report_aux_path = lambda args, additional: os_path.join(mk_report_path(args), additional)
mk_report_csv_path = lambda args, report, ug_name: os_path.join(mk_report_path(args), f'report_{report}_group_{ug_name}_members.csv')
mk_report_ca_coverage_path = lambda args, report: os_path.join(mk_report_path(args), f'report_{report}_coverage.csv')


META_APP_ALL_UNMETIONED_APPS = "RestOfTheApps"
MICROSOFT_ADMIN_PORTALS_APP = "MicrosoftAdminPortals"

ALL_CLIENT_APP_TYPES = ['browser', 'mobileAppsAndDesktopClients', 'exchangeActiveSync', 'other']
ALL_USER_RISK_LEVELS = ['high', 'medium', 'low', 'none']
ALL_SIGNIN_RISK_LEVELS = ['high', 'medium', 'low', 'none']

ENTRA_ADMIN_ROLES = {
  'Application Administrator': '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
  'Application Developer': 'cf1c38e5-3621-4004-a7cb-879624dced7c'
}