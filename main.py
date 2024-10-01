from os.path import join as path_join
import os
from typing import List
from enum import Enum, auto

from ca import create_policymodels
from licenses import get_licenses
from reporting import create_report_section, mk_html5_doc
from settings import catharsis_parser, mk_all_users_path, mk_summary_report_path
from solver import translate_policymodels_to_task
from utils import count_s, get_members
from utils_graphapi import fetch_all_users, fetch_ca_policy, resolve_memberships_with_query

solver_imports_available = True
try:
  import cpmpy as cp
  from cpmpy.solvers.ortools import OrtSolutionPrinter
except ImportError:
  cp = None
  OrtSolutionPrinter = None
  solver_imports_available = False


# Conditional Access Constraint Solver for Gaps
# CACSFG



def display_warnings(args):
  # https://learn.microsoft.com/en-us/entra/identity/conditional-access/migrate-approved-client-app
  pass

def main():
  args = catharsis_parser.parse_args()

  if args.use_solver and not solver_imports_available:
    raise Exception("cpmpy related libraries are not available!")

  if not os.path.exists(args.work_dir):
    os.makedirs(args.work_dir)
  fetch_ca_policy(args)
  resolve_memberships_with_query(args)
  fetch_all_users(args)
  if args.get_licenses_from_graph:
    get_licenses(args)

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
  main()
