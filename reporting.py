
import csv
import json
from typing import List

import pandas as pd
from typedefs import GeneralInfo, PolicyModel

from utils import get_all_members
from settings import mk_all_users_path, mk_report_csv_path, mk_report_ca_coverage_path, mk_solutions_report_path


mk_html5_doc = lambda title, body_content: """
<html>
  <head>
    <style type="text/css">
      .mystyle {
        font-size: 11pt; 
        font-family: Arial;
        border-collapse: collapse; 
        border: 1px solid silver;
      }
      .mystyle td, th {
        padding: 5px;
      }
      .mystyle tr:nth-child(even) {
        background: #E0E0E0;
      }
      .mystyle tr:hover {
        background: silver;
        cursor: pointer;
      }
    </style>
    <title>%s</title>
  </head>

  <body>
  <h1>%s</h1>
  %s
  </body>
""" % (title, title, body_content)


def create_additional_section(args, policyModels, generalInfo:GeneralInfo):
  users_by_ids = get_all_members(args)

  s = '<ul>'
  s += '<li>Total users in section: %s</li>' % generalInfo.users_count
  for ug_id, user_ids in generalInfo.disjoint_artificial_user_groups.items():
    example_user = sorted(list(user_ids))[0]
    s += '<li>User group %d: Users: %d. Example user: %s</li>' % (ug_id, len(user_ids), users_by_ids[example_user]['userPrincipalName'])
  s += '</ul>'
  return s


def create_report_section(args, policyModels:List[PolicyModel], generalInfo:GeneralInfo, title):
  pms = sorted(policyModels, key=lambda x: (not x.enabled, x.name))

  d = {
     'Name': [p.name for p in pms],
     'On': [str(p.enabled) for p in pms],
     'Users': [len(p.members) for p in pms]
  }
  def x(b):
    return 'X' if b else ''

  for ug, members in generalInfo.disjoint_artificial_user_groups.items():
    u_count = len(members)
    d['UG%s/ %d' % (ug, u_count)] = [x(ug in p.condition_usergroups) for p in pms]

  for ag, apps in generalInfo.disjoint_artificial_app_groups.items():
    if len(apps) == 1:
      ag_id = 'AG%s %s' % (ag, list(apps)[0])
    else:
      ag_id = 'AG%s (%d apps)' % (ag, len(apps))
    d[ag_id] = [x(ag in p.condition_applications) for p in pms]

  for action in sorted(list(generalInfo.seen_app_user_actions)):
    d['Action: %s' % action] = [x(action in p.condition_application_user_action) for p in pms]

  d['C:operator'] = [p.grant_operator for p in pms]

  for control in sorted(list(generalInfo.seen_grant_controls)):
    d['GC:%s' % control] = [x(control in p.grant_controls) for p in pms]

  for control in sorted(list(generalInfo.seen_session_controls)):
    d['SC:%s' % control] = [x(control in p.session_controls) for p in pms]

  df = pd.DataFrame(data=d)

  additional = create_additional_section(args, policyModels, generalInfo)

  body_part = ''
  body_part += f'<h2>{title}</h2>'
  body_part += df.to_html(classes='mystyle')
  body_part += additional


  title_fn = title.replace(' ', '_').replace('&', '-')

  with open(mk_all_users_path(args)) as in_f:
    user_data = {}
    for member in json.load(in_f)['value']:
      user_data[member['id']] = member

  for ug, members in generalInfo.disjoint_artificial_user_groups.items():
    if '(' in title_fn:
      title_fn = title_fn[:title_fn.index('(')]
    fn = mk_report_csv_path(args, report=title_fn, ug_name='UG%s' % ug)
    with open(fn, 'w') as out_f:
      fieldnames = ['id', 'upn', 'accountEnabled', 'roles']
      writer = csv.DictWriter(out_f, fieldnames=fieldnames, dialect=csv.excel)
      writer.writeheader()
      for member in members:
        user = user_data[member]
        writer.writerow({
          'id': user['id'],
          'upn': user['userPrincipalName'],
          'accountEnabled': user['accountEnabled'],
          'roles': ''
        })
    
  with open(mk_report_ca_coverage_path(args, title_fn), 'w') as out_f:
    fieldnames = ['ca_name', 'assigned_users']
    writer = csv.DictWriter(out_f, fieldnames=fieldnames, dialect=csv.excel)
    writer.writeheader()
    for pm in pms:
      writer.writerow({
        'ca_name': pm.name,
        'assigned_users': len(pm.members)
      })

  return body_part


def solutions_to_table(args, solutions, displayed_vars):
  d = {}
  def x(b):
    return 'X' if b else ''

  for i in range(0, len(displayed_vars)):
    d[displayed_vars[i].name] = [x(s[i]) for s in solutions]

  df = pd.DataFrame(data=d)
  with open(mk_solutions_report_path(args), 'w') as out_f:
    out_f.write(mk_html5_doc("Solutions summary", df.to_html(classes='mystyle')))