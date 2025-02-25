
import csv
from typing import List

import pandas as pd
from catharsis.graph_query import get_all_principals
from catharsis.typedefs import GeneralInfo, PolicyModel, principal_to_string

from catharsis.settings import mk_report_csv_path, mk_report_ca_coverage_path, mk_solutions_report_path


mk_html5_doc = lambda title, body_content: """
<html>
  <head>
    <link rel="stylesheet" href="style.css" />
    <title>%s</title>
    <script src="app.js"></script>
  </head>

  <body>
  <h1>%s</h1>
  %s
  </body>
""" % (title, title, body_content)


async def create_additional_section(args, policyModels, generalInfo:GeneralInfo):
  principals_by_uids = await get_all_principals(args)

  s = '<ul>'
  s += '<li>Total users in section: %s</li>' % generalInfo.users_count
  for ug_id, principal_ids in generalInfo.disjoint_artificial_user_groups.items():
    example_principal_id = sorted(list(principal_ids))[0]
    example_principal = principals_by_uids[example_principal_id]
    s += '<li>User group %d: Users: %d. Example user: %s</li>' % (ug_id, len(principal_ids), principal_to_string(example_principal))
  s += '</ul>'
  return s


async def create_report_section(args, policyModels:List[PolicyModel], generalInfo:GeneralInfo, title):
  pms = sorted(policyModels, key=lambda x: (not x.enabled, x.name))

  col_groups: List[dict] = []
  d = {
     'Name': [p.name for p in pms],
     'On': [str(p.enabled) for p in pms],
     'Users': [len(p.members) for p in pms]
  }
  col_groups.append({
    'name': 'Basic info',
    'span': 4,
    'columns': ['Row', 'Name', 'On', 'Users'],
    'class': 'basicinfo'
  })
  def x(b):
    return 'X' if b else ''

  ug_counts = {}
  ugs = []
  for ug, member_principal_ids in generalInfo.disjoint_artificial_user_groups.items():
    u_count = len(member_principal_ids)
    ug_col_name = 'UG%s' % ug
    #d['UG%s/ %d' % (ug, u_count)] = [x(ug in p.condition_usergroups) for p in pms]
    d[ug_col_name] = [x(ug in p.condition_usergroups) for p in pms]
    ugs.append(ug_col_name)
    ug_counts[ug_col_name] = u_count
  col_groups.append({
    'name': 'UGs',
    'span': len(ugs),
    'columns': ugs,
    'class': 'ugs'
  })

  ags = []
  for ag, apps in generalInfo.disjoint_artificial_app_groups.items():
    if len(apps) == 1:
      ag_id = 'AG%s %s' % (ag, list(apps)[0])
    else:
      ag_id = 'AG%s (%d apps)' % (ag, len(apps))
    d[ag_id] = [x(ag in p.condition_applications) for p in pms]
    ags.append(ag_id)
  if ags:
    col_groups.append({
      'name': 'AGs',
      'span': len(ags),
      'columns': ags,
      'class': 'ags'
    })

  actions = []
  for action in sorted(list(generalInfo.seen_app_user_actions)):
    action_name = 'Action: %s' % action
    d[action_name] = [x(action in p.condition_application_user_action) for p in pms]
    actions.append(action_name)
  if actions:
    col_groups.append({
      'name': 'User actions',
      'span': len(actions),
      'columns': actions,
      'class': 'useractions'
    })

  grant_controls = ['Operator']
  for control in sorted(list(generalInfo.seen_grant_controls)):
    grant_control_name = 'GC:%s' % control
    d[grant_control_name] = [x(control in p.grant_controls) for p in pms]
    grant_controls.append(grant_control_name)
  if grant_controls:
    d['Operator'] = [(p.grant_operator or '') for p in pms]
    col_groups.append({
      'name': 'GrantControls',
      'span': len(grant_controls),
      'columns': grant_controls,
      'class': 'grantcontrols'
    })

  session_controls = []
  for control in sorted(list(generalInfo.seen_session_controls)):
    session_control_name = 'SC:%s' % control
    d[session_control_name] = [x(control in p.session_controls) for p in pms]
    session_controls.append(session_control_name)
  if session_controls:
    col_groups.append({
      'name': 'SessionControls',
      'span': len(session_controls),
      'columns': session_controls,
      'class': 'sessioncontrols'
    })

  # df = pd.DataFrame(data=d)

  additional = await create_additional_section(args, policyModels, generalInfo)

  body_part = ''
  body_part += f'<h2>{title}</h2>'
  #body_part += df.to_html(classes='mystyle')
  
  body_part += '<table class="catable">'
  body_part += f'<caption>{title}</caption>'
  body_part += '<colgroup>'
  for cg_data in col_groups:
    span = cg_data['span']
    cls = cg_data['class']
    body_part += f'<col span="{span}" columnname="{cls}" class="{cls} colgroup-large" />'
    body_part += f'<col span="1" columnname="{cls}" class="{cls} colgroup-min" />'
  body_part += '</colgroup>' 

  # Zero row: column group names
  body_part += '<tr>' 
  for cg_data in col_groups:
      span = cg_data['span']
      cls = cg_data['class']
      name = cg_data['name']
      body_part += f'<th colspan="{span}" class="col-group {cls}"><a columname="{cls}" class="col-closeaction {cls}">{name}</a></th>'
      body_part += f'<th class="col-group-minified {cls}"><a columname="{cls}" class="col-openaction {cls}">{name} (show)</a></th>'
  body_part += '</tr>' 

  # First row: columns, group names
  body_part += '<tr>' 
  for cg_data in col_groups:
      span = cg_data['span']
      cls = cg_data['class']
      for col in cg_data['columns']:
        body_part += f'<th class="col-{col} {cls} subtitle">{col}</th>'
      body_part += f'<th></th>'
  body_part += '</tr>' 

  # 2nd row: counts
  body_part += '<tr>' 
  for cg_data in col_groups:
    for col in cg_data['columns']:
      count = ''
      if col.startswith('UG'):
        count = '%d' % ug_counts[col]
      body_part += f'<th>{count}</th>'
    body_part += f'<td>.</td>' # minified column
  body_part += '</tr>'

  # Policy rows
  for i, p in enumerate(pms):
    body_part += '<tr>'
    for cg_data in col_groups:
      for col_name in cg_data['columns']:
        css_classes = []
        if col_name in d:
          content = d[col_name][i]
        elif col_name == 'Row':
          content = '%d' % (i+1)
        else:
          content = '?'

        if col_name.startswith('UG'):
          css_classes.append('ug')
        elif col_name.startswith('AG'):
          css_classes.append('ag')
        if col_name.startswith('UG') or col_name.startswith('AG'):
          css_classes.append('onoff')
          css_classes.append('onoff-filled' if content else 'onoff-empty')
        class_part = (' class ="%s"' % (' '.join(css_classes))) if css_classes else ''
        body_part += f'<td{class_part}>{content}</td>'
      body_part += f'<td>.</td>' # minified column
    body_part += '</tr>'

  body_part += '</table>'

  body_part += additional

  title_fn = title.replace(' ', '_').replace('&', '-')

  principals = await get_all_principals(args)

  for ug, member_principal_ids in generalInfo.disjoint_artificial_user_groups.items():
    if '(' in title_fn:
      title_fn = title_fn[:title_fn.index('(')]
    fn = mk_report_csv_path(args, report=title_fn, ug_name='UG%s' % ug)
    with open(fn, 'w') as out_f:
      fieldnames = ['id', 'upn', 'accountEnabled', 'roles']
      writer = csv.DictWriter(out_f, fieldnames=fieldnames, dialect=csv.excel)
      writer.writeheader()
      for member_id in member_principal_ids:
        principal = principals[member_id]
        writer.writerow({
          'id': principal.id,
          'upn': principal_to_string(principal),
          'accountEnabled': str(principal.accountEnabled),
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