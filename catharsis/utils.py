from functools import cache
import json
import math
import subprocess

from catharsis.common_apps import common_apps

from catharsis.settings import mk_all_users_path


def count_s(a, b):
  frac = math.floor(a / b * 100)
  return '%d of %d / %s %%' % (a,b,frac)


def run_cmd(cmd_string, parse=False):
  print(f'run_cmd {cmd_string}')
  r = subprocess.run(cmd_string, shell=True, capture_output=True)
  if r.returncode != 0:
    err = r.stderr.decode('utf-8')
    print('run_cmd (%s), got error: %s' % (cmd_string, err))
    raise Exception(err)
  if parse:
    return json.loads(r.stdout.decode('utf-8'))
  else:
    return r.stdout



def get_members(path, req_user_active=False, req_user_guest=False, req_user_internal=False):
  def user_filter(u):
    if req_user_active and not u['accountEnabled']:
      return False
    if req_user_internal and '#EXT#@' in u['userPrincipalName']:
      return False
    if req_user_guest and '#EXT#@' not in u['userPrincipalName']:
      return False
    return True

  with open(path) as in_f:
    user_data = json.load(in_f)

    if 'role_' in path:
      return set([v['principalId'] for v in user_data['value']])
    else:
      return set([v['id'] for v in user_data['value'] if user_filter(v)])


@cache
def _get_all_members(users_path):
  with open(users_path) as in_f:
    data = json.load(in_f)
  result = {}
  for item in data['value']:
    result[item['id']] = item
  return result

def get_all_members(args):
  return _get_all_members(mk_all_users_path(args))
