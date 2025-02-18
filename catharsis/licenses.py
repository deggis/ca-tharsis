import json
from os import path as os_path
from catharsis.utils import get_members, run_cmd


def get_licenses(args):
  """
  No bulk download option in API for all users at once?
  This is slow.
  """

  users_licenses_path = mk_users_licenses(args)
  users_licenses_path_temp = users_licenses_path+'_temp'

  users_licenses = {}
  if os_path.exists(users_licenses_path):
    with open(users_licenses_path) as in_f:
      users_licenses = json.load(in_f)

  def save():
    with open(users_licenses_path, 'w') as out_f:
      json.dump(users_licenses, out_f)

  all_users = get_members(mk_all_users_path(args))
  fetched = 0
  c_users = len(all_users)
  for i, user_id in enumerate(all_users):
    if i % 50 == 0:
      print('Licenses checked for users: %d/%d' % (i, c_users))
    if user_id in users_licenses:
      continue
    url = f'https://graph.microsoft.com/v1.0/users/{user_id}/licenseDetails'
    reply = run_cmd(f"az rest --uri \"{url}\"", parse=True)
    users_licenses[user_id] = reply['value']
    fetched += 1

    if fetched % 10 == 0:
      print('Licenses fetched: %d' % fetched)
      save()
  
  save()
  return users_licenses