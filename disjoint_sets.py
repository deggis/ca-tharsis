from collections import namedtuple
from collections import Counter

# Type for giving in the task
GroupMembers = namedtuple('GroupMembers', ['name', 'members'])


class _Group(object):
  def __init__(self, name, unreferencedMembers, artificialGroups):
    self.name = name
    self.unreferencedMembers = unreferencedMembers
    self.artificialGroups = artificialGroups

  def __str__(self):
    return f'G: {self.name} {self.unreferencedMembers} {self.artificialGroups}'

def split_to_disjoint_sets(groups: [GroupMembers]):
  artificial_groups = {}
  artificial_groups_counter = 0

  task_groups = [_Group(g.name, set(g.members), []) for g in groups]

  referenced_users = set().union(*[tg.unreferencedMembers for tg in task_groups])
  # not_referenced_users = all_members - referenced_users

  def pick_any_unreferenced_members():
    currently_unreferenced_members = list(set().union(*[tg.unreferencedMembers for tg in task_groups]))
    if not currently_unreferenced_members:
      return None
    return currently_unreferenced_members[0]

  def find_unref_members_that_have_same_groups(user_id):
    ref_member_memberships = [user_id in tg.unreferencedMembers for tg in task_groups]
    currently_unreferenced_members = list(set().union(*[tg.unreferencedMembers for tg in task_groups]))
    peer_ids = set([user_id])  # Redundant
    for peer_user_id in currently_unreferenced_members:
      peer_memberships = [peer_user_id in tg.unreferencedMembers for tg in task_groups]
      if peer_memberships == ref_member_memberships:
        peer_ids.add(peer_user_id)
    return peer_ids

  while True:
    unref_member_id = pick_any_unreferenced_members()
    if not unref_member_id:
      break

    new_group_member_ids = find_unref_members_that_have_same_groups(unref_member_id)
    new_group_id = artificial_groups_counter
    artificial_groups[new_group_id] = set(new_group_member_ids)
    artificial_groups_counter += 1
    for tg in task_groups:
      if new_group_member_ids & tg.unreferencedMembers == new_group_member_ids:
        tg.artificialGroups.append(new_group_id)
        tg.unreferencedMembers = tg.unreferencedMembers - new_group_member_ids

  plain_groups = {g.name: g.artificialGroups for g in task_groups}
  return (plain_groups, artificial_groups)

def main():
  # all_users = set(range(1,23))
  pol1_users = set(range(1,21))
  pol2_users = set(range(1,7))
  pol3_users = set(range(1,17))
  pol4_users = set([4,10,11])
  pol5_users = set([6])

  groups = [
    GroupMembers('pol1', pol1_users),
    GroupMembers('pol2', pol2_users),
    GroupMembers('pol3', pol3_users),
    GroupMembers('pol4', pol4_users),
    GroupMembers('pol5', pol5_users)
  ]

  task_groups, artificial_groups = split_to_disjoint_sets(groups)

if __name__ == '__main__':
  main()