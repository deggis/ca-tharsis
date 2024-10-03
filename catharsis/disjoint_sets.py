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

def split_to_disjoint_sets_ordered(groups: [GroupMembers]):
  def ag_key(user_ids):
    first_id = sorted(user_ids)[0]
    # ids guaranteed to differ: group members don't belong to multiple groups
    return -len(user_ids), first_id

  unsorted_task_groups, unsorted_artificial_groups = split_to_disjoint_sets(groups)

  sorted_group_ids = sorted(unsorted_artificial_groups.keys(), key=lambda x: ag_key(unsorted_artificial_groups[x]))

  translation = {}
  for i in range(0, len(sorted_group_ids)):
    translation[sorted_group_ids[i]] = i

  sorted_task_groups, sorted_artificial_groups = {}, {}

  for from_id, to_id in translation.items():
    sorted_artificial_groups[to_id] = unsorted_artificial_groups[from_id]

  for pol_name, group_ids in unsorted_task_groups.items():
    sorted_task_groups[pol_name] = sorted([translation[gid] for gid in group_ids])

  return (sorted_task_groups, sorted_artificial_groups)