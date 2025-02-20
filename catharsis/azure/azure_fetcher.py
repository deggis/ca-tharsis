


import json
import os
import itertools
import csv
from typing import List
from catharsis.azure.azure_graph_queries import ALL_QUERIES, MANAGEMENT_GROUPS_FILE, get_az_result_path, SUBSCRIPTIONS_FILE
from catharsis.azure.typedefs import AzureMG, AzureSub
from catharsis.disjoint_sets import GroupMembers, split_to_disjoint_sets_ordered
from catharsis.typedefs import Principal, RunConf
from catharsis.utils import fetch_az_graph_query, get_members_azcli, get_principals, run_cmd, group_members
from catharsis.utils_graphapi import fetch_group_members
from catharsis.settings import mk_group_result_path

mk_azure_sub_assignment_path = lambda args, sub_id: os.path.join(args.work_dir, f'azure_sub_assignments_{sub_id}.json')
# Note: Tenant Root Group will have a GUID as name
# Note: Names not put to lower case. Let's see if this bites back.
mk_azure_mg_assignment_path = lambda args, mg_name: os.path.join(args.work_dir, f'azure_mg_assignments_{mg_name}.json')

# Note: custom roles skipped for now
PRIVILEGED_AZURE_ROLES = [
    "Owner",
    "Contributor",
    "Access Review Operator Service Role",
    "Role Based Access Control Administrator",
    "User Access Administrator"
]

def get_graph_result_file(args: RunConf, fn: str):
    with open(get_az_result_path(args, fn)) as in_f:
        return json.load(in_f)

def fetch_scope_assignments(args: RunConf, resource_id: str, full_path: str):
    if not args.force_update and os.path.exists(full_path):
        return
    cmd = 'az role assignment list --scope "%s" > %s' % (resource_id, full_path)
    run_cmd(cmd)

def get_scope_assignment_referenced_groups(args: RunConf, full_path: str) -> List[str]:
    group_ids = []
    with open(full_path) as in_f:
        scope_assignments = json.load(in_f)
        for assignment in scope_assignments:
            if assignment['principalType'] == 'Group':
                group_ids.append(assignment['principalId'])
    return group_ids

def get_sub_assignment_referenced_groups(args: RunConf, sub: AzureSub) -> List[str]:
    full_path = mk_azure_sub_assignment_path(args, sub.guid)
    return get_scope_assignment_referenced_groups(args, full_path)

def get_mg_assignment_referenced_groups(args: RunConf, mg: AzureMG) -> List[str]:
    full_path = mk_azure_mg_assignment_path(args, mg.name)
    return get_scope_assignment_referenced_groups(args, full_path)

def get_subs(args: RunConf) -> dict[str, AzureSub]:
    sub_guid = lambda sub: sub['id'].split('/')[-1]
    return {sub_guid(sub): AzureSub(id=sub['id'], guid=sub_guid(sub), name=sub['name'], raw=sub) for sub in get_graph_result_file(args, SUBSCRIPTIONS_FILE)['data']}

def get_mgs(args: RunConf) -> dict[str, AzureMG]:
    return {mg['id']: AzureMG(id=mg['id'], name=mg['name'], raw=mg) for mg in get_graph_result_file(args, MANAGEMENT_GROUPS_FILE)['data']}

def get_privileged_principals_by_role(args: RunConf, assignment_path: str) -> dict:
    by_role: dict[str, set[str]] = {}
    with open(assignment_path) as in_f:
        scope_assignments = json.load(in_f)
        for assignment in scope_assignments:
            role_name = assignment['roleDefinitionName']
            if role_name in PRIVILEGED_AZURE_ROLES:
                role_holders = by_role.setdefault(role_name, set())
                if assignment['principalType'] == 'ServicePrincipal':
                    role_holders.add(assignment['principalId'])
                elif assignment['principalType'] == 'User':
                    role_holders.add(assignment['principalId'])
                elif assignment['principalType'] == 'Group':
                    for member in group_members(args, assignment['principalId']):
                        role_holders.add(member.id)

    return by_role

def fetch_container_roles(args: RunConf) -> tuple[dict, dict]:
    mg_privileged_roles_by_containers = {}
    for mg in get_mgs(args).values():
        full_path = mk_azure_mg_assignment_path(args, mg.name)
        fetch_scope_assignments(args, mg.id, full_path)
        # Resolve groups
        for group_id in get_mg_assignment_referenced_groups(args, mg):
            fetch_group_members(args, group_id)
        by_role = get_privileged_principals_by_role(args, full_path)
        mg_privileged_roles_by_containers[mg.name] = by_role

    sub_privileged_roles_by_containers = {}
    for sub in get_subs(args).values():
        full_path = mk_azure_sub_assignment_path(args, sub.guid)
        fetch_scope_assignments(args, sub.id, full_path)
        # Resolve groups
        for group_id in get_sub_assignment_referenced_groups(args, sub):
            fetch_group_members(args, group_id)
        
        by_role = get_privileged_principals_by_role(args, full_path)
        sub_privileged_roles_by_containers[sub.guid] = by_role
        # Add ancestor chain with MGs
    
    all_privileged_ids = set()
    for mg_name, mg_roles in mg_privileged_roles_by_containers.items():
        for role, holders in mg_roles.items():
            all_privileged_ids.update(holders)

    for sub_guid, sub_roles in sub_privileged_roles_by_containers.items():
        for role, holders in sub_roles.items():
            all_privileged_ids.update(holders)
    
    fn = os.path.join(args.work_dir, 'all_interesting_azure_role_ids.json')
    with open(fn, 'w') as out_f:
        json.dump(list(all_privileged_ids), out_f)
    
    fn = os.path.join(args.work_dir, 'all_interesting_azure_role')
    with open(fn, 'w') as out_f:
        json.dump(list(all_privileged_ids), out_f)
    

    return mg_privileged_roles_by_containers, sub_privileged_roles_by_containers    

def resolve_roles(args: RunConf, all_mg_roles: dict, all_sub_roles: dict):
    principals = get_principals(args)

    sub_to_principals_to_roles_to_paths: dict = {}
    sub_to_roles_to_principals: dict = {}
    principals_to_subs_to_roles: dict = {}
    subs = get_subs(args)
    for sub in subs.values():
        sub_roles = all_sub_roles[sub.guid]
        this_sub_principals_to_roles_to_paths = sub_to_principals_to_roles_to_paths[sub.guid] = {}
        this_sub_roles_to_principals = sub_to_roles_to_principals[sub.guid] = {}

        for role, holders in sub_roles.items():
            for holder in holders:
                this_sub_principals_to_roles_to_paths.setdefault(holder, {}).setdefault(role, set()).add('Sub assignment')
                this_sub_roles_to_principals.setdefault(role, set()).add(holder)
                principals_to_subs_to_roles.setdefault(holder, {}).setdefault(sub.guid, set()).add(role)

        for parent_mg in [mg['name'] for mg in sub.raw['properties']['managementGroupAncestorsChain']]:
            mg_roles = all_mg_roles[parent_mg]
            for role, holders in mg_roles.items():
                for holder in holders:
                    this_sub_principals_to_roles_to_paths.setdefault(holder, {}).setdefault(role, set()).add(parent_mg)
                    this_sub_roles_to_principals.setdefault(role, set()).add(holder)
                    principals_to_subs_to_roles.setdefault(holder, {}).setdefault(sub.guid, set()).add(role)

        # print('Subscription: %s' % sub.name)
        for role, holders in this_sub_roles_to_principals.items():
            #print('  Role: %s' % role)
            for holder in holders:
                principal = principals.get(holder)
                if not principal:
                    # Possibly removed?
                    continue
                paths = ', '.join(list(this_sub_principals_to_roles_to_paths[holder][role]))
                #print('    %s (%s)' % (str(principal), paths))

    return principals, principals_to_subs_to_roles, sub_to_roles_to_principals, sub_to_principals_to_roles_to_paths

def do_all_kinds_of_things(args: RunConf, all_mg_roles: dict, all_sub_roles: dict):
    principals, principals_to_subs_to_roles, sub_to_roles_to_principals, sub_to_principals_to_roles_to_paths = resolve_roles(args, all_mg_roles, all_sub_roles)

    def most_common_principals():
        i = 0
        for principal, sub_data in sorted(principals_to_subs_to_roles.items(), key=lambda p: len(p[1]), reverse=True):
            i += 1
            if i > 50:
                break
            try:
                print('%s: (%d subs)' % (str(principals[principal]), len(sub_data)))
            except KeyError:
                print('Principal removed? %s' % principal)
                continue
            for sub_id, sub_roles in itertools.islice(sub_data.items(), 3):
                sub = subs[sub_id]
                print(' * %s (%s)' % (sub.name, ', '.join(sub_roles)))
    
    def disjoint_sets_by_subs():
        """
    users_task = [GroupMembers(name=policy_id, members=members)
        for policy_id, members in policy_user_memberships.items()]
    policy_user_groups, dja_user_groups = split_to_disjoint_sets_ordered(users_task)
        """
        subs_task = [GroupMembers(name=sub_data_p[0], members=sub_data_p[1].keys()) for sub_data_p in sub_to_principals_to_roles_to_paths.items()]
        aa, bee = split_to_disjoint_sets_ordered(subs_task)

    fn = os.path.join(args.work_dir, 'azure_privileges.csv')
    with open(fn, 'w') as out_f:
        sorted_principals: List[str] = [p[0] for p in sorted(principals_to_subs_to_roles.items(), key=lambda p: len(p[1]), reverse=True) if p[0] in principals]
        fieldnames = ['Sub name', 'Sub id', 'MG parent']
        def principal_name(p: Principal):
            return f'{p.displayName} ({p.id})'

        for p_id in sorted_principals:
            fieldnames.append(principal_name(principals[p_id]))
        writer = csv.DictWriter(out_f, fieldnames)
        writer.writeheader()

        row = {'Sub name': '(Sub count per admin identity)'}
        for p_id in sorted_principals:
            row[principal_name(principals[p_id])] = '%d' % len(principals_to_subs_to_roles[p_id].keys())
        writer.writerow(row)

        for sub in sorted(subs.values(), key=lambda s: s.name):
            row = {
                'Sub name': sub.name,
                'Sub id': sub.id.split('/')[-1],
                'MG parent': sub.raw['properties']['managementGroupAncestorsChain'][0]['name']
            }
            if row['MG parent'] == args.root_group_guid:
                row['MG parent'] = 'Tenant Root Group'
            for p_id in sorted_principals:
                row[principal_name(principals[p_id])] = 'X' if p_id in sub_to_principals_to_roles_to_paths[sub.guid] else ''
            writer.writerow(row)


def fetch_azure_queries(args: RunConf):
    for fn_part, query in ALL_QUERIES:
        full_path = os.path.join(args.work_dir, fn_part)
        if not args.force_update and os.path.exists(full_path):
            continue
        print('Fetching %s' % fn_part)
        r = fetch_az_graph_query(query, mgmt_group_guid=args.root_group_guid)
        with open(full_path, 'w') as out_f:
            json.dump(r, out_f)
    
    mg_roles, sub_roles = fetch_container_roles(args)
    # do_all_kinds_of_things(args, mg_roles, sub_roles)

    principals, principals_to_subs_to_roles, sub_to_roles_to_principals, sub_to_principals_to_roles_to_paths = resolve_roles(args, mg_roles, sub_roles)

def get_privileged_azure_principals(args: RunConf):
    fetch_azure_queries(args)
    mg_roles, sub_roles = fetch_container_roles(args)
    principals, principals_to_subs_to_roles, sub_to_roles_to_principals, sub_to_principals_to_roles_to_paths = resolve_roles(args, mg_roles, sub_roles)
    return principals_to_subs_to_roles
