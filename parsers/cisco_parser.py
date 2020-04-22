import re
from utils.yaml import YAML
import os
from utils.header_fields_convertion import cisco_to_cmg_he_conversion


def remove_timestamp(file_input):
    fin = open(file_input)
    pattern = r'\[.*\]'

    with open(r'cisco_wo_timestamp.txt', 'w') as fout:
        for line in fin:
            match = re.match(pattern, line)
            if match:
                fout.write(line.replace(match.group(), '').strip())
                fout.write('\n')

    return os.path.abspath('cisco_wo_timestamp.txt')


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


# patterns
def export_yaml(data, project_name='RuleBase'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml_noalias({project_name: data})
    return path


def pr_diff_based_on_numbers(pr_name):
    digits_regex = r'-(\d+)--(\d+)|--(\d+)'
    pattern = re.compile(digits_regex)

    matches = re.search(pattern, pr_name)
    try:
        if matches.group(1) and matches.group(2):
            _sum = int(matches.group(1) + matches.group(2))
        else:
            _sum = int(matches.group(3))
        return _sum
    except:
        return pr_name

rule_base_name_pattern = r'rulebase (.+)'
precedence_pattern = r'action priority (\d+?)\s'
rule_name_pattern = r'ruledef (.+?)\s'
group_of_rule_pattern = r'group-of-ruledefs (.+?)\s'
charging_action_pattern = r'charging-action ([a-zA-Z0-9_-]+)'
monitoring_key_pattern = r'monitoring-key (\d+)'
he_template_name_pattern = r'xheader-format (.+)'
he_field_name_pattern = r'insert (.+?)\s'
he_field_pattern = r'variable (.+)'
he_field_pattern_const = r'string-constant (.+)'
content_id_pattern = r'content-id (\d+)'
service_id_pattern = r'service-identifier (\d+)'
flow_action_pattern = r'flow action (.+)'
rating_group_pattern = r'rating-group (\d+)'
port_pattern = r'either-port = (.+)'
server_domain_pattern = r'ip server-domain-name = (.+)'


# From Cisco Config File to AUX YAML Files
def get_rule_base(cisco_input):
    rule_base_dict = dict()
    with open(cisco_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('rulebase'):
                rule_base_name = re.findall(rule_base_name_pattern, line)[0]
                if not rule_base_dict.get(rule_base_name):
                    rule_base_dict.update(
                        {rule_base_name: dict()}
                    )
            if line.startswith('action priority'):
                match_ruledef = re.findall(rule_name_pattern, line)
                if match_ruledef:
                    policy_rule_name = match_ruledef[0]
                    precedence = re.findall(precedence_pattern, line)[0]
                    charging_action = re.findall(charging_action_pattern, line)[0]
                    match_mk = re.findall(monitoring_key_pattern, line)
                    monitoring_key = match_mk[0] if match_mk else None
                    rule_base_dict.get(rule_base_name).update(
                        {policy_rule_name: {'charging-action': charging_action,
                                            'monitoring-key': monitoring_key,
                                            'precedence': precedence}}
                    )

                else:
                    match_ruledef = re.findall(group_of_rule_pattern, line)
                    if match_ruledef:
                        policy_rule_name = match_ruledef[0]
                        precedence = re.findall(precedence_pattern, line)[0]
                        charging_action = re.findall(charging_action_pattern, line)[0]
                        match_mk = re.findall(monitoring_key_pattern, line)
                        monitoring_key = match_mk[0] if match_mk else None
                        rule_base_dict.get(rule_base_name).update(
                            {policy_rule_name: {'charging-action': charging_action,
                                                'monitoring-key': monitoring_key,
                                                'precedence': precedence,
                                                'group': True}}
                        )

    return export_yaml(rule_base_dict, project_name='PolicyRuleBaseCisco')


def create_fqdn_list_cmg(rule_def_dict):
    fqdn_dict = dict()
    for rule in rule_def_dict:
        domain_list = list()
        filters = rule_def_dict.get(rule).get('Filters')
        for key in filters:
            domain = filters.get(key).get('domain-name')
            if domain:
                if not domain.startswith('*'):
                    domain = '^' + domain
                if not domain.endswith('*'):
                    domain = domain + '$'
                domain_list.append(domain.replace('.', '\.'))

        if domain_list:
            fqdn_dict.update(
                {
                    rule: domain_list
                }
            )

    return export_yaml(fqdn_dict, 'FQDNList')


def get_he_templates(cisco_input):
    he_template_dict = dict()
    with open(cisco_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('xheader-format'):
                match_he_template_name = re.findall(he_template_name_pattern, line)
                he_template_name = match_he_template_name[0] if match_he_template_name else None
                if he_template_name:
                    if not he_template_dict.get(he_template_name):
                        he_template_dict.update({he_template_name: dict()})
            if line.startswith('insert'):
                match_field_name = re.findall(he_field_name_pattern, line)
                match_field = re.findall(he_field_pattern, line)
                match_field_const = re.findall(he_field_pattern_const, line)
                if match_field_name and (match_field or match_field_const):
                    he_template_dict.get(he_template_name).update(
                        {match_field_name[0]: match_field[0] if match_field else match_field_const[0]}
                    )
    return export_yaml(he_template_dict, project_name='HETemplateCisco')


def transform_he_to_cmg(cisco_input):
    he_dict = read_yaml_file(get_he_templates(cisco_input)).get('HETemplateCisco')
    for key in he_dict:
        for header_name in he_dict.get(key):
            field = he_dict.get(key).get(header_name)
            field = field.replace('delete-existing', '')
            if 'encrypt' in field:
                field = field.replace('encrypt', '')
                he_dict.get(key).update({
                    header_name: cisco_to_cmg_he_conversion.get(field.strip(), field.strip()) + ' encode'
                })
            else:
                he_dict.get(key).update({
                    header_name: cisco_to_cmg_he_conversion.get(field.strip(), field.strip())
                })

    return export_yaml(he_dict, project_name='HETemplateCiscoConverted')


def get_charging_action(cisco_input):
    charging_action_dict = dict()
    with open(cisco_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('charging-action'):
                match_ca = re.findall(charging_action_pattern, line)
                if match_ca:
                    charging_action_name = match_ca[0]
                    charging_action_dict.update({
                        charging_action_name: {'charging-method': 'offline'}
                    })
            if line.startswith('content-id'):
                match_cid = re.findall(content_id_pattern, line)
                if match_cid:
                    charging_action_dict.get(charging_action_name).update({
                        'content-id': match_cid[0]
                    })
            if line.startswith('service-identifier'):
                match_sid = re.findall(service_id_pattern, line)
                if match_sid:
                    charging_action_dict.get(charging_action_name).update({
                        'service-id': match_sid[0]
                    })
            if line.startswith('xheader-insert'):
                match_he = re.findall(he_template_name_pattern, line)
                if match_he:
                    charging_action_dict.get(charging_action_name).update({
                        'http-enrich': match_he[0]
                    })
            if line.startswith('flow action'):
                match_fa = re.findall(flow_action_pattern, line)
                if match_fa:
                    charging_action_dict.get(charging_action_name).update(
                        {
                            'flow-action': match_fa[0]
                        }
                    )
            if line.startswith('cca charging credit'):
                charging_action_dict.get(charging_action_name).update({
                    'charging-method': 'both'
                })

            if line.startswith('cca'):
                match_rg = re.findall(rating_group_pattern, line)
                if match_rg:
                    charging_action_dict.get(charging_action_name).update(
                        {
                            'rating-group': match_rg[0]
                        }
                    )

    return export_yaml(charging_action_dict, project_name='ChargingActionCisco')


def get_ruledef(cisco_input):
    rule_name_pattern = r'ruledef (.+)'
    ip_address_pattern = r'ip server-ip-address = (.+)'
    host_pool_pattern = r'ip server-ip-address range host-pool (.+)'
    ruledef_dict = dict()
    rule_name = None
    with open(cisco_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('ruledef'):
                filter_count = 0
                match_name = re.findall(rule_name_pattern, line)
                if match_name:
                    rule_name = match_name[0]
                    filter_dict = dict()
                    ruledef_dict.update({
                        rule_name:
                            {'Filters': filter_dict}
                    })
            if line.startswith('ip server-ip-address ='):
                ip_address = re.findall(ip_address_pattern, line)[0]
                if not len(filter_dict):
                    filter_count = 1
                    filter_dict.update({filter_count: {
                        'destination-address': ip_address
                    }})

                else:
                    if not (filter_dict.get(len(filter_dict)).get('host-pool') or filter_dict.get(len(filter_dict)).get(
                            'destination-address') or filter_dict.get(len(filter_dict)).get('domain-name')):
                        filter_dict.get(len(filter_dict)).update({
                            'destination-address': ip_address
                        })
                    else:
                        filter_count += 1
                        filter_dict.update({filter_count: {
                            'destination-address': ip_address
                        }})
            if line.startswith('ip server-ip-address range host-pool'):
                if rule_name:
                    ruledef_dict.get(rule_name).update({'host-pool': True})
                host_pool_name = re.findall(host_pool_pattern, line)[0]
                if not len(filter_dict):
                    filter_count = 1
                    filter_dict.update({filter_count: {'host-pool': host_pool_name}})
                else:
                    if not (filter_dict.get(len(filter_dict)).get('host-pool') or filter_dict.get(len(filter_dict)).get(
                            'destination-address') or filter_dict.get(len(filter_dict)).get('domain-name')):
                        filter_dict.get(len(filter_dict)).update({
                            'host-pool': host_pool_name
                        })
                    else:
                        filter_count += 1
                        filter_dict.update({filter_count: {
                            'host-pool': host_pool_name
                        }})
            if line.startswith('ip server-domain-name'):
                if re.findall(r'server-domain-name = (.+)', line):
                    domain_name = re.findall(r'server-domain-name = (.+)', line)[0]
                elif re.findall(r'server-domain-name ends-with (.+)', line):
                    domain_name = '*' + re.findall(r'server-domain-name ends-with (.+)', line)[0]
                elif re.findall(r'server-domain-name starts-with (.+)', line):
                    domain_name = re.findall(r'server-domain-name starts-with (.+)', line)[0] + '*'
                elif re.findall(r'server-domain-name contains (.+)', line):
                    domain_name = '*' + re.findall(r'server-domain-name contains (.+)', line)[0] + '*'
                else:
                    domain_name = 'CHECK ME!!!'

                if not len(filter_dict):
                    filter_count = 1
                    filter_dict.update({filter_count: {'domain-name': domain_name}})
                else:
                    if not (filter_dict.get(len(filter_dict)).get('host-pool') or filter_dict.get(len(filter_dict)).get(
                            'destination-address') or filter_dict.get(len(filter_dict)).get('domain-name')):
                        filter_dict.get(len(filter_dict)).update({
                            'domain-name': domain_name
                        })
                    else:
                        filter_count += 1
                        filter_dict.update({filter_count: {
                            'domain-name': domain_name
                        }})
            if line.startswith('tcp either-port ='):
                port = re.findall(port_pattern, line)[0]
                if ruledef_dict.get(rule_name).get('destination-port-list'):
                    port = '{},{}'.format(ruledef_dict.get(rule_name).get('destination-port-list'), port)
                    ruledef_dict.get(rule_name).update({'destination-port-list': port})
                else:
                    ruledef_dict.get(rule_name).update({'destination-port-list': port})
                if ruledef_dict.get(rule_name).get('protocol-id') == '17':
                    ruledef_dict.get(rule_name).update({'protocol-id': '6, 17'})
                else:
                    ruledef_dict.get(rule_name).update({'protocol-id': '6'})
            if line.startswith('udp either-port ='):
                port = re.findall(port_pattern, line)[0]
                if ruledef_dict.get(rule_name).get('destination-port-list'):
                    port = '{},{}'.format(ruledef_dict.get(rule_name).get('destination-port-list'), port)
                    ruledef_dict.get(rule_name).update({'destination-port-list': port})
                else:
                    ruledef_dict.get(rule_name).update({'destination-port-list': port})
                if ruledef_dict.get(rule_name).get('protocol-id') == '6':
                    ruledef_dict.get(rule_name).update({'protocol-id': '6, 17'})
                else:
                    ruledef_dict.get(rule_name).update({'protocol-id': '17'})
            if line.startswith('http host'):
                if re.findall(r'http host = (.+)', line):
                    host_name = re.findall(r'http host = (.+)', line)[0]
                elif re.findall(r'http host ends-with (.+)', line):
                    host_name = '*' + re.findall(r'http host ends-with (.+)', line)[0]
                elif re.findall(r'http host starts-with (.+)', line):
                    host_name = re.findall(r'http host starts-with (.+)', line)[0] + '*'
                elif re.findall(r'http host contains (.+)', line):
                    host_name = '*' + re.findall(r'http host contains (.+)', line)[0] + '*'
                else:
                    host_name = 'CHECK ME!!!'

                if not len(filter_dict):
                    filter_count = 1
                    filter_dict.update({filter_count: {'host-name': host_name}})
                else:
                    if not filter_dict.get(len(filter_dict)).get('host-name'):
                        filter_dict.get(len(filter_dict)).update({
                            'host-name': host_name
                        })
                    else:
                        filter_count += 1
                        filter_dict.update({filter_count: {
                            'host-name': host_name
                        }})

            if line.startswith('#exit'):
                if rule_name:
                    ruledef_dict.get(rule_name).update(
                        {'Filters': filter_dict}
                    )

                    if ruledef_dict.get(rule_name).get('host-pool') or not ruledef_dict.get(rule_name).get(
                            'multi-line'):
                        if ruledef_dict.get(rule_name).get('Filters'):
                            for key in ruledef_dict.get(rule_name).get('Filters'):
                                ruledef_dict.get(rule_name).get('Filters').get(key).update({
                                    'destination-port-list': ruledef_dict.get(rule_name).get('destination-port-list')
                                })
                                ruledef_dict.get(rule_name).get('Filters').get(key).update({
                                    'protocol-id': ruledef_dict.get(rule_name).get('protocol-id')
                                })
                            ruledef_dict.get(rule_name).pop('destination-port-list', None)
                            ruledef_dict.get(rule_name).pop('protocol-id', None)
                        else:
                            ruledef_dict.get(rule_name).get('Filters').update({1: {
                                'destination-port-list': ruledef_dict.get(rule_name).get('destination-port-list'),
                                'protocol-id': ruledef_dict.get(rule_name).get('protocol-id')
                            }})
                            ruledef_dict.get(rule_name).pop('destination-port-list', None)
                            ruledef_dict.get(rule_name).pop('protocol-id', None)

                rule_name = None

        return export_yaml(ruledef_dict, project_name='RuleDef')


def get_group_of_ruledef(cisco_input):
    group_of_rule_pattern = r'group-of-ruledefs (.+)'
    rule_name_pattern = r'\d+ ruledef (.+)'
    group_of_ruledef_dict = dict()
    with open(cisco_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('group-of-ruledefs'):
                match_name = re.findall(group_of_rule_pattern, line)
                if match_name:
                    group_name = match_name[0]
                    if not group_of_ruledef_dict.get(group_name):
                        group_of_ruledef_dict.update(
                            {group_name: list()}
                        )
            if line.startswith('add-ruledef'):
                match_ruledef = re.findall(rule_name_pattern, line)
                if match_ruledef:
                    ruledef_name = match_ruledef[0]
                    group_of_ruledef_dict.get(group_name).append(ruledef_name)

    return export_yaml(group_of_ruledef_dict, project_name='GroupRuleDefCisco')


def get_ip_host_pool(cisco_input):
    host_pool_pattern = 'host-pool (.+)'
    ip_address_host_pool_pattern = 'ip (.+)'
    host_pool_dict = dict()
    host_pool_name = None
    with open(cisco_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('host-pool'):
                host_pool_name = re.findall(host_pool_pattern, line)[0]
                host_pool_dict.update({host_pool_name: list()})
            if line.startswith('ip'):
                ip_address = re.findall(ip_address_host_pool_pattern, line)[0]
                if host_pool_name:
                    host_pool_dict.get(host_pool_name).append(ip_address)
            if line.startswith('#exit'):
                host_pool_name = None
    return export_yaml(host_pool_dict, project_name='HostPool')


# Create Base YAML files
def filter_base_yaml(cisco_input, rule_def_yaml=None, host_pool_yaml=None):
    if not (rule_def_yaml and host_pool_yaml):
        ruledef = read_yaml_file(get_ruledef(cisco_input)).get('RuleDef')
        host_pool = read_yaml_file(get_ip_host_pool(cisco_input)).get('HostPool')
    else:
        ruledef = read_yaml_file(rule_def_yaml).get('RuleDef')
        host_pool = read_yaml_file(host_pool_yaml).get('HostPool')
    create_fqdn_list_cmg(ruledef)
    filter_base_dict = dict()
    for ruledef_name in ruledef:
        filter_dict = dict()
        if not filter_dict:
            filter_count = 1
            for key in ruledef.get(ruledef_name).get('Filters'):
                if ruledef.get(ruledef_name).get('Filters').get(key).get('host-pool'):
                    ip_prefix_list = host_pool.get(ruledef.get(ruledef_name).get('Filters').get(key).get('host-pool'))
                    for ip in ip_prefix_list:
                        filter_dict.update(
                            {
                                filter_count: {
                                    'destination-address': ip,
                                    'destination-port-list': ruledef.get(ruledef_name).get('Filters').get(key).get(
                                        'destination-port-list'),
                                    'protocol-id': ruledef.get(ruledef_name).get('Filters').get(key).get('protocol-id'),
                                    'host-name': ruledef.get(ruledef_name).get('Filters').get(key).get('host-name'),
                                    'host-pool': ruledef.get(ruledef_name).get('Filters').get(key).get('host-pool')

                                }
                            }
                        )
                        filter_count += 1

                else:
                    filter_dict.update(
                        {
                            filter_count: ruledef.get(ruledef_name).get('Filters').get(key)
                        }
                    )
                    filter_count += 1
        else:
            filter_count = int(sorted(list(filter_dict.keys()))[-1]) + 1
            for key in ruledef.get(ruledef_name).get('Filters'):
                if ruledef.get(ruledef_name).get('Filters').get(key).get('host-pool'):
                    ip_prefix_list = host_pool.get(ruledef.get(ruledef_name).get('Filters').get(key).get('host-pool'))
                    for ip in ip_prefix_list:
                        filter_dict.update(
                            {
                                filter_count: {
                                    'destination-address': ip,
                                    'destination-port-list': ruledef.get(ruledef_name).get('Filters').get(key).get(
                                        'destination-port-list'),
                                    'protocol-id': ruledef.get(ruledef_name).get('Filters').get(key).get('protocol-id'),
                                    'host-name': ruledef.get(ruledef_name).get('Filters').get(key).get('host-name'),
                                    'host-pool': ruledef.get(ruledef_name).get('Filters').get(key).get('host-pool')

                                }
                            }
                        )
                        filter_count += 1
                else:
                    filter_dict.update(
                        {
                            filter_count: ruledef.get(ruledef_name).get('Filters').get(key)
                        }
                    )
                    filter_count += 1

        filter_base_dict.update({ruledef_name: filter_dict})

    return export_yaml(filter_base_dict, project_name='FilterBase')


def create_policy_rule_base_dict(cisco_input):
    group_of_rule_def = read_yaml_file(get_group_of_ruledef(cisco_input)).get('GroupRuleDefCisco')
    rule_base = read_yaml_file(get_rule_base(cisco_input)).get('PolicyRuleBaseCisco')

    policy_rule_base_dict = dict()
    for rule_base_name in rule_base:
        policy_rule_base_dict.update({rule_base_name: list()})
        for rule_name in rule_base.get(rule_base_name):
            group = group_of_rule_def.get(rule_name)
            policy_rule_list = group if group else [rule_name]
            a = map(
                lambda x: '{}___{}___{}'.format(x, rule_base.get(rule_base_name).get(rule_name).get('charging-action'),
                                                rule_base.get(rule_base_name).get(rule_name).get('monitoring-key')),
                policy_rule_list)
            policy_rule_base_dict.get(rule_base_name).extend(list(a))
    return policy_rule_base_dict


def create_policy_rule_dict(policy_rule_base_dict):
    """
    Aux function to determine unique names to Policy Rules coming from Cisco ASR
    """
    aux_dict_pr = dict()
    aux_list_pr = list()
    for rule_base_name in policy_rule_base_dict:
        pr_list = policy_rule_base_dict.get(rule_base_name)
        for pr_name in pr_list:
            if not aux_dict_pr.get(pr_name):
                pr = re.findall(r'(^[a-zA-Z0-9-_]+?)___', pr_name)[0]
                aux_list_pr.append(pr)
                aux_dict_pr.update({pr_name: '{}--{}'.format(pr, aux_list_pr.count(pr))})
    return export_yaml(aux_dict_pr, project_name='PolicyRuleDict')


def policy_rule_base_yaml(policy_rule_base_dict, aux_dict_pr):
    for rule_base_name in policy_rule_base_dict:
        policy_rule_base_dict.update({
            rule_base_name: list(map(lambda x: aux_dict_pr.get(x), policy_rule_base_dict.get(rule_base_name)))
        })
    return export_yaml(policy_rule_base_dict, project_name='PolicyRuleBase')


def he_dict_to_list(he_dict):
    """
    Aux function to convert HE Dict to String with Key = Template Name
    :param he_dict:
    :return: dict
    """
    he_list_dict = dict()
    for he_template in he_dict:
        aux_list = list()
        for key in he_dict.get(he_template):
            aux_list.append(he_dict.get(he_template).get(key))
        he_list_dict.update(
            {he_template: ','.join(aux_list)}
        )

    return he_list_dict


def policy_rule_yaml(cisco_input):
    policy_rule_base_dict = create_policy_rule_base_dict(cisco_input)
    aux_dict_pr = read_yaml_file(create_policy_rule_dict(policy_rule_base_dict)).get('PolicyRuleDict')
    prb_yaml = policy_rule_base_yaml(policy_rule_base_dict, aux_dict_pr)
    charging_action_dict = read_yaml_file(get_charging_action(cisco_input)).get('ChargingActionCisco')
    he_dict = he_dict_to_list(read_yaml_file(transform_he_to_cmg(cisco_input)).get('HETemplateCiscoConverted'))

    pattern = re.compile(r'(^[a-zA-Z0-9-_]+?)___([a-zA-Z0-9-_]+?)___(.+)')
    redirect_url_pattern = re.compile(r'redirect-url (.+)')
    policy_rule_dict = dict()
    precedence = 10
    aux_dict_pr = {k: v for k, v in sorted(aux_dict_pr.items(),
                                           key=lambda item: (item[1], pr_diff_based_on_numbers(item[1])
                                                             )
                                           )}

    for pr_name in aux_dict_pr:
        re_extract = re.match(pattern, pr_name)
        filter_base = re_extract.group(1)
        charging_action = re_extract.group(2)
        monitoring_key = re_extract.group(3)

        flow_action = charging_action_dict.get(charging_action).get('flow-action')
        if flow_action:
            match = re.match(redirect_url_pattern, flow_action)
        else:
            match = None
        if match:
            redirect_uri = match.group(1)
            action = 'redirect'
        else:
            redirect_uri = None
            action = {'terminate-flow': 'drop'}.get(flow_action, 'charge-v')

        policy_rule_dict.update(
            {aux_dict_pr.get(pr_name): {
                'Filters': None,
                'header-enrichment-type': he_dict.get(charging_action_dict.get(charging_action).get('http-enrich')),
                'monitoring-key': monitoring_key if monitoring_key != 'None' else None,
                'pcc-filter-base-name': filter_base,
                'pcc-rule-action': action,
                'precedence': precedence,
                'qos-profile-name': None,
                'rating-group': charging_action_dict.get(charging_action).get('content-id'),
                'redirect-uri': redirect_uri,
                'service-id': charging_action_dict.get(charging_action).get('service-id'),
                'charging-method': charging_action_dict.get(charging_action).get('charging-method')
            }}
        )

        precedence += 10

    pr_yaml = export_yaml(policy_rule_dict, project_name='PolicyRule')

    return {'PolicyRuleBase': prb_yaml, 'PolicyRule': pr_yaml}


def main():
    cisco_input = r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\input_cisco\ECS-TOR-ASR5K5-1-2908 .log'
    filter_base_yaml(cisco_input)
    policy_rule_yaml(cisco_input)


if __name__ == "__main__":
    main()
