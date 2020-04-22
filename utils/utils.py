import os
from utils.yaml import read_yaml_file


def export_mop_file(mop_name, list_of_commands):
    with open('{}.txt'.format(mop_name), 'w') as fout:
        for command in list_of_commands:
            fout.write(command)
            fout.write('\n')

    return os.path.abspath('{}.txt'.format(mop_name))


def check_spi_rule(filter_base_yaml):
    filter_base_dict = read_yaml_file(filter_base_yaml, 'FilterBase')

    for filter_base in filter_base_dict:
        spi_check_set = set()
        for filter_id in filter_base_dict.get(filter_base):
            filter_dict = filter_base_dict.get(filter_base).get(filter_id)
            if filter_dict.get('host-name') or filter_dict.get('l7-uri'):
                spi_check_set.add(False)
        if False not in spi_check_set:
            filter_base_dict.get(filter_base).update({'SPI': True})
        else:
            filter_base_dict.get(filter_base).update({'SPI': False})

    return filter_base_dict


def check_name_lenghts(cmg_policy_rule_yaml, prefix_list_yaml, dns_ip_cache_yaml, policy_rule_unit_yaml,
                       application_yaml):
    cmg_policy_rule_dict = read_yaml_file(cmg_policy_rule_yaml).get('CMGPolicyRule')
    prefix_list_dict = read_yaml_file(prefix_list_yaml).get('PrefixList')
    dns_ip_cache_dict = read_yaml_file(dns_ip_cache_yaml).get('DnsIpCache')
    policy_rule_unit_dict = read_yaml_file(policy_rule_unit_yaml).get('PolicyRuleUnit')
    application_dict = read_yaml_file(application_yaml).get('Application')

    prefix_max_length = 32
    policy_rule_max_length = 64
    policy_rule_unit_max_length = 32
    application_max_length = 32
    dns_ip_cache_max_length = 32

    for policy_rule_name in cmg_policy_rule_dict:
        if len(policy_rule_name) > policy_rule_max_length:
            print(
                'WARNING: The Policy-Rule: {} has a bigger name than {} chars, '
                'please review it and change it accordingly.'.format(policy_rule_name, policy_rule_max_length))

    for prefix_name in prefix_list_dict:
        if len(prefix_name) > prefix_max_length:
            print(
                'WARNING: The Prefix-List: {} has a bigger name than {} chars, '
                'please review it and change it accordingly.'.format(prefix_name, prefix_max_length))

    for dns_name in dns_ip_cache_dict:
        if len(dns_name) > prefix_max_length:
            print(
                'WARNING: The DNS-IP-Cache: {} has a bigger name than {} chars, '
                'please review it and change it accordingly.'.format(dns_name, dns_ip_cache_max_length))

    for pru_name in policy_rule_unit_dict:
        if len(pru_name) > prefix_max_length:
            print(
                'WARNING: The Policy-Rule-Unit: {} has a bigger name than {} chars, '
                'please review it and change it accordingly.'.format(pru_name, policy_rule_unit_max_length))

    for application in application_dict:
        if len(application) > prefix_max_length:
            print(
                'WARNING: The Application: {} has a bigger name than {} chars, '
                'please review it and change it accordingly.'.format(application, application_max_length))


def create_rule_filter_dict(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    policy_rule_filters = dict()
    for policy_rule in policy_rule_dict:
        if policy_rule_dict.get(policy_rule).get('Filters'):
            policy_rule_filters.update({policy_rule: policy_rule_dict.get(policy_rule).get('Filters')})
    return policy_rule_filters
