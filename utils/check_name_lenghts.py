from utils.yaml import YAML


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


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
