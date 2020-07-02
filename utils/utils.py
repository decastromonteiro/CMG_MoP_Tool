import os
from utils.yaml import read_yaml_file
from utils.yaml import export_yaml
import traceback

flow_gate_status_dict = {'charge-v': 'allow', 'pass': 'allow', 'drop': 'drop', 'deny': 'drop', 'redirect': 'allow'}


def export_mop_file(mop_name, list_of_commands):
    with open('{}.txt'.format(mop_name), 'w') as fout:
        for command in list_of_commands:
            fout.write(command)
            fout.write('\n')

    return os.path.abspath('{}.txt'.format(mop_name))


def check_spi_rule(filter_base_yaml, policy_rule_yaml, domain_name=False, ip_address=False):
    filter_base_dict = read_yaml_file(filter_base_yaml, 'FilterBase')
    pr_dict = read_yaml_file(policy_rule_yaml, 'PolicyRule')

    for pr in pr_dict.keys():
        pr_parameters = pr_dict.get(pr)
        he = pr_parameters.get('header-enrichment-type')
        redirect = pr_parameters.get('redirect-uri')
        filter_base = pr_parameters.get('pcc-filter-base-name')
        if filter_base_dict.get(filter_base):
            try:
                if ((he == 'null') or (he == 'cisco: None') or (not he)) and not redirect:
                    spi_check_set = set()
                    # Same Filter Base might be used several times, therefore SPI may already be present
                    # (if its false, it will forever be false)
                    # (if its true, and it made the #1 criteria, it will continue true)
                    if isinstance(filter_base_dict.get(filter_base).get('SPI'), bool):
                        continue
                    else:
                        for filter_id in filter_base_dict.get(filter_base):
                            filter_dict = filter_base_dict.get(filter_base).get(filter_id)
                            if domain_name and ip_address:
                                if filter_dict.get('host-name') or filter_dict.get('l7-uri') or filter_dict.get(
                                        'signature'):
                                    spi_check_set.add(False)
                            elif domain_name:
                                if filter_dict.get('host-name') or filter_dict.get('l7-uri') or filter_dict.get(
                                        'signature') \
                                        or filter_dict.get('destination-address'):
                                    spi_check_set.add(False)
                            elif ip_address:
                                if filter_dict.get('host-name') or filter_dict.get('l7-uri') or filter_dict.get(
                                        'signature') \
                                        or filter_dict.get('domain-name'):
                                    spi_check_set.add(False)
                            else:
                                spi_check_set.add(False)
                        if False not in spi_check_set:
                            filter_base_dict[filter_base]['SPI'] = True
                        else:
                            filter_base_dict[filter_base]['SPI'] = False

                else:
                    filter_base_dict[filter_base]['SPI'] = False

            except:
                print(f" FilterBase -- {filter_base} -- referecend by PR {pr}  does not exist in FilterBase.yaml.")
                traceback.print_exc()

    for filter_base in list(filter_base_dict):
        if not isinstance(filter_base_dict.get(filter_base).get('SPI'), bool):
            filter_base_dict.pop(filter_base)

    return export_yaml(filter_base_dict, 'FilterBase')


def check_spi_filter(filter_base_yaml, policy_rule_yaml, domain_name=False, ip_address=False):
    filter_base_dict = read_yaml_file(filter_base_yaml, 'FilterBase')
    pr_dict = read_yaml_file(policy_rule_yaml, 'PolicyRule')

    for pr in pr_dict.keys():
        pr_parameters = pr_dict.get(pr)
        he = pr_parameters.get('header-enrichment-type')
        redirect = pr_parameters.get('redirect-uri')
        filter_base = pr_parameters.get('pcc-filter-base-name')
        if filter_base_dict.get(filter_base):
            try:
                if ((he == 'null') or (he == 'cisco: None') or (not he)) and not redirect:
                    # Same Filter Base might be used several times, therefore SPI may already be present
                    # (if its false, it will forever be false)
                    # (if its true, and it made the #1 criteria, it will continue true)
                    if isinstance(filter_base_dict.get(filter_base).get('SPI'), bool):
                        continue
                    for filter_id in filter_base_dict.get(filter_base):
                        filter_dict = filter_base_dict.get(filter_base).get(filter_id)
                        if domain_name and ip_address:
                            if filter_dict.get('host-name') or filter_dict.get('l7-uri') or filter_dict.get(
                                    'signature'):
                                filter_dict['SPI'] = False
                            else:
                                filter_dict['SPI'] = True
                        elif domain_name:
                            if filter_dict.get('host-name') or filter_dict.get('l7-uri') or filter_dict.get(
                                    'signature') \
                                    or filter_dict.get('destination-address'):
                                filter_dict['SPI'] = False
                            else:
                                filter_dict['SPI'] = True
                        elif ip_address:
                            if filter_dict.get('host-name') or filter_dict.get('l7-uri') or filter_dict.get(
                                    'signature') \
                                    or filter_dict.get('domain-name'):
                                filter_dict['SPI'] = False
                            else:
                                filter_dict['SPI'] = True
                        else:
                            filter_dict['SPI'] = False
                    filter_base_dict[filter_base]['SPI'] = True
                else:
                    filter_base_dict[filter_base]['SPI'] = False

            except:
                print(f" FilterBase -- {filter_base} -- referecend by PR {pr}  does not exist in FilterBase.yaml.")
                traceback.print_exc()

    for filter_base in list(filter_base_dict):
        if not isinstance(filter_base_dict.get(filter_base).get('SPI'), bool):
            filter_base_dict.pop(filter_base)

    return export_yaml(filter_base_dict, 'FilterBase')


def create_unique_pru(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml, 'PolicyRule')
    unique_pru_dict = dict()
    used_filterbase_dict = dict()
    for pr_name in policy_rule_dict.keys():
        filter_base = policy_rule_dict.get(pr_name).get('pcc-filter-base-name')
        flow_gate_status = policy_rule_dict.get(pr_name).get('pcc-rule-action')
        concat = f"{filter_base}{flow_gate_status}"
        if not unique_pru_dict.get(concat):
            if not used_filterbase_dict.get(filter_base):
                used_filterbase_dict.update({filter_base: 1})
            else:
                used_filterbase_dict[filter_base] += 1
            unique_pru_dict.update({concat: f"{filter_base}---{used_filterbase_dict[filter_base]}_PRU"})

    return export_yaml(unique_pru_dict, 'UniquePolicyRuleUnit')


def check_name_lenghts(cmg_policy_rule_yaml, prefix_list_yaml, dns_ip_cache_yaml, policy_rule_unit_yaml,
                       application_yaml, spi_policy_rule_unit_yaml=None):
    cmg_policy_rule_dict = read_yaml_file(cmg_policy_rule_yaml).get('CMGPolicyRule')
    prefix_list_dict = read_yaml_file(prefix_list_yaml).get('PrefixList')
    dns_ip_cache_dict = read_yaml_file(dns_ip_cache_yaml).get('DnsIpCache')
    policy_rule_unit_dict = read_yaml_file(policy_rule_unit_yaml).get('PolicyRuleUnit')
    application_dict = read_yaml_file(application_yaml).get('Application')
    if spi_policy_rule_unit_yaml:
        spi_policy_rule_unit_dict = read_yaml_file(spi_policy_rule_unit_yaml).get('SPIPolicyRuleUnit')

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
    if spi_policy_rule_unit_yaml:
        for pru_name in spi_policy_rule_unit_dict:
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


def chuncks(lista, size):
    for i in range(0, len(lista), size):
        yield lista[i:i + size]


# todo: may not work for FNG because SPI is not considered for FNG
def aggregate_address(input_dict, spi_mode=False):
    if input_dict:
        aggregation_list = dict()
        for key in input_dict:
            if spi_mode:
                if input_dict.get(key).pop('SPI'):
                    list_of_filters_dict = input_dict.get(key)
                    aggregate_addresses = dict()
                    filter_base_aggregation = dict()
                    for filter_name in list_of_filters_dict:
                        if list_of_filters_dict.get(filter_name).get('destination-address') or list_of_filters_dict.get(
                                filter_name).get('ipv6-destination-address'):
                            address = None
                            aggregation_string = None
                            if list_of_filters_dict.get(filter_name).get('destination-address'):
                                address = list_of_filters_dict.get(filter_name).get('destination-address')
                                if ':' not in address:
                                    aggregation_string = 'v4Protocol{}Port{}Domain{}Host{}URI{}'
                                else:
                                    aggregation_string = 'v6Protocol{}Port{}Domain{}Host{}URI{}'
                            elif list_of_filters_dict.get(filter_name).get('ipv6-destination-address'):
                                address = list_of_filters_dict.get(filter_name).get('ipv6-destination-address')
                                aggregation_string = 'v6Protocol{}Port{}Domain{}Host{}URI{}'

                            protocol = list_of_filters_dict.get(filter_name).get('protocol-id', '0000')
                            ports = list_of_filters_dict.get(filter_name).get('destination-port-list', '0000')
                            domain = list_of_filters_dict.get(filter_name).get('domain-name', '0000')
                            host = list_of_filters_dict.get(filter_name).get('host-name', '0000')
                            uri = list_of_filters_dict.get(filter_name).get('l7-uri', '0000')

                            protocol = protocol if protocol else '0000'
                            ports = ports if ports else '0000'
                            domain = domain if domain else '0000'
                            host = host if host else '0000'
                            uri = uri if uri else '0000'

                            aggregation_string = aggregation_string.format(protocol, ports, domain, host, uri)

                            if not aggregate_addresses.get(aggregation_string):
                                aggregate_addresses.update({aggregation_string: list()})
                            if address:
                                aggregate_addresses.get(aggregation_string).append(address)

                    filter_base_aggregation.update({key: aggregate_addresses})
                    aggregation_list.update(filter_base_aggregation)
            else:
                if not input_dict.get(key).pop('SPI'):
                    list_of_filters_dict = input_dict.get(key)
                    aggregate_addresses = dict()
                    filter_base_aggregation = dict()
                    for filter_name in list_of_filters_dict:
                        if list_of_filters_dict.get(filter_name).get('destination-address') or list_of_filters_dict.get(
                                filter_name).get('ipv6-destination-address'):
                            address = None
                            aggregation_string = None
                            if list_of_filters_dict.get(filter_name).get('destination-address'):
                                address = list_of_filters_dict.get(filter_name).get('destination-address')
                                if ':' not in address:
                                    aggregation_string = 'v4Protocol{}Port{}Domain{}Host{}URI{}'
                                else:
                                    aggregation_string = 'v6Protocol{}Port{}Domain{}Host{}URI{}'
                            elif list_of_filters_dict.get(filter_name).get('ipv6-destination-address'):
                                address = list_of_filters_dict.get(filter_name).get('ipv6-destination-address')
                                aggregation_string = 'v6Protocol{}Port{}Domain{}Host{}URI{}'

                            protocol = list_of_filters_dict.get(filter_name).get('protocol-id', '0000')
                            ports = list_of_filters_dict.get(filter_name).get('destination-port-list', '0000')
                            domain = list_of_filters_dict.get(filter_name).get('domain-name', '0000')
                            host = list_of_filters_dict.get(filter_name).get('host-name', '0000')
                            uri = list_of_filters_dict.get(filter_name).get('l7-uri', '0000')

                            protocol = protocol if protocol else '0000'
                            ports = ports if ports else '0000'
                            domain = domain if domain else '0000'
                            host = host if host else '0000'
                            uri = uri if uri else '0000'

                            aggregation_string = aggregation_string.format(protocol, ports, domain, host, uri)

                            if not aggregate_addresses.get(aggregation_string):
                                aggregate_addresses.update({aggregation_string: list()})
                            if address:
                                aggregate_addresses.get(aggregation_string).append(address)

                    filter_base_aggregation.update({key: aggregate_addresses})
                    aggregation_list.update(filter_base_aggregation)
        return aggregation_list


def get_filter_base(filter_base_yaml, spi_mode=False):
    filter_base_list = read_yaml_file(filter_base_yaml).get('FilterBase')
    if filter_base_list:
        return aggregate_address(filter_base_list, spi_mode)
    return None


def get_filter(policy_rule_yaml, spi_mode=False):
    policy_rule_filters = create_rule_filter_dict(policy_rule_yaml)
    if policy_rule_filters:
        return aggregate_address(policy_rule_filters, spi_mode)
    return None
