import re
from collections import OrderedDict
from utils.yaml import read_yaml_file, export_yaml

filter_base_name_pattern = re.compile(r'pcc-filter-base-name : (.+)')
filter_name_pattern = re.compile(r'filter = (.+)')
l7_uri_pattern = re.compile(r'l7-uri = (.+)')
protocol_id_pattern = re.compile(r'protocol-id = (.+)')
destination_address_pattern = re.compile(r'destination-address = (.+)')
ipv6_destination_address_pattern = re.compile(r'ipv6-destination-address = (.+)')
destination_port_list_pattern = re.compile(r'destination-port-list = (.+)')
domain_name_pattern = re.compile(r'domain-name = (.+)')
host_name_pattern = re.compile(r'host-name = (.+)')
pcc_rule_name_pattern = re.compile(r'pcc-rule-name : (.+)')
header_enrichment_type_pattern = re.compile(r'header-enrichment-type = (.+)')
monitoring_key_pattern = re.compile(r'monitoring-key = (.+)')
pcc_rule_action_pattern = re.compile(r'pcc-rule-action = (.+)')
precedence_pattern = re.compile(r'precedence = (.+)')
rating_group_pattern = re.compile(r'rating-group = (.+)')
service_id_pattern = re.compile(r'service-id = (.+)')
redirect_uri_pattern = re.compile(r'redirect-uri = (.+)')
qos_profile_name_pattern = re.compile(r'qos-profile-name = (.+)')
source_address_pattern = re.compile(r'source-address = (.+)')
maximum_bit_rate_dl_pattern = re.compile(r'maximum-bit-rate-dl = (.+)')
maximum_bit_rate_ul_pattern = re.compile(r'maximum-bit-rate-ul = (.+)')


def parse_filter_base(file_input):
    list_of_filter_base = dict()
    filter_base_dict = None
    filter_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('pcc-filter-base-name'):
                if filter_base_dict:
                    list_of_filter_base.update(filter_base_dict)
                match = re.findall(filter_base_name_pattern, line)
                if match:
                    filter_base_dict = dict()
                    filter_base_dict[match[0]] = dict()
            if line.startswith('filter'):
                filter_match = re.findall(filter_name_pattern, line)
                if filter_match:
                    if filter_base_dict:
                        filter_dict = dict()
                        filter_base_dict[match[0]].update(
                            {filter_match[0]: filter_dict}
                        )
                        destination_address = None
                        ipv6_destination_address = None
                        domain_name = None
                        destination_port_list = None
                        host_name = None
                        l7_uri = None
                        precedence = None
                        protocol_id = None
                        signature = None
            # IPv4 Destination Address
            if line.startswith('destination-address'):
                destination_address_match = destination_address_pattern.match(line)
                if destination_address_match:
                    destination_address = destination_address_match.group(1)
            # IPv6 Destination Address
            if line.startswith('ipv6-destination-address'):
                ipv6_destination_address_match = ipv6_destination_address_pattern.match(line)
                if ipv6_destination_address_match:
                    ipv6_destination_address = ipv6_destination_address_match.group(1)
            # Domain Name
            if line.startswith('domain-name'):
                domain_name_match = domain_name_pattern.match(line)
                if domain_name_match:
                    domain_name = domain_name_match.group(1)
            # Port List
            if line.startswith('destination-port-list'):
                destination_port_list_match = destination_port_list_pattern.match(line)
                if destination_port_list_match:
                    destination_port_list = destination_port_list_match.group(1)
            # Host Name (L7)
            if line.startswith('host-name'):
                host_name_match = host_name_pattern.match(line)
                if host_name_match:
                    host_name = host_name_match.group(1)
            # L7 URI
            if line.startswith('l7-uri'):
                l7_uri_match = l7_uri_pattern.match(line)
                if l7_uri_match:
                    if l7_uri_match.group(1).endswith(':'):
                        signature = l7_uri_match.group(1)[:-1]
                    else:
                        l7_uri = l7_uri_match.group(1)
            # Precedence
            if line.startswith('precedence'):
                precedence_match = precedence_pattern.match(line)
                if precedence_match:
                    precedence = precedence_match.group(1)
            # Protocol ID
            if line.startswith('protocol-id'):
                protocol_id_match = protocol_id_pattern.match(line)
                if protocol_id_match:
                    protocol_id = protocol_id_match.group(1)

            if isinstance(filter_dict, dict):
                filter_dict.update(
                        {
                            'destination-address': destination_address,
                            'ipv6-destination-address': ipv6_destination_address,
                            'domain-name': domain_name,
                            'destination-port-list': destination_port_list,
                            'protocol-id': protocol_id,
                            'host-name': host_name,
                            'l7-uri': l7_uri,
                            'signature': signature,
                            'precedence': precedence
                        }

                    )
        if filter_base_dict:
            list_of_filter_base.update(filter_base_dict)
    return export_yaml(list_of_filter_base, 'FilterBase')


def parse_pcc_rule_filter(file_input, conversion_dict=None):
    if not conversion_dict:
        conversion_dict = dict()
    else:
        conversion_dict = read_yaml_file(conversion_dict)
    list_of_pcc_rule = dict()
    pcc_rule_dict = None
    filter_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('pcc-rule-name'):
                if pcc_rule_dict:
                    list_of_pcc_rule.update(pcc_rule_dict)
                match = pcc_rule_name_pattern.match(line)
                if match:
                    pcc_rule_dict = dict()
                    pcc_rule_dict[conversion_dict.get(match.group(1), match.group(1))] = dict()
            if line.startswith('filter'):
                filter_match = filter_name_pattern.match(line)
                if filter_match:
                    if pcc_rule_dict:
                        filter_dict = dict()
                        pcc_rule_dict[conversion_dict.get(match.group(1), match.group(1))].update(
                            {filter_match.group(1): filter_dict}
                        )
                        destination_address = None
                        ipv6_destination_address = None
                        domain_name = None
                        destination_port_list = None
                        host_name = None
                        l7_uri = None
                        precedence = None
                        protocol_id = None
                        signature = None
            # IPv4 Destination Address
            if line.startswith('destination-address'):
                destination_address_match = destination_address_pattern.match(line)
                if destination_address_match:
                    destination_address = destination_address_match.group(1)
            # IPv6 Destination Address
            if line.startswith('ipv6-destination-address'):
                ipv6_destination_address_match = ipv6_destination_address_pattern.match(line)
                if ipv6_destination_address_match:
                    ipv6_destination_address = ipv6_destination_address_match.group(1)
            # Domain Name
            if line.startswith('domain-name'):
                domain_name_match = domain_name_pattern.match(line)
                if domain_name_match:
                    domain_name = domain_name_match.group(1)
            # Port List
            if line.startswith('destination-port-list'):
                destination_port_list_match = destination_port_list_pattern.match(line)
                if destination_port_list_match:
                    destination_port_list = destination_port_list_match.group(1)
            # Host Name (L7)
            if line.startswith('host-name'):
                host_name_match = host_name_pattern.match(line)
                if host_name_match:
                    host_name = host_name_match.group(1)
            # L7 URI
            if line.startswith('l7-uri'):
                l7_uri_match = l7_uri_pattern.match(line)
                if l7_uri_match:
                    if l7_uri_match.group(1).endswith(':'):
                        signature = l7_uri_match.group(1)[:-1]
                    else:
                        l7_uri = l7_uri_match.group(1)
            # Precedence
            if line.startswith('precedence'):
                precedence_match = precedence_pattern.match(line)
                if precedence_match:
                    precedence = precedence_match.group(1)
            # Protocol ID
            if line.startswith('protocol-id'):
                protocol_id_match = protocol_id_pattern.match(line)
                if protocol_id_match:
                    protocol_id = protocol_id_match.group(1)

            if isinstance(filter_dict, dict):
                filter_dict.update(
                        {
                            'destination-address': destination_address,
                            'ipv6-destination-address': ipv6_destination_address,
                            'domain-name': domain_name,
                            'destination-port-list': destination_port_list,
                            'protocol-id': protocol_id,
                            'host-name': host_name,
                            'l7-uri': l7_uri,
                            'signature': signature,
                            'precedence': precedence
                        }

                    )

        if pcc_rule_dict:
            list_of_pcc_rule.update(pcc_rule_dict)
    return list_of_pcc_rule


def parse_pcc_rule(file_input, fng_filter_input, conversion_dict=None):
    if not conversion_dict:
        conversion_dict = dict()
    else:
        conversion_dict = read_yaml_file(conversion_dict)
    pcc_rule_filter_dict = parse_pcc_rule_filter(fng_filter_input, conversion_dict)
    pcc_rule_name_pattern = re.compile(r'pcc-rule-name = (.+)')
    pcc_filter_base_pattern = re.compile(r'pcc-filter-base-name = (.+)')
    list_of_pcc_rule = dict()
    pcc_rule_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('pcc-rule-name'):
                match = pcc_rule_name_pattern.match(line)
                if match:
                    pcc_rule_dict = dict()
                    parameter_dict = dict()
                    pcc_rule_dict[conversion_dict.get(match.group(1), match.group(1))] = parameter_dict
            if line.startswith('precedence'):
                precedence_match = precedence_pattern.match(line)
                if precedence_match:
                    parameter_dict.update({'precedence': precedence_match.group(1)})
            if line.startswith('header-enrichment-type'):
                header_enrichment_type_match = header_enrichment_type_pattern.match(line)
                if header_enrichment_type_match:
                    he = None if header_enrichment_type_match.group(
                        1) == 'null' else header_enrichment_type_match.group(1)
                    parameter_dict.update(
                        {'header-enrichment-type': he}
                    )

            if line.startswith('monitoring-key'):
                monitoring_key_match = monitoring_key_pattern.match(line)
                if monitoring_key_match:
                    parameter_dict.update({'monitoring-key': monitoring_key_match.group(1)})

            if line.startswith('pcc-filter-base-name'):
                pcc_filter_base_match = pcc_filter_base_pattern.match(line)
                if pcc_filter_base_match:
                    filter_base = None if pcc_filter_base_match.group(1) == 'null' else pcc_filter_base_match.group(1)
                    parameter_dict.update(
                        {'pcc-filter-base-name': filter_base}
                    )

            if line.startswith('pcc-rule-action'):
                pcc_rule_action_match = pcc_rule_action_pattern.match(line)
                if pcc_rule_action_match:
                    parameter_dict.update(
                        {'pcc-rule-action': pcc_rule_action_match.group(1)}
                    )

            if line.startswith('precedence'):
                precedence_match = precedence_pattern.match(line)
                if precedence_match:
                    parameter_dict.update({'precedence': precedence_match.group(1)})

            if line.startswith('qos-profile-name'):
                qos_profile_name_match = qos_profile_name_pattern.match(line)
                if qos_profile_name_match:
                    qos_profile = None if qos_profile_name_match.group(1) == 'null' else qos_profile_name_match.group(1)
                    parameter_dict.update(
                        {'qos-profile-name': qos_profile}
                    )

            if line.startswith('rating-group'):
                rating_group_match = rating_group_pattern.match(line)
                if rating_group_match:
                    parameter_dict.update(
                        {'rating-group': rating_group_match.group(1)}
                    )
            if line.startswith('redirect-uri'):
                redirect_uri_match = redirect_uri_pattern.match(line)
                if redirect_uri_match:
                    redirect_uri = None if redirect_uri_match.group(1) == 'null' else redirect_uri_match.group(1)
                    parameter_dict.update(
                        {'redirect-uri': redirect_uri}
                    )
            if line.startswith('service-id'):
                service_id_match = service_id_pattern.match(line)
                if service_id_match:
                    service_id = None if service_id_match.group(1) == 'null' else service_id_match.group(1)
                    parameter_dict.update({'service-id': service_id})
                    list_of_pcc_rule.update(pcc_rule_dict)
        for pcc_rule in list_of_pcc_rule:
            list_of_pcc_rule.get(pcc_rule).update({'Filters': pcc_rule_filter_dict.get(pcc_rule)})

        list_of_pcc_rule = OrderedDict(sorted(list_of_pcc_rule.items(), key=lambda x: x[1]['precedence']))
    return export_yaml(list_of_pcc_rule, 'PolicyRule')


def parse_pcc_rule_base(file_input, conversion_dict=None):
    if not conversion_dict:
        conversion_dict = dict()
    else:
        conversion_dict = read_yaml_file(conversion_dict)
    pcc_rule_name_pattern = re.compile(r'pcc-rule-name = (\S+)')
    pcc_rule_base_pattern = re.compile(r'pcc-rule-base-name = (\S+)')
    dict_of_pcc_rule_base = dict()
    pcc_rule_base_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('pcc-rule-base-name'):
                match = pcc_rule_base_pattern.match(line)
                if match:
                    pcc_rule_base_dict = dict()
                    pcc_rule_list = list()
                    pcc_rule_base_dict[match.group(1)] = pcc_rule_list
            if line.startswith('pcc-rule-name'):
                pcc_rule_name_match = pcc_rule_name_pattern.match(line)
                if pcc_rule_name_match:
                    pcc_rule_base_dict[match.group(1)].append(
                        conversion_dict.get(pcc_rule_name_match.group(1), pcc_rule_name_match.group(1)))
            if line.startswith('pcc-rule-base-identifier'):
                dict_of_pcc_rule_base.update(pcc_rule_base_dict)
        if pcc_rule_base_dict:
            dict_of_pcc_rule_base.update(pcc_rule_base_dict)
    return export_yaml(dict_of_pcc_rule_base, 'PolicyRuleBase')


def parse_qos_profiles(file_input):
    dict_of_qos_profile = dict()
    qos_profile_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('qos-profile-name'):
                match = qos_profile_name_pattern.match(line)
                if match:
                    qos_profile_dict = dict()
                    parameter_dict = dict()
                    qos_profile_dict[match.group(1)] = parameter_dict
            if line.startswith('maximum-bit-rate-dl'):
                max_bit_rate_dl = maximum_bit_rate_dl_pattern.match(line)
                if max_bit_rate_dl:
                    parameter_dict.update(
                        {'downlink': {'peak-burst-size': max_bit_rate_dl.group(1),
                                      'peak-data-rate': max_bit_rate_dl.group(1)}}
                    )
                else:
                    parameter_dict.update(
                        {'downlink': {'peak-burst-size': None,
                                      'peak-data-rate': None}}
                    )

            if line.startswith('maximum-bit-rate-ul'):
                max_bit_rate_ul = maximum_bit_rate_ul_pattern.match(line)
                if max_bit_rate_ul:
                    parameter_dict.update(
                        {'uplink': {'peak-burst-size': max_bit_rate_ul.group(1),
                                    'peak-data-rate': max_bit_rate_ul.group(1)}}
                    )
                else:
                    parameter_dict.update(
                        {'uplink': {'peak-burst-size': None,
                                    'peak-data-rate': None}}
                    )
                dict_of_qos_profile.update(qos_profile_dict)
    if qos_profile_dict:
        dict_of_qos_profile.update(qos_profile_dict)
    return export_yaml(dict_of_qos_profile, 'QoSProfiles')


def main():
    pass


if __name__ == "__main__":
    main()
