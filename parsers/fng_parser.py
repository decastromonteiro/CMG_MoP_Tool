import re
from collections import OrderedDict
from utils.yaml import YAML
from utils.rule_convertion import convertion_dict

filter_base_name_pattern = r'pcc-filter-base-name : (.+)'
filter_name_pattern = r'filter = (.+)'
l7_uri_pattern = r'l7-uri = (.+)'
protocol_id_pattern = r'protocol-id = (.+)'
destination_address_pattern = r'destination-address = (.+)'
ipv6_destination_address_pattern = r'ipv6-destination-address = (.+)'
destination_port_list_pattern = r'destination-port-list = (.+)'
domain_name_pattern = r'domain-name = (.+)'
host_name_pattern = r'host-name = (.+)'
pcc_rule_name_pattern = r'pcc-rule-name : (.+)'
header_enrichment_type_pattern = r'header-enrichment-type = (.+)'
monitoring_key_pattern = r'monitoring-key = (.+)'
pcc_rule_action_pattern = r'pcc-rule-action = (.+)'
precedence_pattern = r'precedence = (.+)'
rating_group_pattern = r'rating-group = (.+)'
service_id_pattern = r'service-id = (.+)'
redirect_uri_pattern = r'redirect-uri = (.+)'
qos_profile_name_pattern = r'qos-profile-name = (.+)'
source_address_pattern = r'source-address = (.+)'
maximum_bit_rate_dl_pattern = r'maximum-bit-rate-dl = (.+)'
maximum_bit_rate_ul_pattern = r'maximum-bit-rate-ul = (.+)'


def parse_filter_base(file_input):
    list_of_filter_base = dict()
    filter_base_dict = None
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
            # IPv4 Destination Address
            if line.startswith('destination-address'):
                destination_address_match = re.findall(destination_address_pattern, line)
                if destination_address_match:
                    filter_dict.update({'destination-address': destination_address_match[0]})
            # IPv6 Destination Address
            if line.startswith('ipv6-destination-address'):
                ipv6_destination_address_match = re.findall(ipv6_destination_address_pattern, line)
                if ipv6_destination_address_match:
                    filter_dict.update({'ipv6-destination-address': ipv6_destination_address_match[0]})
            # Domain Name
            if line.startswith('domain-name'):
                domain_name_match = re.findall(domain_name_pattern, line)
                if domain_name_match:
                    filter_dict.update({'domain-name': domain_name_match[0]})
            # Port List
            if line.startswith('destination-port-list'):
                destination_port_list_match = re.findall(destination_port_list_pattern, line)
                if destination_port_list_match:
                    filter_dict.update({'destination-port-list': destination_port_list_match[0]})
            # Host Name (L7)
            if line.startswith('host-name'):
                host_name_match = re.findall(host_name_pattern, line)
                if host_name_match:
                    filter_dict.update({'host-name': host_name_match[0]})
            # L7 URI
            if line.startswith('l7-uri'):
                l7_uri_match = re.findall(l7_uri_pattern, line)
                if l7_uri_match:
                    filter_dict.update({'l7-uri': l7_uri_match[0]})
            # Precedence
            if line.startswith('precedence'):
                precedence_match = re.findall(precedence_pattern, line)
                if precedence_match:
                    filter_dict.update({'precedence': precedence_match[0]})
            # Protocol ID
            if line.startswith('protocol-id'):
                protocol_id_match = re.findall(protocol_id_pattern, line)
                if protocol_id_match:
                    filter_dict.update({'protocol-id': protocol_id_match[0]})
            # IPv4 Source Address
            if line.startswith('source-address'):
                source_address_match = re.findall(source_address_pattern, line)
                if source_address_match:
                    filter_dict.update(
                        {'source-address': source_address_match[0]}
                    )
        if filter_base_dict:
            list_of_filter_base.update(filter_base_dict)
        return list_of_filter_base


def parse_pcc_rule_filter(file_input):
    list_of_pcc_rule = dict()
    pcc_rule_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('pcc-rule-name'):
                if pcc_rule_dict:
                    list_of_pcc_rule.update(pcc_rule_dict)
                match = re.findall(pcc_rule_name_pattern, line)
                if match:
                    pcc_rule_dict = dict()
                    pcc_rule_dict[convertion_dict.get(match[0], match[0])] = dict()
            if line.startswith('filter'):
                filter_match = re.findall(filter_name_pattern, line)
                if filter_match:
                    if pcc_rule_dict:
                        filter_dict = dict()
                        pcc_rule_dict[convertion_dict.get(match[0], match[0])].update(
                            {filter_match[0]: filter_dict}
                        )
            # IPv4 Destination Address
            if line.startswith('destination-address'):
                destination_address_match = re.findall(destination_address_pattern, line)
                if destination_address_match:
                    filter_dict.update({'destination-address': destination_address_match[0]})
            # IPv6 Destination Address
            if line.startswith('ipv6-destination-address'):
                ipv6_destination_address_match = re.findall(ipv6_destination_address_pattern, line)
                if ipv6_destination_address_match:
                    filter_dict.update({'ipv6-destination-address': ipv6_destination_address_match[0]})
            # Domain Name
            if line.startswith('domain-name'):
                domain_name_match = re.findall(domain_name_pattern, line)
                if domain_name_match:
                    filter_dict.update({'domain-name': domain_name_match[0]})
            # Port List
            if line.startswith('destination-port-list'):
                destination_port_list_match = re.findall(destination_port_list_pattern, line)
                if destination_port_list_match:
                    filter_dict.update({'destination-port-list': destination_port_list_match[0]})
            # Host Name (L7)
            if line.startswith('host-name'):
                host_name_match = re.findall(host_name_pattern, line)
                if host_name_match:
                    filter_dict.update({'host-name': host_name_match[0]})
            # L7 URI
            if line.startswith('l7-uri'):
                l7_uri_match = re.findall(l7_uri_pattern, line)
                if l7_uri_match:
                    filter_dict.update({'l7-uri': l7_uri_match[0]})
            # Precedence
            if line.startswith('precedence'):
                precedence_match = re.findall(precedence_pattern, line)
                if precedence_match:
                    filter_dict.update({'precedence': precedence_match[0]})
            # Protocol ID
            if line.startswith('protocol-id'):
                protocol_id_match = re.findall(protocol_id_pattern, line)
                if protocol_id_match:
                    filter_dict.update({'protocol-id': protocol_id_match[0]})
            # IPv4 Source Address
            if line.startswith('source-address'):
                source_address_match = re.findall(source_address_pattern, line)
                if source_address_match:
                    filter_dict.update(
                        {'source-address': source_address_match[0]}
                    )

        if pcc_rule_dict:
            list_of_pcc_rule.update(pcc_rule_dict)
        return list_of_pcc_rule


def parse_pcc_rule(file_input, pcc_rule_filter_dict):
    pcc_rule_name_pattern = r'pcc-rule-name = (.+)'
    pcc_filter_base_pattern = r'pcc-filter-base-name = (.+)'
    list_of_pcc_rule = dict()
    pcc_rule_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('pcc-rule-name'):
                match = re.findall(pcc_rule_name_pattern, line)
                if match:
                    pcc_rule_dict = dict()
                    parameter_dict = dict()
                    pcc_rule_dict[convertion_dict.get(match[0], match[0])] = parameter_dict
            if line.startswith('precedence'):
                precedence_match = re.findall(precedence_pattern, line)
                if precedence_match:
                    parameter_dict.update({'precedence': precedence_match[0]})
            if line.startswith('header-enrichment-type'):
                header_enrichment_type_match = re.findall(header_enrichment_type_pattern, line)
                if header_enrichment_type_match:
                    parameter_dict.update(
                        {'header-enrichment-type': header_enrichment_type_match[0]}
                    )

            if line.startswith('monitoring-key'):
                monitoring_key_match = re.findall(monitoring_key_pattern, line)
                if monitoring_key_match:
                    parameter_dict.update({'monitoring-key': monitoring_key_match[0]})

            if line.startswith('pcc-filter-base-name'):
                pcc_filter_base_match = re.findall(pcc_filter_base_pattern, line)
                if pcc_filter_base_match:
                    parameter_dict.update(
                        {'pcc-filter-base-name': pcc_filter_base_match[0]}
                    )

            if line.startswith('pcc-rule-action'):
                pcc_rule_action_match = re.findall(pcc_rule_action_pattern, line)
                if pcc_rule_action_match:
                    parameter_dict.update(
                        {'pcc-rule-action': pcc_rule_action_match[0]}
                    )

            if line.startswith('precedence'):
                precedence_match = re.findall(precedence_pattern, line)
                if precedence_match:
                    parameter_dict.update({'precedence': precedence_match[0]})

            if line.startswith('qos-profile-name'):
                qos_profile_name_match = re.findall(qos_profile_name_pattern, line)
                if qos_profile_name_match:
                    parameter_dict.update(
                        {'qos-profile-name': qos_profile_name_match[0]}
                    )

            if line.startswith('rating-group'):
                rating_group_match = re.findall(rating_group_pattern, line)
                if rating_group_match:
                    parameter_dict.update(
                        {'rating-group': rating_group_match[0]}
                    )
            if line.startswith('redirect-uri'):
                redirect_uri_match = re.findall(redirect_uri_pattern, line)
                if redirect_uri_match:
                    parameter_dict.update(
                        {'redirect-uri': redirect_uri_match[0]}
                    )
            if line.startswith('service-id'):
                service_id_match = re.findall(service_id_pattern, line)
                if service_id_match:
                    parameter_dict.update({'service-id': service_id_match[0]})
                    list_of_pcc_rule.update(pcc_rule_dict)
        for pcc_rule in list_of_pcc_rule:
            list_of_pcc_rule.get(pcc_rule).update({'Filters': pcc_rule_filter_dict.get(pcc_rule)})

        list_of_pcc_rule = OrderedDict(sorted(list_of_pcc_rule.items(), key=lambda x: x[1]['precedence']))
        return list_of_pcc_rule


def parse_pcc_rule_base(file_input):
    pcc_rule_name_pattern = r'pcc-rule-name = (.+?)\s'
    pcc_rule_base_pattern = r'pcc-rule-base-name = (.+)'
    dict_of_pcc_rule_base = dict()
    pcc_rule_base_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('pcc-rule-base-name'):
                match = re.findall(pcc_rule_base_pattern, line)
                if match:
                    pcc_rule_base_dict = dict()
                    pcc_rule_list = list()
                    pcc_rule_base_dict[match[0]] = pcc_rule_list
            if line.startswith('pcc-rule-name'):
                pcc_rule_name_match = re.findall(pcc_rule_name_pattern, line)
                if pcc_rule_name_match:
                    pcc_rule_base_dict[match[0]].append(
                        convertion_dict.get(pcc_rule_name_match[0], pcc_rule_name_match[0]))
            if line.startswith('pcc-rule-base-identifier'):
                dict_of_pcc_rule_base.update(pcc_rule_base_dict)
        if pcc_rule_base_dict:
            dict_of_pcc_rule_base.update(pcc_rule_base_dict)
        return dict_of_pcc_rule_base


def parse_qos_profiles(file_input):
    dict_of_qos_profile = dict()
    qos_profile_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('qos-profile-name'):
                match = re.findall(qos_profile_name_pattern, line)
                if match:
                    qos_profile_dict = dict()
                    parameter_dict = dict()
                    qos_profile_dict[match[0]] = parameter_dict
            if line.startswith('maximum-bit-rate-dl'):
                max_bit_rate_dl = re.findall(maximum_bit_rate_dl_pattern, line)
                if max_bit_rate_dl:
                    parameter_dict.update({'maximum-bit-rate-dl': max_bit_rate_dl[0]})
            if line.startswith('maximum-bit-rate-ul'):
                max_bit_rate_ul = re.findall(maximum_bit_rate_ul_pattern, line)
                if max_bit_rate_ul:
                    parameter_dict.update({'maximum-bit-rate-ul': max_bit_rate_ul[0]})
                    dict_of_qos_profile.update(qos_profile_dict)
    if qos_profile_dict:
        dict_of_qos_profile.update(qos_profile_dict)
    return dict_of_qos_profile


def main():
    fng_filter_base = r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\input\fng_filter_base'
    fng_filters = r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\input\fng_filters'
    pcc_rule = r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\input\fng_policy_rule'
    pcc_rule_base = r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\input\fng_policy_rule_base'
    qos_profile = r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\input\fng_qos'

    filter_base = parse_filter_base(fng_filter_base)
    filters = parse_pcc_rule_filter(fng_filters)
    pcc_rules = parse_pcc_rule(pcc_rule)
    pcc_rule_bases = parse_pcc_rule_base(pcc_rule_base)
    qos_profiles = parse_qos_profiles(qos_profile)

    fb = YAML(project_name="FilterBase")
    fb.write_to_yaml({'FilterBase': filter_base})

    f = YAML(project_name="PolicyRuleFilter")
    f.write_to_yaml({'PolicyRuleFilter': filters})

    pr = YAML(project_name="PolicyRule")
    pr.write_to_yaml({'PolicyRule': pcc_rules})

    prb = YAML(project_name='PolicyRuleBase')
    prb.write_to_yaml({'PolicyRuleBase': pcc_rule_bases})

    qos = YAML(project_name='QoSProfiles')
    qos.write_to_yaml({'QoSProfiles': qos_profiles})


def main_oi():
    fng_filter_base = r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\input_oi\fng_filter_base'
    fng_filters = r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\input_oi\fng_filters'
    pcc_rule = r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\input_oi\fng_policy_rule'
    pcc_rule_base = r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\input_oi\fng_policy_rule_base'
    qos_profile = r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\input_oi\fng_qos'

    filter_base = parse_filter_base(fng_filter_base)
    filters = parse_pcc_rule_filter(fng_filters)
    pcc_rules = parse_pcc_rule(pcc_rule)
    pcc_rule_bases = parse_pcc_rule_base(pcc_rule_base)
    qos_profiles = parse_qos_profiles(qos_profile)

    fb = YAML(project_name="FilterBase")
    fb.write_to_yaml({'FilterBase': filter_base})

    f = YAML(project_name="PolicyRuleFilter")
    f.write_to_yaml({'PolicyRuleFilter': filters})

    pr = YAML(project_name="PolicyRule")
    pr.write_to_yaml({'PolicyRule': pcc_rules})

    prb = YAML(project_name='PolicyRuleBase')
    prb.write_to_yaml({'PolicyRuleBase': pcc_rule_bases})

    qos = YAML(project_name='QoSProfiles')
    qos.write_to_yaml({'QoSProfiles': qos_profiles})


if __name__ == "__main__":
    main_oi()
