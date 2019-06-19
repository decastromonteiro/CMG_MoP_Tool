import re

from utils.yaml import YAML

filter_base_name_pattern = r'pcc-filter-base-name : (.+)'
filter_name_pattern = r'filter = (.+)'
l7_uri_pattern = r'l7-uri = (.+)'
protocol_id_pattern = r'protocol-id = (.+)'
destination_address_pattern = r'destination-address = (.+)'
destination_port_list_pattern = r'destination-port-list = (.+)'
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


def parse_filter_base(file_input):
    list_of_filter_base = list()
    filter_base_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('pcc-filter-base-name'):
                if filter_base_dict:
                    list_of_filter_base.append(filter_base_dict)
                match = re.findall(filter_base_name_pattern, line)
                if match:
                    filter_base_dict = dict()
                    filter_base_dict[match[0]] = list()
            if line.startswith('filter'):
                filter_match = re.findall(filter_name_pattern, line)
                if filter_match:
                    if filter_base_dict:
                        filter_dict = dict()
                        filter_base_dict[match[0]].append(
                            {filter_match[0]: filter_dict}
                        )
            if line.startswith('destination-address'):
                destination_address_match = re.findall(destination_address_pattern, line)
                if destination_address_match:
                    filter_dict.update({'destination-address': destination_address_match[0]})
            if line.startswith('destination-port-list'):
                destination_port_list_match = re.findall(destination_port_list_pattern, line)
                if destination_port_list_match:
                    filter_dict.update({'destination-port-list': destination_port_list_match[0]})
            if line.startswith('l7-uri'):
                l7_uri_match = re.findall(l7_uri_pattern, line)
                if l7_uri_match:
                    filter_dict.update({'l7-uri': l7_uri_match[0]})
            if line.startswith('precedence'):
                precedence_match = re.findall(precedence_pattern, line)
                if precedence_match:
                    filter_dict.update({'precedence': precedence_match[0]})
            if line.startswith('protocol-id'):
                protocol_id_match = re.findall(protocol_id_pattern, line)
                if protocol_id_match:
                    filter_dict.update({'protocol-id': protocol_id_match[0]})
            if line.startswith('source-address'):
                source_address_match = re.findall(source_address_pattern, line)
                if source_address_match:
                    filter_dict.update(
                        {'source-address': source_address_match[0]}
                    )
        return list_of_filter_base


def parse_pcc_rule_filter(file_input):
    list_of_pcc_rule = list()
    pcc_rule_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('pcc-rule-name'):
                if pcc_rule_dict:
                    list_of_pcc_rule.append(pcc_rule_dict)
                match = re.findall(pcc_rule_name_pattern, line)
                if match:
                    pcc_rule_dict = dict()
                    pcc_rule_dict[match[0]] = list()
            if line.startswith('filter'):
                filter_match = re.findall(filter_name_pattern, line)
                if filter_match:
                    if pcc_rule_dict:
                        filter_dict = dict()
                        pcc_rule_dict[match[0]].append(
                            {filter_match[0]: filter_dict}
                        )
            if line.startswith('destination-address'):
                destination_address_match = re.findall(destination_address_pattern, line)
                if destination_address_match:
                    filter_dict.update({'destination-address': destination_address_match[0]})
            if line.startswith('destination-port-list'):
                destination_port_list_match = re.findall(destination_port_list_pattern, line)
                if destination_port_list_match:
                    filter_dict.update({'destination-port-list': destination_port_list_match[0]})
            if line.startswith('l7-uri'):
                l7_uri_match = re.findall(l7_uri_pattern, line)
                if l7_uri_match:
                    filter_dict.update({'l7-uri': l7_uri_match[0]})
            if line.startswith('host-name'):
                host_name_match = re.findall(host_name_pattern, line)
                if host_name_match:
                    filter_dict.update({'host-name': host_name_match[0]})
            if line.startswith('precedence'):
                precedence_match = re.findall(precedence_pattern, line)
                if precedence_match:
                    filter_dict.update({'precedence': precedence_match[0]})
            if line.startswith('protocol-id'):
                protocol_id_match = re.findall(protocol_id_pattern, line)
                if protocol_id_match:
                    filter_dict.update({'protocol-id': protocol_id_match[0]})

        return list_of_pcc_rule


def parse_pcc_rule(file_input):
    pcc_rule_name_pattern = r'pcc-rule-name = (.+)'
    pcc_filter_base_pattern = r'pcc-filter-base-name = (.+)'
    list_of_pcc_rule = list()
    pcc_rule_dict = None
    with open(file_input) as fin:
        for line in fin:
            line = line.strip()
            if line.startswith('pcc-rule-name'):
                match = re.findall(pcc_rule_name_pattern, line)
                if match:
                    pcc_rule_dict = dict()
                    parameter_dict = dict()
                    pcc_rule_dict[match[0]] = parameter_dict
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
                    list_of_pcc_rule.append(pcc_rule_dict)
        list_of_pcc_rule = sorted(list_of_pcc_rule, key=lambda k: k[list(k.keys())[0]]['precedence'])
        return list_of_pcc_rule


def parse_pcc_rule_base(file_input):
    pcc_rule_name_pattern = r'pcc-rule-name = (.+?)\s'
    pcc_rule_base_pattern = r'pcc-rule-base-name = (.+)'
    list_of_pcc_rule_base = list()
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
                    pcc_rule_base_dict[match[0]].append(pcc_rule_name_match[0])
            if line.startswith('pcc-rule-base-identifier'):
                list_of_pcc_rule_base.append(pcc_rule_base_dict)

        return list_of_pcc_rule_base


def main():
    fng_filter_base = '/home/decastromonteiro/PycharmProjects/CMG_MoP_Tool/fng_inputs/fng_filter_base'
    fng_filters = '/home/decastromonteiro/PycharmProjects/CMG_MoP_Tool/fng_inputs/fng_filters'
    pcc_rule = '/home/decastromonteiro/PycharmProjects/CMG_MoP_Tool/fng_inputs/fng_policy_rule'
    pcc_rule_base = '/home/decastromonteiro/PycharmProjects/CMG_MoP_Tool/fng_inputs/fng_policy_rule_base'

    filter_base = parse_filter_base(fng_filter_base)
    filters = parse_pcc_rule_filter(fng_filters)
    pcc_rules = parse_pcc_rule(pcc_rule)
    pcc_rule_bases = parse_pcc_rule_base(pcc_rule_base)

    fb = YAML(project_name="FilterBase")
    fb.write_to_yaml({'FilterBase': filter_base})

    f = YAML(project_name="PolicyRuleFilter")
    f.write_to_yaml({'PolicyRuleFilter': filters})

    pr = YAML(project_name="PolicyRule")
    pr.write_to_yaml({'PolicyRule': pcc_rules})

    prb = YAML(project_name='PolicyRuleBase')
    prb.write_to_yaml({'PolicyRuleBase': pcc_rule_bases})


main()
