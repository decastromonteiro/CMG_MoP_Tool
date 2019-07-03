import os
from utils.yaml import YAML
import re


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def export_yaml(data, project_name='AppFilter'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({'AppFilter': data})
    return path


def create_app_filter_yaml(policy_rule_filter_yaml, filter_base_yaml, prefix_list_yaml, policy_rule_yaml):
    application_pattern = r'(.+)_'
    r'Protocol6Port80,443Domain0000Host0000URI0000'
    protocol_pattern = r'Protocol(.*)Port'
    port_pattern = r'Port(.*)Domain'
    domain_pattern = r'Domain(.*)Host'
    host_pattern = r'Host(.*)URI'
    uri_pattern = r'URI(.*)'
    policy_rule_filter_dict = read_yaml_file(policy_rule_filter_yaml).get('PolicyRuleFilter')
    prefix_list_dict = read_yaml_file(prefix_list_yaml).get('PrefixList')
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    entry_number = 10
    entries_used = set()

    # Create Rule:Precedence Dictionary
    rule_precedence_dict = dict()
    for key in policy_rule_dict:
        rule_precedence_dict.update({key: policy_rule_dict.get(key).get('precedence')})
        if policy_rule_dict.get(key).get('pcc-filter-base-name').lower() != 'null':
            rule_precedence_dict.update(
                {policy_rule_dict.get(key).get('pcc-filter-base-name'): policy_rule_dict.get(key).get('precedence')})

    app_filter_dict = dict()
    for key in prefix_list_dict:
        application = re.findall(application_pattern, key)[0]
        entry_number = int(rule_precedence_dict.get(application)) if int(
            rule_precedence_dict.get(application)) not in entries_used else entry_number

        filter_string = list(prefix_list_dict.get(key).keys())[0]
        ip_protocol = re.findall(protocol_pattern, filter_string)[0]
        port = re.findall(port_pattern, filter_string)[0]
        host = re.findall(host_pattern, filter_string)[0]
        domain = re.findall(domain_pattern, filter_string)[0]
        uri = re.findall(uri_pattern, filter_string)[0]

        app_filter_dict.update(
            {
                entry_number: {'ip-protocol-num': ip_protocol,
                               'server-port': port,
                               'expression': {
                                   'http-host': host,
                                   'http-uri': uri
                               },
                               'server-address': key or domain,
                               'application': application,
                               'protocol': None
                               }
            }
        )
        entries_used.add(entry_number)
        entry_number += 10

    for key in policy_rule_filter_dict:
        for filter_name in policy_rule_filter_dict.get(key):
            filter_dict = policy_rule_filter_dict.get(key).get(filter_name)
            if not (filter_dict.get('destination-address') or filter_dict.get('ipv6-destination-address')):
                ip_protocol = filter_dict.get('protocol-id')
                port = filter_dict.get('destination-port-list', '0000')
                host = filter_dict.get('host-name', '0000')
                uri = filter_dict.get('l7-uri', '0000') if not filter_dict.get('l7-uri', '0000').endswith(
                    ':') else '0000'
                protocol = filter_dict.get('l7-uri', '0000') if filter_dict.get('l7-uri', '0000').endswith(
                    ':') else '0000'
                domain = filter_dict.get('domain-name', '0000')
                app_filter_dict.update(
                    {
                        entry_number: {'ip-protocol-num': ip_protocol,
                                       'server-port': port,
                                       'expression': {
                                           'http-host': host,
                                           'http-uri': uri
                                       },
                                       'server-address': domain,
                                       'application': key,
                                       'protocol': protocol
                                       }
                    }
                )

                entries_used.add(entry_number)
                entry_number += 10

    return app_filter_dict


def main():
    app_filter_dict = create_app_filter_yaml(
        policy_rule_filter_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\output\PolicyRuleFilter.yaml',
        filter_base_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\output\FilterBase.yaml',
        prefix_list_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\prefix_list\PrefixList.yaml',
        policy_rule_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\output\PolicyRule.yaml')

    export_yaml(app_filter_dict)


if __name__ == "__main__":
    main()
