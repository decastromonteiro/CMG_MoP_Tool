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


def create_rule_precedence_dict(policy_rule_yaml):
    # Create Rule:Precedence Dictionary
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    rule_precedence_dict = dict()
    for key in policy_rule_dict:
        rule_precedence_dict.update({key: policy_rule_dict.get(key).get('precedence')})
        if policy_rule_dict.get(key).get('pcc-filter-base-name').lower() != 'null':
            rule_precedence_dict.update(
                {policy_rule_dict.get(key).get('pcc-filter-base-name'): policy_rule_dict.get(key).get('precedence')})

    return rule_precedence_dict


def create_filter_base_rule_dict(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    filter_base_rule_dict = dict()

    for key in policy_rule_dict:
        if policy_rule_dict.get(key).get('pcc-filter-base-name') != 'null':
            filter_base_rule_dict.update({policy_rule_dict.get(key).get('pcc-filter-base-name'): key})

    return filter_base_rule_dict


def search_application(app_filter_dict, application, used_key):
    used_key = used_key if used_key else list()
    for key in app_filter_dict:
        if app_filter_dict.get(key).get('application') == application:
            if key not in used_key:
                used_key.append(key)
                return key + 1, used_key

    return None, used_key


def calculate_entry_number(entry_number, rule_precedence_dict, application, entries_used):
    if not entry_number:
        if int(rule_precedence_dict.get(application)) not in entries_used:
            entry_number = int(rule_precedence_dict.get(application))
            return entry_number
        else:
            entry_number = sorted(entries_used)[-1] + 1
            return entry_number
    elif entry_number in entries_used:
        entry_number = sorted(entries_used)[-1] + 1
        return entry_number
    else:
        return entry_number


def create_app_filter_yaml(policy_rule_filter_yaml, prefix_list_yaml, policy_rule_yaml):
    dns_ip_cache = {}
    application_pattern = r'(.+)_'
    r'Protocol6Port80,443Domain0000Host0000URI0000'
    protocol_pattern = r'Protocol(.*)Port'
    port_pattern = r'Port(.*)Domain'
    domain_pattern = r'Domain(.*)Host'
    host_pattern = r'Host(.*)URI'
    uri_pattern = r'URI(.*)'
    policy_rule_filter_dict = read_yaml_file(policy_rule_filter_yaml).get('PolicyRuleFilter')
    prefix_list_dict = read_yaml_file(prefix_list_yaml).get('PrefixList')
    entry_number = 10
    entries_used = set()
    rule_precedence_dict = create_rule_precedence_dict(policy_rule_yaml)
    filter_base_rule_dict = create_filter_base_rule_dict(policy_rule_yaml)
    app_filter_dict = dict()
    used_key = list()
    # app-filter from PREFIX-LISTS
    for key in prefix_list_dict:
        application = re.findall(application_pattern, key)[0]
        entry_number, used_key = search_application(app_filter_dict, application, used_key)
        entry_number = calculate_entry_number(entry_number=entry_number,
                                              rule_precedence_dict=rule_precedence_dict,
                                              application=application,
                                              entries_used=entries_used)
        filter_string = list(prefix_list_dict.get(key).keys())[0]
        ip_protocol = re.findall(protocol_pattern, filter_string)[0]
        port = re.findall(port_pattern, filter_string)[0]
        host = re.findall(host_pattern, filter_string)[0]
        domain = re.findall(domain_pattern, filter_string)[0]
        uri = re.findall(uri_pattern, filter_string)[0]
        app_filter_dict.update(
            {
                entry_number: {'ip-protocol-num': ip_protocol if ip_protocol != '0000' else None,
                               'server-port': port if port != '0000' else None,
                               'expression': {
                                   'http-host': host if host != '0000' else None,
                                   'http-uri': uri if uri != '0000' else None,
                               },
                               'server-address': {
                                   'ip-prefix-list': key,
                                   'dns-ip-cache': dns_ip_cache.get(domain),
                                   'ip-address': None
                               },
                               'application': filter_base_rule_dict.get(application, application),
                               'protocol': None
                               }
            }
        )
        entries_used.add(entry_number)
        entry_number += 10
    # app-filter from FILTERS
    for key in policy_rule_filter_dict:
        for filter_name in policy_rule_filter_dict.get(key):
            filter_dict = policy_rule_filter_dict.get(key).get(filter_name)
            if not (filter_dict.get('destination-address') or filter_dict.get('ipv6-destination-address')):
                ip_protocol = filter_dict.get('protocol-id')
                port = filter_dict.get('destination-port-list')
                host = filter_dict.get('host-name')
                uri = filter_dict.get('l7-uri') if not filter_dict.get('l7-uri', '0000').endswith(
                    ':') else None
                protocol = filter_dict.get('l7-uri') if filter_dict.get('l7-uri', '0000').endswith(
                    ':') else None
                domain = filter_dict.get('domain-name')
                application = key
                entry_number, used_key = search_application(app_filter_dict, application, used_key)
                entry_number = calculate_entry_number(entry_number=entry_number,
                                                      rule_precedence_dict=rule_precedence_dict,
                                                      application=application,
                                                      entries_used=entries_used)
                app_filter_dict.update(
                    {
                        entry_number: {'ip-protocol-num': ip_protocol,
                                       'server-port': port,
                                       'expression': {
                                           'http-host': host,
                                           'http-uri': uri
                                       },
                                       'server-address': {
                                           'ip-prefix-list': None,
                                           'dns-ip-cache': dns_ip_cache.get(domain),
                                           'ip-address': None
                                       },
                                       'application': application,
                                       'protocol': protocol
                                       }
                    }
                )

                entries_used.add(entry_number)
                entry_number += 10

    return app_filter_dict


def main():
    app_filter_dict = create_app_filter_yaml(
        policy_rule_filter_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRuleFilter.yaml',
        prefix_list_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\prefix_list\PrefixList.yaml',
        policy_rule_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml')

    export_yaml(app_filter_dict)


if __name__ == "__main__":
    main()
