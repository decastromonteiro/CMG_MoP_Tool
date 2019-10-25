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


def calculate_entry_number(application, entries_application_dict, entries_used, rule_precedence_dict):
    entry_number = int(rule_precedence_dict.get(application))
    if entry_number not in entries_used:
        if not entries_application_dict.get(application):
            entries_application_dict.update({application: [entry_number]})
        else:
            entries_application_dict.get(application).append(entry_number)
        entries_used.add(entry_number)
        return entry_number, entries_application_dict
    else:
        if not entries_application_dict.get(application):
            entry_number = sorted(entries_used)[-1] + 10
            entries_application_dict.update({application: [entry_number]})
        else:
            entry_number = sorted(entries_application_dict.get(application))[-1] + 5
            entry_number = entry_number if entry_number not in entries_used else sorted(entries_used)[-1] + 10
            entries_application_dict.get(application).append(entry_number)
        entries_used.add(entry_number)
        return entry_number, entries_application_dict


def create_domain_dns_dict(dns_ip_cache_yaml):
    dns_ip_cache_dict = read_yaml_file(dns_ip_cache_yaml).get('DnsIpCache')
    domain_dns_ip_cache = dict()
    for dns_ip_cache in dns_ip_cache_dict:
        for rule in dns_ip_cache_dict.get(dns_ip_cache):
            lista = dns_ip_cache_dict.get(dns_ip_cache).get(rule)
            for domain in lista:
                if not domain_dns_ip_cache.get(domain):
                    domain_dns_ip_cache.update(
                        {domain: dns_ip_cache}
                    )
    return domain_dns_ip_cache


def create_app_filter_yaml(policy_rule_filter_yaml, prefix_list_yaml, policy_rule_yaml, filter_base_yaml,
                           dns_ip_cache_yaml):
    dns_ip_cache = create_domain_dns_dict(dns_ip_cache_yaml)
    application_pattern = r'(.+?)_\d+'
    protocol_pattern = r'Protocol(.*)Port'
    port_pattern = r'Port(.*)Domain'
    domain_pattern = r'Domain(.*)Host'
    host_pattern = r'Host(.*)URI'
    uri_pattern = r'URI(.*)'
    policy_rule_filter_dict = read_yaml_file(policy_rule_filter_yaml).get('PolicyRuleFilter')
    prefix_list_dict = read_yaml_file(prefix_list_yaml).get('PrefixList')
    filter_base_dict = read_yaml_file(filter_base_yaml).get('FilterBase')
    entries_application_dict = dict()
    entries_used = set()
    rule_precedence_dict = create_rule_precedence_dict(policy_rule_yaml)
    filter_base_rule_dict = create_filter_base_rule_dict(policy_rule_yaml)
    app_filter_dict = dict()

    # app-filter from PREFIX-LISTS
    for key in prefix_list_dict:
        application = re.findall(application_pattern, key)[0]

        entry_number, entries_application_dict = calculate_entry_number(
            rule_precedence_dict=rule_precedence_dict,
            application=application,
            entries_used=entries_used,
            entries_application_dict=entries_application_dict)
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
        entry_number += 10
    # app-filter from FILTER_BASE
    for key in filter_base_dict:
        filter_dict = filter_base_dict.get(key)
        for filter_name in filter_dict:
            if not (filter_dict.get(filter_name).get('destination-address') or filter_dict.get(filter_name).get(
                    'ipv6-destination-address') or filter_dict.get(filter_name).get('source-address') or
                    filter_dict.get(filter_name).get('ipv6-source-address')):
                ip_protocol = filter_dict.get(filter_name).get('protocol-id')

                port = filter_dict.get(filter_name).get('destination-port-list')
                host = filter_dict.get(filter_name).get('host-name')
                uri = filter_dict.get(filter_name).get('l7-uri') if not filter_dict.get(filter_name).get('l7-uri',
                                                                                                         '0000').endswith(
                    ':') else None
                protocol = filter_dict.get(filter_name).get('l7-uri') if filter_dict.get(filter_name).get('l7-uri',
                                                                                                          '0000').endswith(
                    ':') else None
                domain = filter_dict.get(filter_name).get('domain-name')
                application = key
                entry_number, entries_application_dict = calculate_entry_number(
                    rule_precedence_dict=rule_precedence_dict,
                    application=application,
                    entries_used=entries_used,
                    entries_application_dict=entries_application_dict)
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

                entry_number += 10
    # app-filter from FILTERS
    for key in policy_rule_filter_dict:
        for filter_name in policy_rule_filter_dict.get(key):
            filter_dict = policy_rule_filter_dict.get(key).get(filter_name)
            if not (filter_dict.get('destination-address') or filter_dict.get(
                    'ipv6-destination-address') or filter_dict.get('source-address') or
                    filter_dict.get('ipv6-source-address')):
                ip_protocol = filter_dict.get('protocol-id')
                port = filter_dict.get('destination-port-list')
                host = filter_dict.get('host-name')
                uri = filter_dict.get('l7-uri') if not filter_dict.get('l7-uri', '0000').endswith(
                    ':') else None
                protocol = filter_dict.get('l7-uri') if filter_dict.get('l7-uri', '0000').endswith(
                    ':') else None
                domain = filter_dict.get('domain-name')
                application = key
                entry_number, entries_application_dict = calculate_entry_number(
                    rule_precedence_dict=rule_precedence_dict,
                    application=application,
                    entries_used=entries_used,
                    entries_application_dict=entries_application_dict)
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

                entry_number += 10

    return app_filter_dict


def main():
    app_filter_dict = create_app_filter_yaml(
        policy_rule_filter_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRuleFilter.yaml',
        prefix_list_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\prefix_list\PrefixList.yaml',
        policy_rule_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml',
        filter_base_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\FilterBase.yaml',
        dns_ip_cache_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\dns_ip_cache\DnsIpCache.yaml'
    )

    export_yaml(app_filter_dict)


if __name__ == "__main__":
    main()
