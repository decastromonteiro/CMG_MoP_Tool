import os

from utils.utils import create_rule_filter_dict, export_mop_file
from utils.yaml import read_yaml_file, export_yaml


def create_dns_yaml(policy_rule_yaml, filter_base_yaml, spid):
    """
    :param policy_rule_yaml:
    :param filter_base_yaml:
    :param spid: SPI for domain-names
    :return:
    """
    policy_rule_domain_dict = dict()
    policy_rule_filter_dict = create_rule_filter_dict(policy_rule_yaml)
    filter_base_dict = read_yaml_file(filter_base_yaml).get('FilterBase')

    for key in filter_base_dict:
        filter_dict = filter_base_dict.get(key)
        if spid and filter_base_dict.get(key).pop('SPI'):
            continue
        for filter_name in filter_dict:
            domain = filter_dict.get(filter_name).get('domain-name')
            if domain:
                if not policy_rule_domain_dict.get(key):
                    policy_rule_domain_dict.update(
                        {key: [domain]}
                    )
                else:
                    if domain not in policy_rule_domain_dict.get(key):
                        policy_rule_domain_dict.get(key).append(
                            domain
                        )
    for key in policy_rule_filter_dict:
        for filter_name in policy_rule_filter_dict.get(key):
            filter_dict = policy_rule_filter_dict.get(key).get(filter_name)
            domain = filter_dict.get('domain-name')
            if domain:
                if not policy_rule_domain_dict.get(key):
                    policy_rule_domain_dict.update(
                        {key: [domain]}
                    )
                else:
                    if domain not in policy_rule_domain_dict.get(key):
                        policy_rule_domain_dict.get(key).append(
                            domain
                        )
    return export_yaml({'DefaultLayer3Layer7': {'ip-cache-size': 64000, 'domains': policy_rule_domain_dict}},
                       'DnsIpCache')


def create_dns_mop(dns_entries_yaml, dns_commands_yaml):
    dns_ip_cache_dict = read_yaml_file(dns_entries_yaml).get('DnsIpCache')
    provision_commands = read_yaml_file(dns_commands_yaml).get('commands').get('provision')
    commands_list = list()
    used_domains = set()
    aqp_entry = 11000
    for dns_ip_cache in dns_ip_cache_dict:
        ip_cache_size = dns_ip_cache_dict.get(dns_ip_cache).get('ip-cache-size')
        rule_domain = dns_ip_cache_dict.get(dns_ip_cache).get('domains')
        commands_list.append(
            provision_commands.get('create').format(name=dns_ip_cache)
        )
        commands_list.append(provision_commands.get('ip-cache-size').format(name=dns_ip_cache,
                                                                            ip_cache_size=ip_cache_size)
                             )
        for rule in rule_domain:
            domain_list = rule_domain.get(rule)
            count = 1
            for domain in domain_list:
                if domain not in used_domains:
                    used_domains.add(domain)
                    if not domain.startswith('*'):
                        domain = '^' + domain
                    if not domain.endswith('*'):
                        domain = domain + '$'

                    commands_list.append(provision_commands.get('add_domain').format(
                        name=dns_ip_cache, pr_name=rule + '_{}'.format(count), domain_name=domain
                    ))
                count += 1
        commands_list.append(provision_commands.get('no_shutdown').format(
            name=dns_ip_cache
        ))

        if rule_domain:
            commands_list.extend([provision_commands.get('aqp-begin').format(partition='1:1'),
                                  provision_commands.get('aqp-create').format(partition='1:1', entry=aqp_entry),
                                  provision_commands.get('aqp-add-dns').format(partition='1:1', entry=aqp_entry,
                                                                               dns_ip_cache=dns_ip_cache),
                                  provision_commands.get('aqp-commit').format(partition='1:1')])
            aqp_entry += 10

    return export_mop_file('aa_dns_ip_cache_mop', commands_list)


def main():
    pass


if __name__ == '__main__':
    main()
