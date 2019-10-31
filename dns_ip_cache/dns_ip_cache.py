import os

from utils.yaml import YAML
from app_filter.app_filter import create_filter_base_rule_dict


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def export_yaml(data, project_name='DnsIpCache'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({'DnsIpCache': data})
    return path


def create_dns_yaml(policy_rule_filter_yaml, policy_rule_yaml, filter_base_yaml):
    policy_rule_domain_dict = dict()
    policy_rule_filter_dict = read_yaml_file(policy_rule_filter_yaml).get('PolicyRuleFilter')
    filter_base_dict = read_yaml_file(filter_base_yaml).get('FilterBase')
    filter_base_rule_dict = create_filter_base_rule_dict(policy_rule_yaml)

    for key in filter_base_dict:
        filter_dict = filter_base_dict.get(key)
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
    return export_yaml({'DefaultLayer3Layer7': {'ip-cache-size': 64000, 'domains': policy_rule_domain_dict}})


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
    with open('mop_dns_ip_cache.txt', 'w') as fout:
        for command in commands_list:
            fout.write(command)
            fout.write('\n')

    return os.path.abspath('mop_dns_ip_cache.txt')


def main():
    path = create_dns_yaml(
        policy_rule_filter_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRuleFilter.yaml',
        policy_rule_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml',
        filter_base_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\FilterBase.yaml')

    create_dns_mop(path, r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\dns_ip_cache_commands.yaml')


if __name__ == '__main__':
    main()
