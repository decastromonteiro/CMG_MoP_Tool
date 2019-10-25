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
                if not policy_rule_domain_dict.get(filter_base_rule_dict.get(key)):
                    policy_rule_domain_dict.update(
                        {filter_base_rule_dict.get(key): [domain]}
                    )
                else:
                    if domain not in policy_rule_domain_dict.get(filter_base_rule_dict.get(key)):
                        policy_rule_domain_dict.get(filter_base_rule_dict.get(key)).append(
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
    export_yaml({'DefaultLayer3Layer7': policy_rule_domain_dict})



def main():
    create_dns_yaml(
        policy_rule_filter_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRuleFilter.yaml',
        policy_rule_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml',
        filter_base_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\FilterBase.yaml')


if __name__ == '__main__':
    main()
