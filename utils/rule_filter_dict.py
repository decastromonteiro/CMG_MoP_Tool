from utils.yaml import YAML


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def create_rule_filter_dict(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    policy_rule_filters = dict()
    for policy_rule in policy_rule_dict:
        if policy_rule_dict.get(policy_rule).get('Filters'):
            policy_rule_filters.update({policy_rule: policy_rule_dict.get(policy_rule).get('Filters')})
    return policy_rule_filters
