from utils.yaml import YAML


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def get_policy_rule(filter_base_yaml):
    policy_rule_list = list()
    policy_rule_dict_list = read_yaml_file(filter_base_yaml).get('PolicyRule')
    for policy_rule in policy_rule_dict_list:
        for name in policy_rule:
            policy_rule_list.append(name)

    return policy_rule_list


def export_aa_charging_group(lista, project_name='ChargingGroup'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({project_name: lista})
    return path


def make_application_mop(application_yaml_input, command_yaml_input):
    pass


lista = get_policy_rule('/home/decastromonteiro/PycharmProjects/CMG_MoP_Tool/parsers/output/PolicyRule.yaml')

export_aa_charging_group(lista)
