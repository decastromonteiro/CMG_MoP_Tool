import os

from utils.yaml import YAML
from utils.utils import export_mop_file


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def export_yaml(data, project_name='Application'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({'Application': data})
    return path


def get_policy_rule(policy_rule_yaml):
    policy_rule_list = list()
    policy_rule_dict_list = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    for policy_rule in policy_rule_dict_list:
        fb = policy_rule_dict_list.get(policy_rule).get('pcc-filter-base-name')
        if not fb or fb == 'null':
            policy_rule_list.append(policy_rule)
        else:
            if fb not in policy_rule_list:
                policy_rule_list.append(fb)

    return policy_rule_list


def create_application_yaml(policy_rule_yaml):
    return export_yaml(get_policy_rule(policy_rule_yaml))


def create_application_mop(application_yaml_input, command_yaml_input):
    application_list = read_yaml_file(application_yaml_input).get('Application')
    list_of_commands = list()

    provision_command_list = read_yaml_file(command_yaml_input).get('commands').get('provision')
    list_of_commands.append(provision_command_list.get('begin').format(partition='1:1'))
    for application in application_list:
        list_of_commands.extend(
            [provision_command_list.get('charging-group').format(partition='1:1', charging_group=application),

             provision_command_list.get('application').format(partition='1:1',
                                                              application=application),

             provision_command_list.get('combine_app_cg').format(partition='1:1',
                                                                 application=application,
                                                                 charging_group=application)])
    list_of_commands.append(
        provision_command_list.get('charging-group').format(partition='1:1', charging_group='default'))
    list_of_commands.append(
        provision_command_list.get('default_cg').format(partition='1:1', charging_group='default')
    )
    list_of_commands.append(provision_command_list.get('commit').format(partition='1:1'))

    return export_mop_file('aa_application_mop', list_of_commands)


def main():
    path = create_application_yaml(r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml')

    create_application_mop(path,
                           r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\application_commands.yaml')


if __name__ == "__main__":
    main()
