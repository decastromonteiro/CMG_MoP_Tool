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


def export_application(lista, project_name='Application'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({project_name: lista})
    return path


def make_application_mop(application_yaml_input, command_yaml_input):
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

    list_of_commands.append(provision_command_list.get('commit').format(partition='1:1'))

    with open('mop_application.txt', 'w') as fout:
        for command in list_of_commands:
            fout.write(command + '\n')


lista = get_policy_rule(r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\output\PolicyRule.yaml')

application_yaml_input = export_application(lista)

make_application_mop(application_yaml_input,
                     r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\application_commands.yaml')
