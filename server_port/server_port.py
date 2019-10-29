import os

from utils.yaml import YAML
import re


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def export_yaml(data, project_name='ServerPort'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({'ServerPort': data})
    return path


def create_port_list_yaml(policy_rule_filter_yaml, filter_base_yaml, prefix_list_yaml):
    policy_rule_filter_dict = read_yaml_file(policy_rule_filter_yaml).get('PolicyRuleFilter')
    prefix_list_dict = read_yaml_file(prefix_list_yaml).get('PrefixList')
    filter_base_dict = read_yaml_file(filter_base_yaml).get('FilterBase')
    port_list_dict = dict()
    port_list_set = list()

    port_pattern = r'Port(.*)Domain'

    for prefix_name in prefix_list_dict:
        for prefix_id in prefix_list_dict.get(prefix_name):
            port_string = re.findall(port_pattern, prefix_id)[0]
            if port_string:
                if ',' in port_string:
                    port_lst = sorted(port_string.split(','))
                    if port_lst not in port_list_set:
                        port_list_set.append(port_lst)

    for policy_rule in policy_rule_filter_dict:
        for filter_name in policy_rule_filter_dict.get(policy_rule):
            filter_dict = policy_rule_filter_dict.get(policy_rule).get(filter_name)
            port_string = filter_dict.get('destination-port-list')
            if port_string:
                if ',' in port_string:
                    port_lst = sorted(port_string.split(','))
                    if port_lst not in port_list_set:
                        port_list_set.append(port_lst)

    for key in filter_base_dict:
        filter_dict = filter_base_dict.get(key)
        for filter_name in filter_dict:
            port_string = filter_dict.get(filter_name).get('destination-port-list')
            if port_string:
                if ',' in port_string:
                    port_lst = sorted(port_string.split(','))
                    if port_lst not in port_list_set:
                        port_list_set.append(port_lst)

    count = 1
    for port_list in port_list_set:
        port_list_dict.update(
            {'PORT_LIST_{}'.format(count): {'description': ','.join(port_list),
                                            'ports': port_list}}
        )
        count += 1

    return export_yaml(port_list_dict)


def create_port_list_mop(server_port_yaml, port_list_commands_yaml):
    port_list_dict = read_yaml_file(server_port_yaml).get('ServerPort')
    provision_commands = read_yaml_file(port_list_commands_yaml).get('commands').get('provision')
    list_of_commands = list()
    for port_dict in port_list_dict:
        list_of_commands.append(provision_commands.get('create').format(
            partition='1:1', port_list=port_dict
        ))
        list_of_commands.append(provision_commands.get('description').format(
            partition='1:1', port_list=port_dict, description=port_list_dict.get(port_dict).get('description')
        ))
        for port in port_list_dict.get(port_dict).get('ports'):
            list_of_commands.append(provision_commands.get('add_port').format(
                partition='1:1', port_list=port_dict, port=port
            ))

    with open('mop_port_list.txt', 'w') as fout:
        for command in list_of_commands:
            fout.write(command)
            fout.write('\n')

    return os.path.abspath('mop_port_list.txt')


def main():
    path = create_port_list_yaml(
        policy_rule_filter_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRuleFilter.yaml',
        prefix_list_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\prefix_list\PrefixList.yaml',
        filter_base_yaml=r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\FilterBase.yaml'
    )

    create_port_list_mop(path, r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\port_list_commands.yaml')


if __name__ == "__main__":
    main()
