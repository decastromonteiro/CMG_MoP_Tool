from utils.yaml import YAML
from utils.utils import chuncks, get_filter_base, get_filter
import os
import ipaddress
import re


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def export_yaml(lista, project_name='PrefixList'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({'PrefixList': lista})
    return path


def create_prefix_list_yaml(policy_rule_yaml, filter_base_yaml):
    filters = get_filter(policy_rule_yaml)
    filter_bases = get_filter_base(filter_base_yaml)
    if filters and filter_bases:
        filters.update(filter_bases)
        prefix_dict = filters
    elif filters:
        prefix_dict = filters
    else:
        prefix_dict = filter_bases
    arranged_prefix_dict_list = dict()
    prefix_name = '{policy_rule_name}_{prefix_id_count}_{list_count}'

    for policy_rule_name in prefix_dict:
        prefix_dict_list = prefix_dict.get(policy_rule_name)
        count = 1
        for prefix_id in prefix_dict_list:
            prefix_list = prefix_dict_list.get(prefix_id)
            split_lists = chuncks(prefix_list, 256)
            _count = 1
            for lista in split_lists:
                arranged_prefix_dict_list.update({prefix_name.format(
                    policy_rule_name=policy_rule_name, prefix_id_count=count, list_count=_count
                ): {prefix_id: lista}})
                _count += 1
            count += 1

    path = export_yaml(arranged_prefix_dict_list, project_name='PrefixList')
    return path


def create_prefix_list_mop(prefix_yaml_input, command_yaml_input):
    prefix_dict_list = read_yaml_file(prefix_yaml_input).get('PrefixList')
    provision_command_dict = read_yaml_file(command_yaml_input).get('commands').get('provision')
    command_list = list()

    for list_prefix_name in prefix_dict_list:
        prefix_id = prefix_dict_list.get(list_prefix_name)
        for key, value in prefix_id.items():
            command_list.extend([

                provision_command_dict.get('create').format(partition='1:1',
                                                            name=list_prefix_name),
                provision_command_dict.get('description').format(partition='1:1',
                                                                 name=list_prefix_name,
                                                                 description=key[2:])

            ])
            for item in value:
                if key.startswith('v4'):
                    command_list.append(provision_command_dict.get('add_prefix').format(
                        partition='1:1',
                        name=list_prefix_name,
                        ip=item if '/' in item else item + '/32',
                        prefix_name=''
                    ))
                else:
                    command_list.append(provision_command_dict.get('add_prefix').format(
                        partition='1:1',
                        name=list_prefix_name,
                        ip=item if '/' in item else item + '/128',
                        prefix_name=''
                    ))

    with open('mop_ip_prefix.txt', 'w') as fout:
        for command in command_list:
            fout.write(command + '\n')

    return os.path.abspath('mop_ip_prefix.txt')


def main():
    path = create_prefix_list_yaml(r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml',
                                   r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\FilterBase.yaml')

    create_prefix_list_mop(path,
                           r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\prefix_list_commands.yaml')


if __name__ == "__main__":
    main()
