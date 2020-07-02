from utils.yaml import read_yaml_file, export_yaml
from utils.utils import export_mop_file, chuncks, get_filter, get_filter_base
import os


def create_addr_list_yaml(policy_rule_yaml, filter_base_yaml, minimum_ip_qnt=3):
    filters = get_filter(policy_rule_yaml, spi_mode=True)
    filter_bases = get_filter_base(filter_base_yaml, spi_mode=True)
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
            split_lists = list(chuncks(prefix_list, 100))
            _count = 1
            for lista in split_lists:
                if len(split_lists) == 1:
                    if len(lista) > minimum_ip_qnt:
                        arranged_prefix_dict_list.update({prefix_name.format(
                            policy_rule_name=policy_rule_name, prefix_id_count=count, list_count=_count
                        ): {prefix_id: lista}})
                        _count += 1
                elif len(split_lists) > 1:
                    arranged_prefix_dict_list.update({prefix_name.format(
                        policy_rule_name=policy_rule_name, prefix_id_count=count, list_count=_count
                    ): {prefix_id: lista}})
                    _count += 1
            count += 1

    return export_yaml(arranged_prefix_dict_list, project_name='AddrList')


def create_addr_list_mop(addr_list_yaml, addr_list_commands):
    addr_list_dict = read_yaml_file(addr_list_yaml, 'AddrList')

    addr_list_commands_dict = read_yaml_file(addr_list_commands, 'commands')

    addr_list_provision = addr_list_commands_dict.get('provision')

    list_of_commands = list()

    for addr_list_name in addr_list_dict:
        list_of_commands.append(addr_list_provision.get('create').format(addr_list_name=addr_list_name))
        for key in addr_list_dict.get(addr_list_name):
            addr_list = addr_list_dict.get(addr_list_name).get(key)
            for address in addr_list:
                list_of_commands.append(
                    addr_list_provision.get('add_prefix').format(addr_list_name=addr_list_name, prefix=address))

    return export_mop_file('mop_addr_list', list_of_commands)
