from utils.yaml import YAML
import re
import os


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def export_yaml(lista, project_name='PrefixList'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({'PrefixList': lista})
    return path


def get_filter_base(filter_base_yaml):
    filter_base_list = read_yaml_file(filter_base_yaml).get('FilterBase')
    return aggregate_address(filter_base_list)


def get_filter(filter_yaml):
    pr_filter_list = read_yaml_file(filter_yaml).get('PolicyRuleFilter')
    return aggregate_address(pr_filter_list)


def aggregate_address(input_dict):
    if input_dict:
        aggregation_list = dict()
        for key in input_dict:
            list_of_filters_dict = input_dict.get(key)
            aggregate_addresses = dict()
            filter_base_aggregation = dict()
            for filter_name in list_of_filters_dict:

                if list_of_filters_dict.get(filter_name).get('destination-address') or list_of_filters_dict.get(
                        filter_name).get('ipv6-destination-address'):
                    address = list_of_filters_dict.get(filter_name).get(
                        'destination-address') or list_of_filters_dict.get(
                        filter_name).get(
                        'ipv6-destination-address')
                    protocol = list_of_filters_dict.get(filter_name).get('protocol-id', '0000')
                    ports = list_of_filters_dict.get(filter_name).get('destination-port-list', '0000')
                    domain = list_of_filters_dict.get(filter_name).get('domain-name', '0000')
                    host = list_of_filters_dict.get(filter_name).get('host-name', '0000')
                    uri = list_of_filters_dict.get(filter_name).get('l7-uri', '0000')

                    aggregation_string = 'Protocol{}Port{}Domain{}Host{}URI{}'.format(protocol, ports,
                                                                                      domain, host,
                                                                                      uri)

                    if not aggregate_addresses.get(aggregation_string):
                        aggregate_addresses.update({aggregation_string: list()})
                    if address:
                        aggregate_addresses.get(aggregation_string).append(address)

            filter_base_aggregation.update({key: aggregate_addresses})
            aggregation_list.update(filter_base_aggregation)
        return aggregation_list


def arrange_prefix_lists(prefix_yaml_input):
    prefix_dict = read_yaml_file(prefix_yaml_input).get('PrefixList')

    arranged_prefix_dict_list = dict()

    for policy_rule_name in prefix_dict:
        prefix_dict_list = prefix_dict.get(policy_rule_name)
        count = 1
        for prefix_id in prefix_dict_list:
            prefix_name = policy_rule_name + '_{}'.format(count)
            prefix_list = prefix_dict_list.get(prefix_id)
            if len(prefix_list) <= 256:
                prefix_list.append(prefix_id)
                arranged_prefix_dict_list.update({prefix_name: prefix_list})
            else:
                ip_left = len(prefix_list) - 256
                first_prefix = prefix_list[:-ip_left]
                first_prefix.append(prefix_id)
                arranged_prefix_dict_list.update({prefix_name: first_prefix})
                count += 1
                prefix_name = policy_rule_name + '_{}'.format(count)
                last_prefix = prefix_list[-ip_left:]
                last_prefix.append(prefix_id)
                arranged_prefix_dict_list.update({prefix_name: last_prefix})

            count += 1
    return arranged_prefix_dict_list


def make_prefix_list_mop(prefix_yaml_input, command_yaml_input):
    prefix_dict_list = arrange_prefix_lists(prefix_yaml_input)

    provision_command_dict = read_yaml_file(command_yaml_input).get('commands').get('provision')

    command_list = list()

    for list_prefix_name in prefix_dict_list:
        lista = prefix_dict_list.get(list_prefix_name)
        command_list.extend([

            provision_command_dict.get('create').format(partition='1:1',
                                                        name=list_prefix_name),
            provision_command_dict.get('description').format(partition='1:1',
                                                             name=list_prefix_name,
                                                             description=lista.pop())

        ])
        for item in lista:
            command_list.append(provision_command_dict.get('add_prefix').format(
                partition='1:1',
                name=list_prefix_name,
                ip=item if '/' in item else item + '/32',
                prefix_name=''
            ))

    with open('mop_ip_prefix.txt', 'w') as fout:
        for command in command_list:
            fout.write(command + '\n')

    return os.path.abspath('mop_ip_prefix.txt')


def make_yaml_from_mop(mop_input):
    prefix_name_pattern = r'ip-prefix-list (.+) create'
    description_pattern = r'description (.+)'
    prefix_pattern = r'prefix (.+) name'
    with open(mop_input) as fin:
        ip_prefix_dict = dict()
        for line in fin:
            line = line.strip()
            if 'create' in line:
                prefix_name_match = re.findall(prefix_name_pattern, line)
                if prefix_name_match:
                    if not ip_prefix_dict.get(prefix_name_match[0]):
                        ip_prefix_dict.update({prefix_name_match[0]: dict()})

            if 'description' in line:
                description_match = re.findall(description_pattern, line)
                if description_match:
                    ip_prefix_dict.get(prefix_name_match[0]).update({description_match[0]: list()})

            if 'prefix' in line:
                prefix_match = re.findall(prefix_pattern, line)
                if prefix_match:
                    ip_prefix_dict.get(prefix_name_match[0]).get(description_match[0]).append(prefix_match[0])

    return export_yaml(ip_prefix_dict)


def main():
    filters = get_filter(r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\output\PolicyRuleFilter.yaml')
    filter_bases = get_filter_base(
        r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\output\FilterBase.yaml')
    filters.update(filter_bases)
    path = export_yaml(filters, project_name='PrePrefixList')

    mop_path = make_prefix_list_mop(path,
                                    r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\prefix_list_commands.yaml')

    make_yaml_from_mop(mop_path)


def main_oi():
    filters = get_filter(r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRuleFilter.yaml')

    path = export_yaml(filters, project_name='PrePrefixList')

    mop_path = make_prefix_list_mop(path,
                                    r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\prefix_list_commands.yaml')

    make_yaml_from_mop(mop_path)


if __name__ == "__main__":
    main()
