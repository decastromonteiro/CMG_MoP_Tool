from utils.yaml import YAML


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


def aggregate_address(input_list):
    if input_list:
        aggregation_list = list()
        for dicts in input_list:
            for name in dicts:
                list_of_filters_dict = dicts.get(name)
                aggregate_addresses = dict()
                filter_base_aggregation = dict()
                for filter_dict in list_of_filters_dict:
                    for filter_name in filter_dict:
                        if filter_dict.get(filter_name).get('destination-address'):
                            address = filter_dict.get(filter_name).get('destination-address')
                            protocol = filter_dict.get(filter_name).get('protocol-id', '0000')
                            ports = filter_dict.get(filter_name).get('destination-port-list', '0000')
                            domain = filter_dict.get(filter_name).get('domain-name', '0000')
                            host = filter_dict.get(filter_name).get('host-name', '0000')
                            uri = filter_dict.get(filter_name).get('l7-uri', '0000')

                            aggregation_string = 'Protocol{}Port{}Domain{}Host{}URI{}'.format(protocol, ports,
                                                                                              domain, host,
                                                                                              uri)

                            if not aggregate_addresses.get(aggregation_string):
                                aggregate_addresses.update({aggregation_string: list()})
                            if address:
                                aggregate_addresses.get(aggregation_string).append(address)

                filter_base_aggregation.update({name: aggregate_addresses})
                aggregation_list.append(filter_base_aggregation)
        return aggregation_list


def arrange_prefix_lists(prefix_yaml_input):
    policy_rule_prefix_dict_list = read_yaml_file(prefix_yaml_input).get('PrefixList')

    arranged_prefix_dict_list = dict()

    for prefix_dict in policy_rule_prefix_dict_list:
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

    provision_command_list = read_yaml_file(command_yaml_input).get('commands').get('provision')

    command_list = list()

    for list_prefix_name in prefix_dict_list:
        lista = prefix_dict_list.get(list_prefix_name)
        command_list.extend([

            provision_command_list.get('create').format(partition='1:1',
                                                        name=list_prefix_name),
            provision_command_list.get('description').format(partition='1:1',
                                                             name=list_prefix_name,
                                                             description=lista.pop())

        ])
        for item in lista:
            command_list.append(provision_command_list.get('add_prefix').format(
                partition='1:1',
                name=list_prefix_name,
                ip=item if '/' in item else item + '/32',
                prefix_name=''
            ))

    with open('mop_ip_prefix.txt', 'w') as fout:
        for command in command_list:
            fout.write(command + '\n')


# a = get_filter('/home/decastromonteiro/PycharmProjects/CMG_MoP_Tool/parsers/output/PolicyRuleFilter.yaml')
# b = get_filter_base('/home/decastromonteiro/PycharmProjects/CMG_MoP_Tool/parsers/output/FilterBase.yaml')
#
# a.extend(b)
#
# export_yaml(a)

make_prefix_list_mop('/home/decastromonteiro/PycharmProjects/CMG_MoP_Tool/prefix_list/PrefixList.yaml',
                     '/home/decastromonteiro/PycharmProjects/CMG_MoP_Tool/templates/prefix_list_commands.yaml')
# lista = arrange_prefix_lists('/home/decastromonteiro/PycharmProjects/CMG_MoP_Tool/prefix_list/PrefixList.yaml')
