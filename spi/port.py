from utils.yaml import read_yaml_file, export_yaml
from utils.utils import export_mop_file


def create_spi_port_list_yaml(filter_base_yaml):
    filter_base_dict = read_yaml_file(filter_base_yaml, 'FilterBase')
    port_list_dict = dict()
    port_list_set = list()
    for key in filter_base_dict.keys():
        if filter_base_dict.get(key).pop('SPI'):
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

    return export_yaml(port_list_dict, 'SPIPortList')


def create_spi_port_list_mop(port_list_yaml, port_list_commands_template):
    port_list_commands = read_yaml_file(port_list_commands_template, 'commands').get('provision')

    port_list_dict = read_yaml_file(port_list_yaml, 'SPIPortList')

    list_of_commands = list()
    for port_dict in port_list_dict:
        list_of_commands.append(port_list_commands.get('create').format(port_list=port_dict))
        for port in port_list_dict.get(port_dict).get('ports'):
            list_of_commands.append(port_list_commands.get('add_port').format(
                port_list=port_dict, port=port
            ))

    return export_mop_file('mop_port_list', list_of_commands)
