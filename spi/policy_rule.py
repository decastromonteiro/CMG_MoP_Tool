from utils.yaml import read_yaml_file, export_yaml
from utils.utils import export_mop_file, flow_gate_status_dict
import os
import re


# todo: use addr list when IP has more than 3 flow-descriptions
def create_spi_policy_rule_unit_yaml(filter_base_yaml, policy_rule_yaml, unique_pru_yaml, port_list_yaml,
                                     addr_list_yaml, pdr_yaml):
    filter_base_dict = read_yaml_file(filter_base_yaml, 'FilterBase')
    policy_rule_dict = read_yaml_file(policy_rule_yaml, 'PolicyRule')
    unique_pru_dict = read_yaml_file(unique_pru_yaml, 'UniquePolicyRuleUnit')
    if pdr_yaml:
        pdr_dict = read_yaml_file(pdr_yaml, 'PDR')
    else:
        pdr_dict = None
    policy_rule_unit_dict = dict()
    used_filter_base = list()
    for policy_rule in policy_rule_dict.keys():
        filter_base = policy_rule_dict.get(policy_rule).get('pcc-filter-base-name')
        flow_gate_status = policy_rule_dict.get(policy_rule).get('pcc-rule-action')
        concat = f"{filter_base}{flow_gate_status}"
        if filter_base_dict.get(filter_base):
            if filter_base not in used_filter_base:
                used_filter_base.append(filter_base)
                if filter_base_dict.get(filter_base).pop('SPI'):
                    flow_description = create_flow_description(filter_base_dict.get(filter_base),
                                                               application=filter_base,
                                                               port_list_yaml=port_list_yaml,
                                                               addr_list_yaml=addr_list_yaml)
                    pru_name = f"SPI-{unique_pru_dict.get(concat)}"
                    policy_rule_unit_dict.update(
                        {pru_name: {
                            'flow-description': flow_description,
                            'flow-gate-status': flow_gate_status_dict.get(flow_gate_status, flow_gate_status)
                        }}
                    )
                    if pdr_dict:
                        pru_previous_name = unique_pru_dict.get(concat)
                        policy_rule_unit_dict[pru_name]['pdr-id'] = pdr_dict.get(pru_previous_name)
                    unique_pru_dict[concat] = pru_name

    export_yaml(unique_pru_dict, 'UniquePolicyRuleUnit', os.path.dirname(os.path.abspath(unique_pru_yaml)))
    return export_yaml(policy_rule_unit_dict, 'SPIPolicyRuleUnit')


def create_flow_description(filters_dict, application, port_list_yaml, addr_list_yaml):
    flow_description_count = 1
    reverse_port_list_dict = reverse_port_list(port_list_yaml)
    reverse_addr_list_dict = reverse_addr_list(addr_list_yaml)
    addr_list_dict = read_yaml_file(addr_list_yaml, 'AddrList')
    flow_description_dict = dict()
    used_fqdn_list = list()
    used_addr_list = list()
    description_pattern = re.compile(r"v\dProtocol(\S+)Port(\S+)Domain\S+Host\S+URI\S+")
    for filter_id in filters_dict:
        filter_parameters = filters_dict.get(filter_id)

        remote_ip = filter_parameters.get('destination-address')
        port_list_string = filter_parameters.get('destination-port-list')
        domain_name = filter_parameters.get('domain-name')
        if port_list_string:
            remote_port = port_list_string if ',' not in port_list_string else None
            remote_port_list = reverse_port_list_dict.get(','.join(sorted(port_list_string.split(','))))
        else:
            remote_port = None
            remote_port_list = None
        protocol = filter_parameters.get('protocol-id')
        if domain_name:
            if not application in used_fqdn_list:
                used_fqdn_list.append(application)
                flow_description_dict.update(
                    {flow_description_count: {
                        'remote-ip-list': None,
                        'remote-ip': remote_ip,
                        'remote-port': remote_port,
                        'remote-port-list': remote_port_list,
                        'protocol': protocol,
                        'dns-fqdn-list': application}}
                )
                flow_description_count += 1
        # todo: deal with ip addr list
        else:
            if reverse_addr_list_dict.get(application):
                for addr_list_name in reverse_addr_list_dict.get(application):
                    description = list(addr_list_dict.get(addr_list_name).keys())[0]
                    match = description_pattern.match(description)
                    if match.group(2) != '0000':
                        remote_port = match.group(2) if ',' not in match.group(2) else None
                        remote_port_list = reverse_port_list_dict.get(','.join(sorted(match.group(2).split(','))))
                    else:
                        remote_port = None
                        remote_port_list = None
                    protocol = match.group(1) if match.group(1) != '0000' else None
                    if not addr_list_name in used_addr_list:
                        used_addr_list.append(addr_list_name)
                        flow_description_dict.update(
                            {flow_description_count: {
                                'remote-ip-list': addr_list_name,
                                'remote-ip': None,
                                'remote-port': remote_port,
                                'remote-port-list': remote_port_list,
                                'protocol': protocol,
                                'dns-fqdn-list': None}}
                        )
                        flow_description_count += 1
            else:
                flow_description_dict.update(
                    {flow_description_count: {
                        'remote-ip-list': None,
                        'remote-ip': remote_ip,
                        'remote-port': remote_port,
                        'remote-port-list': remote_port_list,
                        'protocol': protocol,
                        'dns-fqdn-list': None}}
                )
                flow_description_count += 1
    return flow_description_dict


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


def create_spi_pru_mop(spi_pru_yaml, spi_pru_commands_yaml):
    spi_pru_dict = read_yaml_file(spi_pru_yaml, 'SPIPolicyRuleUnit')
    spi_pru_commands_dict = read_yaml_file(spi_pru_commands_yaml, 'commands')
    spi_pru_provision = spi_pru_commands_dict.get('provision')
    list_of_commands = list()
    for spi_pru in spi_pru_dict.keys():
        flow_gate_status = spi_pru_dict.get(spi_pru).get('flow-gate-status')
        pdr_id = spi_pru_dict.get(spi_pru).get('pdr-id')
        list_of_commands.append(
            spi_pru_provision.get('rule_unit_spi').format(policy_rule_unit=spi_pru)
        )
        list_of_commands.append(
            spi_pru_provision.get('flow-gate-status').format(policy_rule_unit=spi_pru,
                                                             flow_gate_status=flow_gate_status)
        )
        if pdr_id:
            list_of_commands.append(
                spi_pru_provision.get('rule_unit_pdrid').format(policy_rule_unit=spi_pru,
                                                                pdr_id=pdr_id)
            )
        flow_descriptions = spi_pru_dict.get(spi_pru).get('flow-description')
        for flow_id in flow_descriptions:
            flow_parameters = flow_descriptions.get(flow_id)
            if flow_parameters.get('dns-fqdn-list'):
                list_of_commands.append(
                    spi_pru_provision.get('rule_unit_dns').format(
                        policy_rule_unit=spi_pru,
                        flow_description_number=flow_id,
                        fqdn_list_name=flow_parameters.get('dns-fqdn-list')
                    ))
            if flow_parameters.get('protocol'):
                list_of_commands.append(
                    spi_pru_provision.get('rule_unit_protocol').format(
                        policy_rule_unit=spi_pru,
                        flow_description_number=flow_id,
                        protocol=flow_parameters.get('protocol')
                    ))
            if flow_parameters.get('remote-ip'):
                list_of_commands.append(
                    spi_pru_provision.get('rule_unit_ip').format(
                        policy_rule_unit=spi_pru,
                        flow_description_number=flow_id,
                        ip=flow_parameters.get('remote-ip')
                    ))
            if flow_parameters.get('remote-ip-list'):
                list_of_commands.append(
                    spi_pru_provision.get('rule_unit_addr_list').format(
                        policy_rule_unit=spi_pru,
                        flow_description_number=flow_id,
                        addr_list=flow_parameters.get('remote-ip-list')
                    ))
            if flow_parameters.get('remote-port'):
                list_of_commands.append(
                    spi_pru_provision.get('rule_unit_port').format(
                        policy_rule_unit=spi_pru,
                        flow_description_number=flow_id,
                        port=flow_parameters.get('remote-port')
                    ))
            if flow_parameters.get('remote-port-list'):
                list_of_commands.append(
                    spi_pru_provision.get('rule_unit_port_list').format(
                        policy_rule_unit=spi_pru,
                        flow_description_number=flow_id,
                        port_list=flow_parameters.get('remote-port-list')
                    ))

    return export_mop_file('mop_spi_rule_unit', list_of_commands)


def reverse_port_list(port_list_yaml):
    port_list_dict = read_yaml_file(port_list_yaml, 'SPIPortList')
    reverse_dict = dict()

    for key in port_list_dict:
        reverse_dict.update(
            {port_list_dict.get(key).get('description'): key}
        )

    return reverse_dict


def reverse_addr_list(addr_list_yaml):
    addr_list_dict = read_yaml_file(addr_list_yaml, 'AddrList')
    reverse_dict = dict()
    # '{policy_rule_name}_{prefix_id_count}_{list_count}'
    addr_list_pattern = re.compile(r'(\S+)_(\d+)_(\d+)')

    for addr_list in addr_list_dict:
        application = addr_list_pattern.match(addr_list).group(1)
        if reverse_dict.get(application):
            reverse_dict.get(application).append(addr_list)
        else:
            reverse_dict[application] = [addr_list]

    return reverse_dict
