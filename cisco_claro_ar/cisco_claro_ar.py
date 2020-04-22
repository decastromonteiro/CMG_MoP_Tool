from prefix_list.prefix_list import create_prefix_list_yaml
from utils.yaml import read_yaml_file, export_yaml
from utils.utils import check_spi_rule, export_mop_file
from charging.charging_rule_unit import create_cru_string
from server_port.server_port import create_port_list_yaml
import os


class CiscoClaroAr:
    def __init__(self, cisco_yaml_path, command_template_path, base_yaml_path):
        self.cisco_yaml_path = cisco_yaml_path
        self.templates = command_template_path
        self.base_yaml_path = base_yaml_path
        self.host_pool_path = os.path.join(self.cisco_yaml_path, 'HostPool.yaml')
        self.addr_list_template_path = os.path.join(self.templates, 'addr_list_commands.yaml')
        self.port_list_template_path = os.path.join(self.templates, 'spi_port_list.yaml')
        self.policy_rule_path = os.path.join(self.base_yaml_path, 'PolicyRule.yaml')
        self.filter_base_path = os.path.join(self.base_yaml_path, 'FilterBase.yaml')
        self.policy_rule_template_path = os.path.join(self.templates, 'policy_rule_commands.yaml')
        self.fqdn_list_template_path = os.path.join(self.templates, 'dns_sniffing_spi.yaml')
        self.rule_def_path = os.path.join(self.cisco_yaml_path, 'RuleDef.yaml')
        self.fqdn_list_path = os.path.join(self.cisco_yaml_path, 'FQDNList.yaml')

    def create_fqdn_list_cmg(self):
        provision_commands = read_yaml_file(self.fqdn_list_template_path, 'commands').get('provision')
        fqdn_dict = read_yaml_file(self.fqdn_list_path, 'FQDNList')

        list_of_commands = list()
        for fqdn_list in fqdn_dict:
            list_of_commands.extend(
                [provision_commands.get('add_domain').format(
                    fqdn_list_name=fqdn_list,
                    fqdn_name_id=i+1,
                    fqdn_name_string=fqdn
                ) for i, fqdn in enumerate(fqdn_dict.get(fqdn_list))]
            )

        export_mop_file('fqdn_list', list_of_commands)

    def create_addr_list_cmg(self):

        host_pool_dict = read_yaml_file(self.host_pool_path, 'HostPool')

        addr_list_dict = read_yaml_file(self.addr_list_template_path, 'commands')

        addr_list_provision = addr_list_dict.get('provision')

        list_of_commands = list()

        for host_pool in host_pool_dict:
            list_of_commands.append(addr_list_provision.get('create').format(addr_list_name=host_pool))
            for prefix in host_pool_dict.get(host_pool):
                list_of_commands.append(
                    addr_list_provision.get('add_prefix').format(addr_list_name=host_pool, prefix=prefix))

        return export_mop_file('mop_addr_list', list_of_commands)

    def create_port_list_mop(self):

        port_list_commands = read_yaml_file(self.port_list_template_path, 'commands').get('provision')

        port_list_dict = read_yaml_file(create_port_list_yaml(self.policy_rule_path,
                                                              self.filter_base_path,
                                                              create_prefix_list_yaml(
                                                                  policy_rule_yaml=self.policy_rule_path,
                                                                  filter_base_yaml=self.filter_base_path)
                                                              ), 'ServerPort')

        list_of_commands = list()
        for port_dict in port_list_dict:
            list_of_commands.append(port_list_commands.get('create').format(port_list=port_dict))
            for port in port_list_dict.get(port_dict).get('ports'):
                list_of_commands.append(port_list_commands.get('add_port').format(
                    port_list=port_dict, port=port
                ))

        return export_mop_file('mop_port_list', list_of_commands)

    def create_spi_rule_unit(self):
        flow_gate_status_dict = {'charge-v': 'allow', 'pass': 'allow', 'drop': 'drop', 'deny': 'drop'}

        policy_rule_dict = read_yaml_file(self.policy_rule_path, 'PolicyRule')

        filter_base_dict = check_spi_rule(self.filter_base_path)

        policy_rule_provision = read_yaml_file(self.policy_rule_template_path, 'commands').get('provision')

        reverse_port_list_dict = self.aux_port_list()

        list_of_commands = list()
        list_of_commands.append(policy_rule_provision.get('begin'))
        used_filter_base = set()
        used_fqdn_set = set()
        for pr in policy_rule_dict:
            filter_base_name = policy_rule_dict.get(pr).get('pcc-filter-base-name')
            header_enrichment = policy_rule_dict.get(pr).get('header-enrichment-type')
            flow_gate_status = policy_rule_dict.get(pr).get('pcc-rule-action')
            if header_enrichment:
                continue
            if filter_base_name not in used_filter_base:
                used_filter_base.add(filter_base_name)
                spi = filter_base_dict.get(filter_base_name).get('SPI')
                used_host_pool = set()
                if spi:
                    list_of_commands.append(
                        policy_rule_provision.get('rule_unit_spi').format(
                            policy_rule_unit='{}_{}'.format(filter_base_name, 'PRU')
                        )
                    )
                    flow_description_number = 1
                    for filter_name in filter_base_dict.get(filter_base_name):
                        if filter_name == 'SPI':
                            continue
                        filter_dict = filter_base_dict.get(filter_base_name).get(filter_name)
                        if filter_dict.get('host-pool') and filter_dict.get('destination-port-list'):
                            if not filter_dict.get('host-pool') in used_host_pool:
                                used_host_pool.add(filter_dict.get('host-pool'))
                                list_of_commands.append(
                                    policy_rule_provision.get('rule_unit_addr_list').format(
                                        policy_rule_unit='{}_{}'.format(filter_base_name, 'PRU'),
                                        flow_description_number=flow_description_number,
                                        addr_list=filter_dict.get('host-pool'),
                                    )
                                )
                                if len(filter_dict.get('destination-port-list').split()) > 1:
                                    list_of_commands.append(
                                        policy_rule_provision.get('rule_unit_port_list').format(
                                            policy_rule_unit='{}_{}'.format(filter_base_name, 'PRU'),
                                            flow_description_number=flow_description_number,
                                            port_list=reverse_port_list_dict.get(
                                                filter_dict.get('destination-port-list')),
                                        )
                                    )
                                else:
                                    list_of_commands.append(
                                        policy_rule_provision.get('rule_unit_port').format(
                                            policy_rule_unit='{}_{}'.format(filter_base_name, 'PRU'),
                                            flow_description_number=flow_description_number,
                                            port=filter_dict.get('destination-port-list'),
                                        )
                                    )
                                flow_description_number += 1
                        elif filter_dict.get('host-pool'):
                            if not filter_dict.get('host-pool') in used_host_pool:
                                used_host_pool.add(filter_dict.get('host-pool'))
                                list_of_commands.append(
                                    policy_rule_provision.get('rule_unit_addr_list').format(
                                        policy_rule_unit='{}_{}'.format(filter_base_name, 'PRU'),
                                        flow_description_number=flow_description_number,
                                        addr_list=filter_dict.get('host-pool'),
                                    )
                                )
                                flow_description_number += 1
                        elif filter_dict.get('destination-address') and filter_dict.get('destination-port-list'):

                            list_of_commands.append(
                                policy_rule_provision.get('rule_unit_ip').format(
                                    policy_rule_unit='{}_{}'.format(filter_base_name, 'PRU'),
                                    flow_description_number=flow_description_number,
                                    ip=filter_dict.get('destination-address'),
                                )
                            )
                            if len(filter_dict.get('destination-port-list').split()) > 1:
                                list_of_commands.append(
                                    policy_rule_provision.get('rule_unit_port_list').format(
                                        policy_rule_unit='{}_{}'.format(filter_base_name, 'PRU'),
                                        flow_description_number=flow_description_number,
                                        port_list=reverse_port_list_dict.get(
                                            filter_dict.get('destination-port-list'))
                                    )
                                )
                            else:
                                list_of_commands.append(
                                    policy_rule_provision.get('rule_unit_port').format(
                                        policy_rule_unit='{}_{}'.format(filter_base_name, 'PRU'),
                                        flow_description_number=flow_description_number,
                                        port=filter_dict.get('destination-port-list'),
                                    )
                                )
                            flow_description_number += 1
                        elif filter_dict.get('destination-address'):

                            list_of_commands.append(
                                policy_rule_provision.get('rule_unit_ip').format(
                                    policy_rule_unit='{}_{}'.format(filter_base_name, 'PRU'),
                                    flow_description_number=flow_description_number,
                                    ip=filter_dict.get('destination-address'),
                                )
                            )
                            flow_description_number += 1
                        elif filter_dict.get('domain-name'):
                            if filter_base_name not in used_fqdn_set:
                                used_fqdn_set.add(filter_base_name)
                                list_of_commands.append(
                                    policy_rule_provision.get('rule_unit_dns').format(
                                        policy_rule_unit='{}_{}'.format(filter_base_name, 'PRU'),
                                        flow_description_number=flow_description_number,
                                        fqdn_list_name=filter_base_name,
                                    )
                                )
                                flow_description_number += 1

                    list_of_commands.append(policy_rule_provision.get('flow-gate-status').format(
                        policy_rule_unit='{}_{}'.format(filter_base_name, 'PRU'),
                        flow_gate_status=flow_gate_status_dict.get(flow_gate_status, flow_gate_status)
                    ))
        list_of_commands.append(policy_rule_provision.get('commit'))

        return export_mop_file('mop_spi_rule_unit', list_of_commands)

    def create_spi_rule(self):
        policy_rule_path = os.path.join(self.base_yaml_path, 'PolicyRule.yaml')
        policy_rule_dict = read_yaml_file(policy_rule_path, 'PolicyRule')

        filter_base_dict = check_spi_rule(os.path.join(self.base_yaml_path, 'FilterBase.yaml'))

        policy_rule_template_path = os.path.join(self.templates, 'policy_rule_commands.yaml')
        policy_rule_provision = read_yaml_file(policy_rule_template_path, 'commands').get('provision')

        used_filter_bases = set()

        list_of_commands = list()
        list_of_commands.append(policy_rule_provision.get('begin'))
        for pr in list(policy_rule_dict):
            filter_base_name = policy_rule_dict.get(pr).get('pcc-filter-base-name')
            header_enrichment = policy_rule_dict.get(pr).get('header-enrichment-type')
            if header_enrichment:
                continue
            spi = filter_base_dict.get(filter_base_name).get('SPI')
            if spi:
                list_of_commands.append(
                    policy_rule_provision.get('rule').format(
                        policy_rule=pr,
                        rule_unit='{}_{}'.format(filter_base_name, 'PRU'),
                        charging_rule_unit=create_cru_string(policy_rule_dict.get(pr), mk_to_ascii=True),
                        precedence=policy_rule_dict.get(pr).get('precedence'),
                        action_rule_unit=''
                    )
                )
                used_filter_bases.add(filter_base_name)
                policy_rule_dict.pop(pr)

        for filter_base_name in used_filter_bases:
            filter_base_dict.pop(filter_base_name)

        for filter_base_name in filter_base_dict:
            filter_base_dict.get(filter_base_name).pop('SPI')
        export_yaml(filter_base_dict, 'FilterBase', self.base_yaml_path)

        list_of_commands.append(policy_rule_provision.get('commit'))
        export_yaml(policy_rule_dict, 'PolicyRule', self.base_yaml_path)

        return export_mop_file('mop_policy_rule_spi', list_of_commands)

    def aux_port_list(self):
        port_list_dict = read_yaml_file(create_port_list_yaml(os.path.join(self.base_yaml_path, 'PolicyRule.yaml'),
                                                              os.path.join(self.base_yaml_path, 'FilterBase.yaml'),
                                                              create_prefix_list_yaml(
                                                                  policy_rule_yaml=os.path.join(self.base_yaml_path,
                                                                                                'PolicyRule.yaml'),
                                                                  filter_base_yaml=os.path.join(self.base_yaml_path,
                                                                                                'FilterBase.yaml'))
                                                              ), 'ServerPort')
        reverse_dict = dict()

        for key in port_list_dict:
            reverse_dict.update(
                {port_list_dict.get(key).get('description'): key}
            )

        return reverse_dict


def main():
    claro = CiscoClaroAr(
        cisco_yaml_path=r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\CiscoYAML',
        command_template_path=r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\templates',
        base_yaml_path=r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\BaseYAML')

    claro.create_port_list_mop()
    claro.create_addr_list_cmg()
    claro.create_fqdn_list_cmg()
    claro.create_spi_rule_unit()
    claro.create_spi_rule()


if __name__ == "__main__":
    main()
