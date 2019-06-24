import yaml
from collections import OrderedDict
import re
from utils.yaml import YAML
import os


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def get_charging_rule_unit(policy_rule_yml):
    rg_sid_mk_set = set()
    d = read_yaml_file(policy_rule_yml)
    list_of_PRs = d.get('PolicyRule')

    for item in list_of_PRs:
        for PR in item:
            mk = item.get(PR).get('monitoring-key')
            rg = item.get(PR).get('rating-group')
            sid = item.get(PR).get('service-id')

            mk_string = 'MK{}'.format(mk) if mk != 'null' else ''
            rg_string = 'RG{}'.format(rg) if rg != 'null' else ''
            sid_string = 'SID{}'.format(sid) if sid != 'null' else ''

            final_string = rg_string + sid_string + mk_string
            if final_string not in rg_sid_mk_set:
                rg_sid_mk_set.add(final_string)

    rating_group_pattern = r'RG(\d+)'
    service_id_pattern = r'SID(\d+)'
    monitoring_key_pattern = r'MK(\d+)'
    lista = list()

    for cg in rg_sid_mk_set:
        d = OrderedDict()
        d['name'] = cg
        d['rating-group'] = int(re.findall(rating_group_pattern, cg)[0]) if re.findall(rating_group_pattern,
                                                                                       cg) else None
        d['service-id'] = int(re.findall(service_id_pattern, cg)[0]) if re.findall(service_id_pattern,
                                                                                   cg) else None
        d['monitoring-key'] = int(re.findall(monitoring_key_pattern, cg)[0]) if re.findall(monitoring_key_pattern,
                                                                                           cg) else None
        d['charging-method'] = 'both'
        d['metering-method'] = 'both'
        d['reporting-level'] = 'rating-group' if not re.findall(service_id_pattern, cg) else 'service-id'
        lista.append(d)
    return lista


def export_yaml(lista, project_name='ChargingRuleUnit'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({'ChargingRuleUnit': lista})
    return path


def create_charging_rule_unit_mop(yaml_cru, yaml_template):
    """
    Create a Method of Procedure for the ChargingRuleUnits specified in the yaml_cru file

    :param yaml_cru: The YAML file containing info from all ChargingRuleUnit
    :param yaml_template: The YAML file containing info from all commands necessary to execute ChargingRuleUnit
    creation and rollback
    :return: The path of the MoP recently created
    """

    configuration_commands = read_yaml_file(yaml_template).get('commands')

    provision_commands = configuration_commands.get('provision')
    rollback_commands = configuration_commands.get('rollback')

    list_of_mop_commands = list()
    list_of_mop_commands.append(provision_commands.get('begin'))
    list_of_charging_rule_units = read_yaml_file(yaml_cru).get('ChargingRuleUnit')
    for cru in list_of_charging_rule_units:
        list_of_mop_commands.append(provision_commands.get('name').format(
            name=cru.get('name')
        ))
        if cru.get('rating-group'):
            list_of_mop_commands.append(provision_commands.get('rating-group').format(
                name=cru.get('name'),
                rating_group=cru.get('rating-group')
            ))
        if cru.get('service-id'):
            list_of_mop_commands.append(provision_commands.get('service-id').format(
                name=cru.get('name'),
                service_id=cru.get('service-id')
            ))
        if cru.get('charging-method'):
            list_of_mop_commands.append(provision_commands.get('charging-method').format(
                name=cru.get('name'),
                charging_method=cru.get('charging-method')
            ))
        if cru.get('metering-method'):
            list_of_mop_commands.append(provision_commands.get('metering-method').format(
                name=cru.get('name'),
                metering_method=cru.get('metering-method')
            ))
        if cru.get('monitoring-key'):
            list_of_mop_commands.append(provision_commands.get('monitoring-key').format(
                name=cru.get('name'),
                monitoring_key=cru.get('monitoring-key')
            ))
        if cru.get('reporting-level'):
            list_of_mop_commands.append(provision_commands.get('reporting-level').format(
                name=cru.get('name'),
                reporting_level=cru.get('reporting-level')
            ))

    list_of_mop_commands.append(provision_commands.get('commit'))
    with open('charging_rule_unit_mop.txt', 'w') as fout:
        for command in list_of_mop_commands:
            fout.write(command)
            fout.write('\n')

    return os.path.abspath('charging_rule_unit_mop.txt')


yaml_cru = export_yaml(
    get_charging_rule_unit(r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\output\PolicyRule.yaml'))
yaml_template = os.path.abspath(
    r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\charging_rule_unit_commands.yaml')

create_charging_rule_unit_mop(yaml_cru, yaml_template)
