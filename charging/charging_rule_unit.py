import yaml
from collections import OrderedDict
import re
from utils.yaml import read_yaml_file, export_yaml
from utils.utils import export_mop_file
import os


def create_cru_string(policy_rule_dict, mk_to_ascii):
    mk = policy_rule_dict.get('monitoring-key')
    rg = policy_rule_dict.get('rating-group')
    sid = policy_rule_dict.get('service-id')
    method = policy_rule_dict.get('charging-method')

    mk_string = 'MK{:03}'.format(int(mk)) if (mk != 'null' and mk is not None) else ''
    if mk_to_ascii and mk_string != '':
        mk_string = 'MK' + str(bytes.fromhex(hex(int(mk_string[2:]))[2:]), "utf-8")
    rg_string = 'RG{:03}'.format(int(rg)) if (rg != 'null' and rg is not None) else ''
    sid_string = 'SID{:03}'.format(int(sid)) if (sid != 'null' and sid is not None) else ''
    method_string = 'CO' if method == 'offline' else 'PP'
    final_string = rg_string + sid_string + mk_string + '_{}'.format(method_string)
    if final_string == "_CO":
        final_string = "RG0_CO"
    elif final_string == "_PP":
        final_string = "RG0_PP"
    return final_string


def get_charging_rule_unit(policy_rule_yml, mk_to_ascii=True):
    rg_sid_mk_set = set()
    d = read_yaml_file(policy_rule_yml)
    item = d.get('PolicyRule')
    for PR in item:
        final_string = create_cru_string(item.get(PR), mk_to_ascii)
        if final_string not in rg_sid_mk_set:
            rg_sid_mk_set.add(final_string)

    rating_group_pattern = r'RG(\d+)'
    service_id_pattern = r'SID(\d+)'
    monitoring_key_pattern = r'MK(\d+)'
    charging_rule_dict = dict()

    for cg in rg_sid_mk_set:
        d = OrderedDict()
        charging_rule_dict.update(
            {cg: d}
        )
        d['rating-group'] = int(re.findall(rating_group_pattern, cg)[0]) if re.findall(rating_group_pattern,
                                                                                       cg) else None
        d['service-id'] = int(re.findall(service_id_pattern, cg)[0]) if re.findall(service_id_pattern,
                                                                                   cg) else None
        d['monitoring-key'] = int(re.findall(monitoring_key_pattern, cg)[0]) if re.findall(monitoring_key_pattern,
                                                                                           cg) else None
        d['charging-method'] = 'offline' if cg.endswith('CO') else 'both'
        d['metering-method'] = 'both'
        d['reporting-level'] = 'rating-group' if not re.findall(service_id_pattern, cg) else 'service-id'

    return charging_rule_dict


def create_charging_rule_unit_yaml(policy_rule_yaml, mk_to_ascii):
    return export_yaml(get_charging_rule_unit(policy_rule_yaml, mk_to_ascii), 'ChargingRuleUnit')


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
    cru_dict = read_yaml_file(yaml_cru).get('ChargingRuleUnit')
    for cru in cru_dict.keys():
        cru_parameters = cru_dict.get(cru)
        list_of_mop_commands.append(provision_commands.get('name').format(
            name=cru
        ))
        if cru_parameters.get('rating-group') and cru_parameters.get('rg-urr-id'):
            list_of_mop_commands.append(provision_commands.get('rating-group-sru').format(
                name=cru,
                rating_group=cru_parameters.get('rating-group'),
                sru=f'RG{cru_parameters.get("rg-urr-id"):03}'
            ))
        elif cru_parameters.get('rating-group'):
            list_of_mop_commands.append(provision_commands.get('rating-group').format(
                name=cru,
                rating_group=cru_parameters.get('rating-group')
            ))
        if cru_parameters.get('service-id') and cru_parameters.get('service-urr-id'):
            list_of_mop_commands.append(provision_commands.get('service-id-sru').format(
                name=cru,
                service_id=cru_parameters.get('service-id'),
                sru=cru
            ))
        elif cru_parameters.get('service-id'):
            list_of_mop_commands.append(provision_commands.get('service-id').format(
                name=cru,
                service_id=cru_parameters.get('service-id')
            ))
        if cru_parameters.get('charging-method'):
            list_of_mop_commands.append(provision_commands.get('charging-method').format(
                name=cru,
                charging_method=cru_parameters.get('charging-method')
            ))
        if cru_parameters.get('metering-method'):
            list_of_mop_commands.append(provision_commands.get('metering-method').format(
                name=cru,
                metering_method=cru_parameters.get('metering-method')
            ))
        if cru_parameters.get('monitoring-key'):
            list_of_mop_commands.append(provision_commands.get('monitoring-key').format(
                name=cru,
                monitoring_key=cru_parameters.get('monitoring-key')
            ))
        if cru_parameters.get('reporting-level'):
            list_of_mop_commands.append(provision_commands.get('reporting-level').format(
                name=cru,
                reporting_level=cru_parameters.get('reporting-level')
            ))

    list_of_mop_commands.append(provision_commands.get('commit'))

    return export_mop_file('charging_rule_unit_mop', list_of_mop_commands)


def main():
    # yaml_cru = create_charging_rule_unit_yaml(
    #     r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\BaseYAML\PolicyRule.yaml',
    #     mk_to_ascii=True)
    yaml_template = os.path.abspath(
        r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\templates\charging_rule_unit_commands.yaml')

    create_charging_rule_unit_mop(
        r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\cmgYAML\ChargingRuleUnit.yaml',
        yaml_template)


if __name__ == "__main__":
    main()
