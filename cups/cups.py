from utils.yaml import read_yaml_file, export_yaml
from utils.utils import export_mop_file
import re
import os


# A CRU is only configured in the CP function (SMF).
# The same RG must not be mapped to different URR IDs (via SRU association).
# For SRU/URR-ID linking in a CRU:
# if reporting is at the RG level, configure the URR ID at the RG.
# if reporting is at the service ID level, configure the URR ID at RG and service ID,
# only if charging is both online and offline; in this case, separate stat-objects are required
# for online to report at the RG level and for offline to report at the RG and service ID level

# For the UP function, the PRU command policy-rule-unit and an SRU list must be configured;
# the URR ID value configured for the SRU associated with the SRU list must be the same for the following rules:
# pre-defined rules associated with the same RG for RG-level reporting
# pre-defined rules associated with the same RG and service identifier for service ID level reporting
# pre-defined rules associated with the same RG, sponsor ID and ASP ID for sponsor-connectivity level reporting
# pre-defined rules associated with the same usage monitoring key

def create_pdr_id(unique_policy_rule_yaml):
    unique_pru_dict = read_yaml_file(unique_policy_rule_yaml, 'UniquePolicyRuleUnit')
    pru_pdr_dict = dict()
    count = 1
    for pru in unique_pru_dict:
        pru_pdr_dict.update(
            {unique_pru_dict.get(pru): count}
        )
        count += 1
    return export_yaml(pru_pdr_dict, 'PDR')


def create_stat_rule_unit_yaml(charging_rule_path):
    """
    Create sru on the Charging-Rule-Unit YAML file
    :param charging_rule_path: Absolute Path to CRU YAML File
    :return: Absolute Path to CRU YAML File
    """
    urrid_limit = 30000
    urr_id_dict = dict()
    used_urr_id = list()

    cru_dict = read_yaml_file(charging_rule_path, 'ChargingRuleUnit')
    increment = max([d.get('rating-group') for cru, d in cru_dict.items()])
    for cru in cru_dict.keys():
        cru_parameters = cru_dict.get(cru)
        service_id, rating_group = cru_parameters.get('service-id'), cru_parameters.get('rating-group')
        rg_urr_id = rating_group
        cru_parameters['rg-urr-id'] = rg_urr_id
        urr_id_dict[f'RG{rating_group:03}'] = int(rating_group)

        if cru_parameters.get('charging-method') == 'both':
            if cru_parameters.get('reporting-level') == 'service-id':
                service_urr_id = int(service_id) + int(rating_group)
                if service_urr_id > urrid_limit:
                    service_urr_id = used_urr_id[-1] + increment if used_urr_id else increment
                    used_urr_id.append(service_urr_id)
                if not urr_id_dict.get(cru):
                    cru_parameters['service-urr-id'] = service_urr_id
                    urr_id_dict[cru] = service_urr_id
                else:
                    cru_parameters['service-urr-id'] = urr_id_dict[cru]

    export_yaml(cru_dict, 'ChargingRuleUnit', os.path.dirname(charging_rule_path))
    return export_yaml(urr_id_dict, 'SRU', os.path.dirname(charging_rule_path))


def create_sru_list_yaml(sru_path):
    urrid_dict = read_yaml_file(sru_path, 'SRU')
    sru_dict = dict()
    rg_pattern = r'RG(\d+)'
    for sru in urrid_dict.keys():
        rg = re.match(rg_pattern, sru).group(1)
        if sru_dict.get(int(rg)):
            sru_dict.get(int(rg)).append(sru)
        else:
            sru_dict.update(
                {int(rg): [sru]}
            )

    return export_yaml(sru_dict, 'SRUList', os.path.dirname(sru_path))


def create_sru_list_mop(sru_list_path, configuration_template):
    configuration_commands = read_yaml_file(configuration_template).get('commands')
    provision_commands = configuration_commands.get('provision')

    sru_list_dict = read_yaml_file(sru_list_path, 'SRUList')
    command_list = list()
    command_list.append(
        provision_commands.get('begin')
    )
    for sru_list in sru_list_dict.keys():
        command_list.extend(
            [provision_commands.get('add_sru').format(sru_list=sru_list, sru=sru) for sru in
             sru_list_dict.get(sru_list)]
        )
    command_list.append(
        provision_commands.get('commit')
    )

    return export_mop_file('upf_sru_list_mop', command_list)


def create_sru_mop(urrid_path, configuration_template):
    urrid_dict = read_yaml_file(urrid_path, 'SRU')
    configuration_commands = read_yaml_file(configuration_template).get('commands')
    provision_commands = configuration_commands.get('provision')
    command_list = list()
    command_list.append(
        provision_commands.get('begin')
    )
    for sru in urrid_dict.keys():
        command_list.append(provision_commands.get('create').format(
            sru=sru,
            urrid=urrid_dict.get(sru)
        )
        )
    command_list.append(
        provision_commands.get('commit')
    )
    return export_mop_file('sru_urrid_mop', command_list)


if __name__ == "__main__":
    # convert_policy_rule_unit(
    # r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\cmgYAML\PolicyRuleUnit.yaml')
    create_stat_rule_unit_yaml(
        r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\cmgYAML\ChargingRuleUnit.yaml'
    )
    create_sru_list_yaml(
        r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\cmgYAML\SRU.yaml')
    create_sru_list_mop(
        r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\cmgYAML\SRUList.yaml',
        r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\templates\sru_list.yaml'
    )
    create_sru_mop(
        r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\cmgYAML\SRU.yaml',
        r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\templates\sru.yaml'
    )
