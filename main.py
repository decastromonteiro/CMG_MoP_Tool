from app_filter.app_filter import create_app_filter_yaml, create_app_filter_mop
from application.application import create_application_yaml, create_application_mop
from charging.charging_rule_unit import create_charging_rule_unit_yaml, create_charging_rule_unit_mop
from dns_ip_cache.dns_ip_cache import create_dns_yaml, create_dns_mop
from header_enrichment.header_enrichment import create_he_template_yaml, create_header_enrichment_yaml, \
    create_header_enrichment_mop, create_he_template_yaml_cisco, create_header_enrichment_yaml_cisco, \
    create_he_aqp_mop_cisco, create_he_template_mop_cisco
from parsers.fng_parser import *
from policy_rule.policy_rule import create_policy_rule_unit_yaml, create_policy_rule_yaml, \
    create_policy_rule_unit_mop, create_policy_rule_mop, create_policy_rule_base_mop, create_policy_rule_base_yaml, \
    create_policy_rule_upf_mop
from prefix_list.prefix_list import create_prefix_list_yaml, create_prefix_list_mop
from server_port.server_port import create_port_list_yaml, create_port_list_mop
from utils.utils import check_spi_rule, create_unique_pru, check_name_length, check_spi_rule_filters
from parsers import tmo_cisco_parser as cisco
from redirect.http_redirect import create_http_redirect_mop, create_redirect_aqp_yaml, create_aqp_http_redirect_mop, \
    create_redirect_yaml, create_rule_redirect_dict
from cups.cups import create_pdr_id, create_stat_rule_unit_yaml, create_sru_list_yaml, create_sru_mop, \
    create_sru_list_mop
from spi.dns import create_dns_snoop_yaml, create_dns_snoop_mop
from spi.port import create_spi_port_list_yaml, create_spi_port_list_mop
from spi.policy_rule import create_spi_policy_rule_unit_yaml, create_spi_pru_mop
from spi.ip_address_list import create_addr_list_yaml, create_addr_list_mop
import argparse
import os


def create_yaml_from_fng(fng_inputs_dir, spid, spip, rule_conersion_dict):
    list_of_files = os.listdir(fng_inputs_dir)
    if not list_of_files:
        raise FileNotFoundError('Directory {} is Empty'.format(fng_inputs_dir))
    if not 'fng_filters' in list_of_files:
        raise FileNotFoundError("Couldn't find fng_filters file in {} directory".format(fng_inputs_dir))
    if not 'fng_filter_base' in list_of_files:
        raise FileNotFoundError("Couldn't find fng_filter_base file in {} directory".format(fng_inputs_dir))
    if not 'fng_policy_rule' in list_of_files:
        raise FileNotFoundError("Couldn't find fng_policy_rule file in {} directory".format(fng_inputs_dir))
    if not 'fng_policy_rule_base' in list_of_files:
        raise FileNotFoundError("Couldn't find fng_policy_rule_base file in {} directory".format(fng_inputs_dir))
    if not 'fng_qos' in list_of_files:
        raise FileNotFoundError("Couldn't find fng_qos file in {} directory".format(fng_inputs_dir))
    if len(list_of_files) != len(set(list_of_files)):
        raise FileExistsError(
            "Inputs are duplicated, please check the Directory and make sure only one input of each exists")

    fng_filter_base = os.path.join(fng_inputs_dir, 'fng_filter_base')
    fng_filters = os.path.join(fng_inputs_dir, 'fng_filters')
    pcc_rule = os.path.join(fng_inputs_dir, 'fng_policy_rule')
    pcc_rule_base = os.path.join(fng_inputs_dir, 'fng_policy_rule_base')
    qos_profile = os.path.join(fng_inputs_dir, 'fng_qos')

    if not os.path.exists(os.path.join(os.getcwd(), 'BaseYAML')):
        os.makedirs(os.path.join(os.getcwd(), 'BaseYAML'))

    os.chdir(os.path.join(os.getcwd(), 'BaseYAML'))
    filter_base = parse_filter_base(fng_filter_base)
    pcc_rules = parse_pcc_rule(pcc_rule, fng_filters, rule_conersion_dict)
    pcc_rule_bases = parse_pcc_rule_base(pcc_rule_base, rule_conersion_dict)
    qos_profiles = parse_qos_profiles(qos_profile)

    filter_base_yaml = check_spi_rule(filter_base_yaml=filter_base,
                                      policy_rule_yaml=pcc_rules,
                                      domain_name=spid, ip_address=spip)

    policy_rule_yaml = check_spi_rule_filters(policy_rule_yaml=pcc_rules, domain_name=spid, ip_address=spip)

    return {
        'FilterBaseYAML': filter_base_yaml,
        'PolicyRuleYAML': policy_rule_yaml,
        'PolicyRuleBaseYAML': pcc_rule_bases,
        'QoSYAML': qos_profiles
    }


def create_yaml_from_cisco(cisco_input_dir, spid, spip):
    list_of_files = os.listdir(cisco_input_dir)
    if not len(list_of_files):
        raise FileNotFoundError(
            "The directory path you've passed is EMPTY."
        )
    if len(list_of_files) > 1:
        raise FileExistsError(
            "Inputs are duplicated, please check the Directory and make sure only one input of each exists")

    cisco_input = os.path.join(cisco_input_dir, list_of_files[0])

    if not os.path.exists(os.path.join(os.getcwd(), 'BaseYAML')):
        os.makedirs(os.path.join(os.getcwd(), 'BaseYAML'))

    if not os.path.exists(os.path.join(os.getcwd(), 'CiscoYAML')):
        os.makedirs(os.path.join(os.getcwd(), 'CiscoYAML'))

    if not os.path.exists(os.path.join(os.getcwd(), 'RawCiscoYAML')):
        os.makedirs(os.path.join(os.getcwd(), 'RawCiscoYAML'))

    os.chdir(os.path.join(os.getcwd(), 'RawCiscoYAML'))
    raw_charging_action_path = cisco.get_context_config(cisco_input, 'charging-action', '#exit', 'RawChargingAction')
    raw_ruledef_path = cisco.get_context_config(cisco_input, 'ruledef', '#exit', 'RawRuleDef')
    raw_host_pool_path = cisco.get_context_config(cisco_input, 'host-pool', '#exit', 'RawHostPool')
    raw_rulebase_path = cisco.get_context_config(cisco_input, 'rulebase', '#exit', 'RawRuleBase',
                                                 exclusion='rulebase = ')
    raw_group_of_ruledef_path = cisco.get_context_config(cisco_input, 'group-of-ruledefs', '#exit',
                                                         'RawGroupofRuleDef')
    raw_he_template_path = cisco.get_context_config(cisco_input, 'xheader-format', '#exit', 'RawHETemplate')

    os.chdir("..")
    os.chdir(os.path.join(os.getcwd(), 'CiscoYAML'))
    host_pool_path = cisco.parse_raw_host_pool(raw_host_pool_path)
    ruledef_path = cisco.parse_raw_ruledef(raw_ruledef_path, host_pool_path)
    group_of_ruledef_path = cisco.parse_raw_group_of_ruledef(raw_group_of_ruledef_path)
    parsed_rulebase_path = cisco.parse_raw_rulebase(raw_rulebase_path, group_of_ruledef_path)
    he_template_path = cisco.parse_raw_he_template(raw_he_template_path)
    charging_action_path = cisco.parse_raw_charging_action(raw_charging_action_path)
    unique_template = cisco.make_unique_template(charging_action_path)
    unique_policy_rule_path = cisco.create_unique_policy_rules(parsed_rulebase_path)

    os.chdir("..")
    os.chdir(os.path.join(os.getcwd(), 'BaseYAML'))
    policy_rule_base_path = cisco.create_policy_rule_base_yaml(parsed_rulebase_path, unique_policy_rule_path)
    qos_yaml = cisco.create_qos_yaml(charging_action_path)
    policy_rule_yaml = cisco.create_policy_rule_yaml(parsed_rulebase_path, charging_action_path,
                                                     unique_policy_rule_path,
                                                     unique_template)
    filter_base_yaml = cisco.create_filterbase_yaml(ruledef_path)
    filter_base_yaml = check_spi_rule(filter_base_yaml=filter_base_yaml,
                                      policy_rule_yaml=policy_rule_yaml,
                                      domain_name=spid, ip_address=spip)

    return {"RawCiscoYAML": os.path.abspath(os.path.dirname(raw_charging_action_path)),
            "CiscoYAML": os.path.abspath(os.path.dirname(host_pool_path)),
            "BaseYAML": os.path.abspath(os.path.dirname(qos_yaml))
            }


def create_yaml_for_cmg(base_yaml_dir, mk_to_ascii, cups, spid, spip, cisco_he, cisco_yaml_dir='CiscoYAML'):
    list_of_files = os.listdir(base_yaml_dir)
    if not list_of_files:
        raise FileNotFoundError('Directory {} is Empty'.format(base_yaml_dir))
    if 'FilterBase.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find FilterBase YAML file in {} directory".format(base_yaml_dir))
    if 'PolicyRule.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find PolicyRule YAML file in {} directory".format(base_yaml_dir))
    if 'PolicyRuleBase.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find PolicyRuleBase YAML file in {} directory".format(base_yaml_dir))
    if 'QoSProfiles.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find QoSProfiles YAML file in {} directory".format(base_yaml_dir))

    if len(list_of_files) != len(set(list_of_files)):
        raise FileExistsError(
            "Inputs are duplicated, please check the Directory and make sure only one input of each exists")

    if not os.path.exists(os.path.join(os.getcwd(), 'cmgYAML')):
        os.makedirs(os.path.join(os.getcwd(), 'cmgYAML'))

    os.chdir(os.path.join(os.getcwd(), 'cmgYAML'))
    output_dict = dict()

    filter_base_yaml = os.path.join(base_yaml_dir, 'FilterBase.yaml')
    policy_rule_yaml = os.path.join(base_yaml_dir, 'PolicyRule.yaml')
    policy_rule_base_yaml = os.path.join(base_yaml_dir, 'PolicyRuleBase.yaml')
    qos_profile_yaml = os.path.join(base_yaml_dir, 'QoSProfiles.yaml')

    application_yaml = create_application_yaml(policy_rule_yaml=policy_rule_yaml)
    charging_yaml = create_charging_rule_unit_yaml(policy_rule_yaml=policy_rule_yaml, mk_to_ascii=mk_to_ascii)
    prefix_yaml = create_prefix_list_yaml(policy_rule_yaml=policy_rule_yaml, filter_base_yaml=filter_base_yaml,
                                          spip=spip)
    dns_ip_cache_yaml = create_dns_yaml(policy_rule_yaml=policy_rule_yaml,
                                        filter_base_yaml=filter_base_yaml,
                                        spid=spid)

    server_port_yaml = create_port_list_yaml(policy_rule_yaml=policy_rule_yaml, filter_base_yaml=filter_base_yaml,
                                             prefix_list_yaml=prefix_yaml)
    app_filter_yaml = create_app_filter_yaml(dns_ip_cache_yaml=dns_ip_cache_yaml,
                                             prefix_list_yaml=prefix_yaml, server_port_yaml=server_port_yaml,
                                             filter_base_yaml=filter_base_yaml, policy_rule_yaml=policy_rule_yaml)
    unique_pru_yaml = create_unique_pru(policy_rule_yaml=policy_rule_yaml)

    if cups:
        pdr_yaml = create_pdr_id(unique_policy_rule_yaml=unique_pru_yaml)
        sru_yaml = create_stat_rule_unit_yaml(charging_yaml)
        sru_list_yaml = create_sru_list_yaml(sru_yaml)
        output_dict['SRU'] = sru_yaml
        # check_name_length(yaml_input=sru_yaml, object_name='SRU', max_len=32)
        output_dict['SRU List'] = sru_list_yaml
        # check_name_length(yaml_input=sru_list_yaml, object_name='SRUList', max_len=32)
        output_dict['PDR'] = pdr_yaml

    else:
        pdr_yaml = None
    if spid or spip:
        spi_port_list_yaml = create_spi_port_list_yaml(filter_base_yaml=filter_base_yaml)
        dns_snoop_yaml = create_dns_snoop_yaml(filter_base_yaml=filter_base_yaml)
        addr_list_yaml = create_addr_list_yaml(filter_base_yaml=filter_base_yaml, policy_rule_yaml=policy_rule_yaml)
        spi_pru_yaml = create_spi_policy_rule_unit_yaml(filter_base_yaml=filter_base_yaml,
                                                        policy_rule_yaml=policy_rule_yaml,
                                                        unique_pru_yaml=unique_pru_yaml,
                                                        port_list_yaml=spi_port_list_yaml,
                                                        addr_list_yaml=addr_list_yaml,
                                                        pdr_yaml=pdr_yaml)
        output_dict['SPIPortList'] = spi_port_list_yaml
        output_dict['FQDNList'] = dns_snoop_yaml
        check_name_length(yaml_input=dns_snoop_yaml, object_name='FQDNList', max_len=32)
        output_dict['SPIPolicyRuleUnit'] = spi_pru_yaml
        check_name_length(yaml_input=spi_pru_yaml, object_name='SPIPolicyRuleUnit', max_len=32)
        output_dict['AddrList'] = addr_list_yaml
        check_name_length(yaml_input=addr_list_yaml, object_name='AddrList', max_len=32)
    else:
        spi_pru_yaml = None

    policy_rule_unit_yaml = create_policy_rule_unit_yaml(policy_rule_yaml=policy_rule_yaml,
                                                         unique_pru_yaml=unique_pru_yaml,
                                                         pdr_yaml=pdr_yaml)
    cmg_policy_rule_yaml = create_policy_rule_yaml(policy_rule_yaml=policy_rule_yaml, mk_to_ascii=mk_to_ascii,
                                                   unique_pru_yaml=unique_pru_yaml)
    cmg_policy_rule_base_yaml = create_policy_rule_base_yaml(policy_rule_base_yaml=policy_rule_base_yaml)
    http_redirect_yaml = create_redirect_yaml(create_rule_redirect_dict(policy_rule_yaml=policy_rule_yaml))
    aqp_http_redirect_yaml = create_redirect_aqp_yaml(http_redirect_yaml=http_redirect_yaml)
    if cisco_he:
        he_template_cisco = os.path.join(cisco_yaml_dir, 'CiscoHETemplate.yaml')
        charging_action_yaml = os.path.join(cisco_yaml_dir, 'ChargingActionCisco.yaml')
        unique_template_yaml = os.path.join(cisco_yaml_dir, 'UniqueHETemplate.yaml')
        he_templates_yaml = create_he_template_yaml_cisco(he_template_cisco, charging_action_yaml, unique_template_yaml)
        header_enrichment_yaml = create_header_enrichment_yaml_cisco(policy_rule_yaml)
    else:
        he_templates_yaml = create_he_template_yaml(policy_rule_yaml=policy_rule_yaml)
        header_enrichment_yaml = create_header_enrichment_yaml(policy_rule_yaml=policy_rule_yaml,
                                                               he_templates_yaml=he_templates_yaml)

    output_dict['ApplicationYAML'] = application_yaml
    check_name_length(yaml_input=application_yaml, object_name='Application', max_len=32)
    output_dict['ChargingYAML'] = charging_yaml
    check_name_length(yaml_input=charging_yaml, object_name='ChargingRuleUnit', max_len=32)
    output_dict['HETemplatesYAML'] = he_templates_yaml
    check_name_length(yaml_input=he_templates_yaml, object_name='HETemplates', max_len=32)
    output_dict['HeaderEnrichmentYAML'] = header_enrichment_yaml
    output_dict['PrefixYAML'] = prefix_yaml
    check_name_length(yaml_input=prefix_yaml, object_name='PrefixList', max_len=32)
    output_dict['DnsIpCacheYAML'] = dns_ip_cache_yaml
    output_dict['ServerPortYAML'] = server_port_yaml
    output_dict['AppFilterYAML'] = app_filter_yaml
    output_dict['PolicyRuleUnitYAML'] = policy_rule_unit_yaml
    check_name_length(yaml_input=policy_rule_unit_yaml, object_name='PolicyRuleUnit', max_len=32)
    output_dict['CMGPolicyRule'] = cmg_policy_rule_yaml
    check_name_length(yaml_input=cmg_policy_rule_yaml, object_name='CMGPolicyRule', max_len=64)
    output_dict['CMGPolicyRuleBase'] = cmg_policy_rule_base_yaml
    check_name_length(yaml_input=cmg_policy_rule_base_yaml, object_name='CMGPolicyRuleBase', max_len=64)
    output_dict['HTTP-Redirect'] = http_redirect_yaml
    check_name_length(yaml_input=http_redirect_yaml, object_name='HTTP-Redirect', max_len=32)
    output_dict['AQP-HTTP-Redirect'] = aqp_http_redirect_yaml

    return output_dict


def create_mop_from_cmg_yaml(cmg_yaml_dir, templates_dir, cups, spip, spid, cisco_he):
    list_of_files = os.listdir(cmg_yaml_dir)
    # list_of_files_base = os.listdir(base_yaml_dir)
    list_of_templates = os.listdir(templates_dir)
    output_dict = dict()
    # CMG YAML Check
    if not list_of_files:
        raise FileNotFoundError('Directory {} is Empty'.format(cmg_yaml_dir))
    if 'Application.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find Application YAML file in {} directory".format(cmg_yaml_dir))
    if 'ChargingRuleUnit.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find Charging YAML file in {} directory".format(cmg_yaml_dir))
    if 'HETemplates.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find HE Templates YAML file in {} directory".format(cmg_yaml_dir))
    if 'HTTPEnrich.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find Header Enrichment YAML file in {} directory".format(cmg_yaml_dir))
    if 'PrefixList.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find Prefix List YAML file in {} directory".format(cmg_yaml_dir))
    if 'DnsIpCache.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find DNS IP Cache YAML file in {} directory".format(cmg_yaml_dir))
    if 'ServerPort.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find Server Port YAML file in {} directory".format(cmg_yaml_dir))
    if 'AppFilter.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find APP Filter YAML file in {} directory".format(cmg_yaml_dir))
    if 'PolicyRuleUnit.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find Policy Rule Unit YAML file in {} directory".format(cmg_yaml_dir))
    if 'CMGPolicyRule.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find CMG Policy Rule YAML file in {} directory".format(cmg_yaml_dir))
    if 'CMGPolicyRuleBase.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find CMG Policy Rule Base YAML file in {} directory".format(cmg_yaml_dir))
    if cups:
        if 'SRU.yaml' not in list_of_files:
            raise FileNotFoundError("Couldn't find CMG Policy Rule Base YAML file in {} directory".format(cmg_yaml_dir))
        if 'SRUList.yaml' not in list_of_files:
            raise FileNotFoundError("Couldn't find CMG Policy Rule Base YAML file in {} directory".format(cmg_yaml_dir))
    if len(list_of_files) != len(set(list_of_files)):
        raise FileExistsError(
            "Inputs are duplicated, please check the CMG YAML Directory and make sure only one input of each exists")
    # # BASE YAML Check
    # if not list_of_files_base:
    #     raise FileNotFoundError('Directory {} is Empty'.format(cmg_yaml_dir))
    # if 'PolicyRuleBase.yaml' not in list_of_files_base:
    #     raise FileNotFoundError("Couldn't find PolicyRuleBase YAML file in {} directory".format(base_yaml_dir))
    # if 'QoSProfiles.yaml' not in list_of_files_base:
    #     raise FileNotFoundError("Couldn't find QoSProfiles YAML file in {} directory".format(base_yaml_dir))
    # if len(list_of_files_base) != len(set(list_of_files_base)):
    #     raise FileExistsError(
    #         "Inputs are duplicated, please check the Base YAML Directory and make sure only one input of each exists")

    # Templates Dir Check
    if not list_of_templates:
        raise FileNotFoundError('Directory {} is Empty'.format(templates_dir))
    if 'app_filter.yaml' not in list_of_templates:
        raise FileNotFoundError("Couldn't find APP Filter Commands YAML file in {} directory".format(templates_dir))
    if 'application_commands.yaml' not in list_of_templates:
        raise FileNotFoundError("Couldn't find Application Commands YAML file in {} directory".format(templates_dir))
    if 'charging_rule_unit_commands.yaml' not in list_of_templates:
        raise FileNotFoundError(
            "Couldn't find Charging Rule Unit Commands YAML file in {} directory".format(templates_dir))
    if 'dns_ip_cache_commands.yaml' not in list_of_templates:
        raise FileNotFoundError("Couldn't find DNS IP Cache Commands YAML file in {} directory".format(templates_dir))
    if 'http_enrich.yaml' not in list_of_templates:
        raise FileNotFoundError(
            "Couldn't find Header Enrichment Commands YAML file in {} directory".format(templates_dir))
    if 'policy_rule_commands.yaml' not in list_of_templates:
        raise FileNotFoundError("Couldn't find Policy Rule Commands YAML file in {} directory".format(templates_dir))
    if 'port_list_commands.yaml' not in list_of_templates:
        raise FileNotFoundError("Couldn't find Port List Commands YAML file in {} directory".format(templates_dir))
    if 'prefix_list_commands.yaml' not in list_of_templates:
        raise FileNotFoundError("Couldn't find Prefix List Commands YAML file in {} directory".format(templates_dir))
    if cups:
        if 'sru.yaml' not in list_of_templates:
            raise FileNotFoundError(
                "Couldn't find Stat-Rule-Unit Commands YAML file in {} directory".format(templates_dir))
        if 'sru_list.yaml' not in list_of_templates:
            raise FileNotFoundError(
                "Couldn't find SRU List Commands YAML file in {} directory".format(templates_dir))
    if not os.path.exists(os.path.join(os.getcwd(), 'cmgMoP')):
        os.makedirs(os.path.join(os.getcwd(), 'cmgMoP'))

    os.chdir(os.path.join(os.getcwd(), 'cmgMoP'))

    # CMG YAML Files
    application_yaml = os.path.join(cmg_yaml_dir, 'Application.yaml')
    charging_yaml = os.path.join(cmg_yaml_dir, 'ChargingRuleUnit.yaml')
    he_templates_yaml = os.path.join(cmg_yaml_dir, 'HETemplates.yaml')
    header_enrichment_yaml = os.path.join(cmg_yaml_dir, 'HTTPEnrich.yaml')
    prefix_yaml = os.path.join(cmg_yaml_dir, 'PrefixList.yaml')
    dns_yaml = os.path.join(cmg_yaml_dir, 'DnsIpCache.yaml')
    server_port_yaml = os.path.join(cmg_yaml_dir, 'ServerPort.yaml')
    app_filter_yaml = os.path.join(cmg_yaml_dir, 'AppFilter.yaml')
    pru_yaml = os.path.join(cmg_yaml_dir, 'PolicyRuleUnit.yaml')
    pr_yaml = os.path.join(cmg_yaml_dir, 'CMGPolicyRule.yaml')
    cmg_policy_rule_base_yaml = os.path.join(cmg_yaml_dir, 'CMGPolicyRuleBase.yaml')
    http_redirect_yaml = os.path.join(cmg_yaml_dir, 'HTTP-Redirect.yaml')
    aqp_redirect_yaml = os.path.join(cmg_yaml_dir, 'AQP-HTTP-Redirect.yaml')
    # # Base YAML Files
    # policy_rule_base_yaml = os.path.join(base_yaml_dir, 'PolicyRuleBase.yaml')
    # # qos_profile_yaml = os.path.join(base_yaml_dir, 'QoSProfiles.yaml')
    # Commands Templates
    app_filter_commands = os.path.join(templates_dir, 'app_filter.yaml')
    application_commands = os.path.join(templates_dir, 'application_commands.yaml')
    charging_commands = os.path.join(templates_dir, 'charging_rule_unit_commands.yaml')
    dns_commands = os.path.join(templates_dir, 'dns_ip_cache_commands.yaml')
    he_commands = os.path.join(templates_dir, 'http_enrich.yaml')
    pr_commands = os.path.join(templates_dir, 'policy_rule_commands.yaml')
    port_list_commands = os.path.join(templates_dir, 'port_list_commands.yaml')
    prefix_commands = os.path.join(templates_dir, 'prefix_list_commands.yaml')
    redirect_commands = os.path.join(templates_dir, 'http_redirect.yaml')
    application_mop = create_application_mop(application_yaml_input=application_yaml,
                                             command_yaml_input=application_commands)
    charging_mop = create_charging_rule_unit_mop(yaml_cru=charging_yaml, yaml_template=charging_commands)
    port_list_mop = create_port_list_mop(server_port_yaml=server_port_yaml, port_list_commands_yaml=port_list_commands)
    prefix_mop = create_prefix_list_mop(prefix_yaml_input=prefix_yaml, command_yaml_input=prefix_commands)
    dns_mop = create_dns_mop(dns_entries_yaml=dns_yaml, dns_commands_yaml=dns_commands)
    app_filter_mop = create_app_filter_mop(app_filter_yaml=app_filter_yaml, app_filter_commands=app_filter_commands)
    if cisco_he:
        he_aqp_mop = create_he_aqp_mop_cisco(http_enrich_yaml=header_enrichment_yaml,
                                             he_template_commands_yaml=he_commands)
        he_template_mop = create_he_template_mop_cisco(he_template_yaml=he_templates_yaml,
                                                       he_template_commands_yaml=he_commands)
        output_dict['AQP-HTTP-Enrich MoP'] = he_aqp_mop
        output_dict['HE Template MoP'] = he_template_mop
    else:
        he_mop = create_header_enrichment_mop(he_template=he_templates_yaml,
                                              header_enrichment_yaml=header_enrichment_yaml,
                                              commands_template=he_commands)
        output_dict['HTTP-Enrich MoP'] = he_mop
    pru_mop = create_policy_rule_unit_mop(policy_rule_unit_yaml=pru_yaml, policy_rule_commands_template=pr_commands)
    pr_mop = create_policy_rule_mop(policy_rule_yaml=pr_yaml, policy_rule_commands_template=pr_commands)
    prb_mop = create_policy_rule_base_mop(cmg_policy_rule_base_yaml=cmg_policy_rule_base_yaml,
                                          policy_rule_commands_template=pr_commands)
    redirect_templates_mop = create_http_redirect_mop(http_redirect_yaml, redirect_commands)
    redirect_aqp_mop = create_aqp_http_redirect_mop(aqp_redirect_yaml, redirect_commands)

    output_dict['Application MoP'] = application_mop
    output_dict['Charging MoP'] = charging_mop
    output_dict['AA PortList MoP'] = port_list_mop
    output_dict['AA Prefix MoP'] = prefix_mop
    output_dict['DNS IP Cache MoP'] = dns_mop
    output_dict['AppFilter MoP'] = app_filter_mop
    output_dict['Policy Rule Unit MoP'] = pru_mop
    output_dict['Policy Rule MoP'] = pr_mop
    output_dict['Policy Rule Base MoP'] = prb_mop
    output_dict['Redirect Template MoP'] = redirect_templates_mop
    output_dict['AQP Redirect MoP'] = redirect_aqp_mop

    if spid or spip:
        addr_list_yaml = os.path.abspath(os.path.join(cmg_yaml_dir, 'AddrList.yaml'))
        addr_list_commands = os.path.abspath(os.path.join(templates_dir, 'addr_list_commands.yaml'))
        addr_list_mop = create_addr_list_mop(addr_list_yaml=addr_list_yaml, addr_list_commands=addr_list_commands)
        output_dict['Address List MoP'] = addr_list_mop

        fqdn_list_yaml = os.path.abspath(os.path.join(cmg_yaml_dir, 'FQDNList.yaml'))
        fqdn_list_commands_yaml = os.path.abspath(os.path.join(templates_dir, 'dns_sniffing_spi.yaml'))
        fqdn_list_mop = create_dns_snoop_mop(dns_snoop_yaml=fqdn_list_yaml,
                                             spi_dns_commands_yaml=fqdn_list_commands_yaml)
        output_dict['FQDN List MoP'] = fqdn_list_mop

        spi_pru_yaml = os.path.abspath(os.path.join(cmg_yaml_dir, 'SPIPolicyRuleUnit.yaml'))
        spi_pru_commands = os.path.abspath(os.path.join(templates_dir, 'spi_pru_commands.yaml'))
        spi_pru_mop = create_spi_pru_mop(spi_pru_yaml=spi_pru_yaml, spi_pru_commands_yaml=spi_pru_commands)
        output_dict['SPI Policy Rule Unit MoP'] = spi_pru_mop

        spi_port_list_yaml = os.path.abspath(os.path.join(cmg_yaml_dir, 'SPIPortList.yaml'))
        spi_port_list_commands = os.path.abspath(os.path.join(templates_dir, 'spi_port_list.yaml'))
        spi_port_list = create_spi_port_list_mop(port_list_yaml=spi_port_list_yaml,
                                                 port_list_commands_template=spi_port_list_commands)
        output_dict['SPI Port List MoP'] = spi_port_list

    if cups:
        sru_commands = os.path.join(templates_dir, 'sru.yaml')
        sru_list_commands = os.path.join(templates_dir, 'sru_list.yaml')
        sru_yaml = os.path.join(cmg_yaml_dir, 'SRU.yaml')
        sru_list_yaml = os.path.join(cmg_yaml_dir, 'SRUList.yaml')
        sru_mop = create_sru_mop(sru_yaml, sru_commands)
        sru_list_mop = create_sru_list_mop(sru_list_yaml, sru_list_commands)
        pr_upf_mop = create_policy_rule_upf_mop(policy_rule_yaml=pr_yaml, sru_list_yaml=sru_list_yaml,
                                                policy_rule_commands_template=pr_commands)

        output_dict['SRU MoP'] = sru_mop
        output_dict['SRU List MoP'] = sru_list_mop
        output_dict['PR UPF MoP'] = pr_upf_mop

    return output_dict


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-fng", "--flexiNG", type=str,
                        help="Input Flexi NG inputs Directory PATH")
    parser.add_argument("-cisco", "--ciscoASR", type=str,
                        help="Input Cisco ASR input Directory PATH")
    parser.add_argument("-by", "--baseYAML", type=str,
                        help="Input BaseYAML Directory PATH")
    parser.add_argument("-cmg", "--cmgYAML", type=str,
                        help="Input cmgYAML Directory PATH")
    parser.add_argument("-t", "--templates", type=str,
                        help="Input Commands Template Directory PATH")
    parser.add_argument("-rd", "--ruleDictionary", type=str,
                        help="Provide PATH to Policy-Rule Name conversion if needed.")
    parser.add_argument("-ascii", "--MKascii", action="store_true",
                        help="Choose whether to use ASCII encode in Monitoring Key parameter")
    parser.add_argument("-cups", "--cups_mode", action="store_true",
                        help="Define if configuration must be provided for CUPS SAEGW")
    parser.add_argument("-spid", "--spi_domain_name", action="store_true",
                        help="Define if SPI rules for domain-name based filters must be provided.")
    parser.add_argument("-spip", "--spi_address", action="store_true",
                        help="Define if SPI rules for ip-address based filters must be provided.")
    parser.add_argument("-ch", "--cisco_he", action="store_true",
                        help="Define if Cisco Header Enrichment is used.")
    parser.add_argument("-cy", "--ciscoYAML",
                        help="Define ciscoYAML Directory Path")
    args = parser.parse_args()

    print("Welcome to CMG Application Assurance Tool v1.1\n\n"
          "Author: Leonardo Monteiro (leonardo.monteiro@nokia.com)\n\n"
          "ChangeLog:\n"
          "v1.0 - First Version\n"
          "v1.1 - Included domain-name on AppFilter.yaml file and "
          "included http-host based on domain-name if http-host is not "
          "provided and ip-protocol-num different from UDP\n\n")

    if args.flexiNG:
        print('#### Initializing script... ####\n\n')
        print("Parsing FNG Files and Creating Base YAML files, please wait.\n")
        path_dict = create_yaml_from_fng(os.path.abspath(args.flexiNG), spip=args.spi_address,
                                         spid=args.spi_domain_name, rule_conersion_dict=args.ruleDictionary)
        print(
            'BaseYAML Files were created on the following Paths:\n\nFilterBaseYAML:{filter_base_path}\n'
            'PolicyRuleYAML: {pr_path}\nPolicyRuleBaseYAML: {prb_path}'
            '\nQosYAML: {qos_path}'.format(
                filter_base_path=path_dict.get('FilterBaseYAML'), pr_path=path_dict.get('PolicyRuleYAML'),
                prb_path=path_dict.get('PolicyRuleBaseYAML'),
                qos_path=path_dict.get('QoSYAML')
            ))
        return
    if args.ciscoASR:
        print('#### Initializing script... ####\n\n')
        print("Parsing Cisco File and Creating Base YAML files, please wait.\n")
        path_dict = create_yaml_from_cisco(os.path.abspath(args.ciscoASR), spid=args.spi_domain_name,
                                           spip=args.spi_address)
        print(f"All Cisco Files were parsed.\n\n"
              f"All Raw Cisco YAML files can be accessed on: {path_dict.get('RawCiscoYAML')}\n"
              f"All Cisco YAML files can be accessed on: {path_dict.get('CiscoYAML')}\n"
              f"All BaseYAML files can be accessed on: {path_dict.get('BaseYAML')}")
        return
    if args.cmgYAML and args.templates:
        print('#### Initializing script... ####\n\n')
        print("Creating all CMG MoP files, please wait.\n")
        path_dict = create_mop_from_cmg_yaml(cmg_yaml_dir=os.path.abspath(args.cmgYAML),
                                             templates_dir=os.path.abspath(args.templates),
                                             cups=args.cups_mode,
                                             spid=args.spi_domain_name,
                                             spip=args.spi_address,
                                             cisco_he=args.cisco_he)

        print()
        for key in path_dict:
            print(f"{key}: {path_dict.get(key)}")
        return

    elif args.baseYAML:
        print('#### Initializing script... ####\n\n')
        print("Creating all CMG YAML files, please wait.\n")

        path_dict = create_yaml_for_cmg(os.path.abspath(args.baseYAML), mk_to_ascii=args.MKascii, cups=args.cups_mode,
                                        spid=args.spi_domain_name, spip=args.spi_address, cisco_he=args.cisco_he,
                                        cisco_yaml_dir=args.ciscoYAML)
        print()
        for key in path_dict:
            print(f"{key}: {path_dict.get(key)}")
        return
    elif args.cmgYAML:
        print("When inputting cmgYAML please provide Templates as well.")
        return
    else:
        print('If you have doubts on how to use this tool, please run it with --help command.')
        input()
        return


if __name__ == "__main__":
    main()
