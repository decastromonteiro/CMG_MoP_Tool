from app_filter.app_filter import create_app_filter_yaml, create_app_filter_mop
from application.application import create_application_yaml, create_application_mop
from charging.charging_rule_unit import create_charging_rule_unit_yaml, create_charging_rule_unit_mop
from dns_ip_cache.dns_ip_cache import create_dns_yaml, create_dns_mop
from header_enrichment.header_enrichment import create_he_template_yaml, create_header_enrichment_yaml, \
    create_header_enrichment_mop
from parsers.fng_parser import *
from policy_rule.policy_rule import create_policy_rule_unit_yaml, create_policy_rule_yaml, \
    create_policy_rule_unit_mop, create_policy_rule_mop, create_policy_rule_base_mop, create_policy_rule_base_yaml
from prefix_list.prefix_list import create_prefix_list_yaml, create_prefix_list_mop
from server_port.server_port import create_port_list_yaml, create_port_list_mop
from utils.check_name_lenghts import check_name_lenghts

import argparse
import os


def create_yaml_from_fng(fng_inputs_dir):
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

    filter_base = parse_filter_base(fng_filter_base)
    filters = parse_pcc_rule_filter(fng_filters)
    pcc_rules = parse_pcc_rule(pcc_rule, filters)
    pcc_rule_bases = parse_pcc_rule_base(pcc_rule_base)
    qos_profiles = parse_qos_profiles(qos_profile)

    if not os.path.exists(os.path.join(os.getcwd(), 'BaseYAML')):
        os.makedirs(os.path.join(os.getcwd(), 'BaseYAML'))

    os.chdir(os.path.join(os.getcwd(), 'BaseYAML'))

    fb = YAML(project_name="FilterBase")
    filter_base_path = fb.write_to_yaml({'FilterBase': filter_base})

    pr = YAML(project_name="PolicyRule")
    pr_path = pr.write_to_yaml({'PolicyRule': pcc_rules})

    prb = YAML(project_name='PolicyRuleBase')
    prb_path = prb.write_to_yaml({'PolicyRuleBase': pcc_rule_bases})

    qos = YAML(project_name='QoSProfiles')
    qos_path = qos.write_to_yaml({'QoSProfiles': qos_profiles})

    return {
        'FilterBaseYAML': filter_base_path,
        'PolicyRuleYAML': pr_path,
        'PolicyRuleBaseYAML': prb_path,
        'QoSYAML': qos_path
    }


def create_yaml_from_cisco(cisco_input_dir):
    pass


def create_yaml_for_cmg(base_yaml_dir):
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

    filter_base_yaml = os.path.join(base_yaml_dir, 'FilterBase.yaml')
    policy_rule_yaml = os.path.join(base_yaml_dir, 'PolicyRule.yaml')
    policy_rule_base_yaml = os.path.join(base_yaml_dir, 'PolicyRuleBase.yaml')
    qos_profile_yaml = os.path.join(base_yaml_dir, 'QoSProfiles.yaml')

    application_yaml = create_application_yaml(policy_rule_yaml=policy_rule_yaml)
    charging_yaml = create_charging_rule_unit_yaml(policy_rule_yaml=policy_rule_yaml)
    he_templates_yaml = create_he_template_yaml(policy_rule_yaml=policy_rule_yaml)
    header_enrichment_yaml = create_header_enrichment_yaml(policy_rule_yaml=policy_rule_yaml,
                                                           he_templates_yaml=he_templates_yaml)
    prefix_yaml = create_prefix_list_yaml(policy_rule_yaml=policy_rule_yaml, filter_base_yaml=filter_base_yaml)
    dns_ip_cache_yaml = create_dns_yaml(policy_rule_yaml=policy_rule_yaml,
                                        filter_base_yaml=filter_base_yaml)

    server_port_yaml = create_port_list_yaml(policy_rule_yaml=policy_rule_yaml, filter_base_yaml=filter_base_yaml,
                                             prefix_list_yaml=prefix_yaml)
    app_filter_yaml = create_app_filter_yaml(dns_ip_cache_yaml=dns_ip_cache_yaml,
                                             prefix_list_yaml=prefix_yaml, server_port_yaml=server_port_yaml,
                                             filter_base_yaml=filter_base_yaml, policy_rule_yaml=policy_rule_yaml)
    policy_rule_unit_yaml = create_policy_rule_unit_yaml(policy_rule_yaml=policy_rule_yaml)
    cmg_policy_rule_yaml = create_policy_rule_yaml(policy_rule_yaml=policy_rule_yaml)
    cmg_policy_rule_base_yaml = create_policy_rule_base_yaml(policy_rule_base_yaml=policy_rule_base_yaml)

    check_name_lenghts(cmg_policy_rule_yaml=cmg_policy_rule_yaml,
                       prefix_list_yaml=prefix_yaml,
                       dns_ip_cache_yaml=dns_ip_cache_yaml,
                       policy_rule_unit_yaml=policy_rule_unit_yaml,
                       application_yaml=application_yaml)

    return {
        'ApplicationYAML': application_yaml,
        'ChargingYAML': charging_yaml,
        'HETemplatesYAML': he_templates_yaml,
        'HeaderEnrichmentYAML': header_enrichment_yaml,
        'PrefixYAML': prefix_yaml,
        'DnsIpCacheYAML': dns_ip_cache_yaml,
        'ServerPortYAML': server_port_yaml,
        'AppFilterYAML': app_filter_yaml,
        'PolicyRuleUnitYAML': policy_rule_unit_yaml,
        'CMGPolicyRule': cmg_policy_rule_yaml,
        'CMGPolicyRuleBase': cmg_policy_rule_base_yaml
    }


def create_mop_from_cmg_yaml(cmg_yaml_dir, templates_dir):
    list_of_files = os.listdir(cmg_yaml_dir)
    # list_of_files_base = os.listdir(base_yaml_dir)
    list_of_templates = os.listdir(templates_dir)

    # CMG YAML Check
    if not list_of_files:
        raise FileNotFoundError('Directory {} is Empty'.format(cmg_yaml_dir))
    if 'Application.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find Application YAML file in {} directory".format(cmg_yaml_dir))
    if 'ChargingRuleUnit.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find Charging YAML file in {} directory".format(cmg_yaml_dir))
    if 'HETemplates.yaml' not in list_of_files:
        raise FileNotFoundError("Couldn't find HE Templates YAML file in {} directory".format(cmg_yaml_dir))
    if 'HeaderEnrichment.yaml' not in list_of_files:
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

    if not os.path.exists(os.path.join(os.getcwd(), 'cmgMoP')):
        os.makedirs(os.path.join(os.getcwd(), 'cmgMoP'))

    os.chdir(os.path.join(os.getcwd(), 'cmgMoP'))

    # CMG YAML Files
    application_yaml = os.path.join(cmg_yaml_dir, 'Application.yaml')
    charging_yaml = os.path.join(cmg_yaml_dir, 'ChargingRuleUnit.yaml')
    he_templates_yaml = os.path.join(cmg_yaml_dir, 'HETemplates.yaml')
    header_enrichment_yaml = os.path.join(cmg_yaml_dir, 'HeaderEnrichment.yaml')
    prefix_yaml = os.path.join(cmg_yaml_dir, 'PrefixList.yaml')
    dns_yaml = os.path.join(cmg_yaml_dir, 'DnsIpCache.yaml')
    server_port_yaml = os.path.join(cmg_yaml_dir, 'ServerPort.yaml')
    app_filter_yaml = os.path.join(cmg_yaml_dir, 'AppFilter.yaml')
    pru_yaml = os.path.join(cmg_yaml_dir, 'PolicyRuleUnit.yaml')
    pr_yaml = os.path.join(cmg_yaml_dir, 'CMGPolicyRule.yaml')
    cmg_policy_rule_base_yaml = os.path.join(cmg_yaml_dir, 'CMGPolicyRuleBase.yaml')
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

    application_mop = create_application_mop(application_yaml_input=application_yaml,
                                             command_yaml_input=application_commands)
    charging_mop = create_charging_rule_unit_mop(yaml_cru=charging_yaml, yaml_template=charging_commands)
    port_list_mop = create_port_list_mop(server_port_yaml=server_port_yaml, port_list_commands_yaml=port_list_commands)
    prefix_mop = create_prefix_list_mop(prefix_yaml_input=prefix_yaml, command_yaml_input=prefix_commands)
    dns_mop = create_dns_mop(dns_entries_yaml=dns_yaml, dns_commands_yaml=dns_commands)
    app_filter_mop = create_app_filter_mop(app_filter_yaml=app_filter_yaml, app_filter_commands=app_filter_commands)
    he_mop = create_header_enrichment_mop(he_template=he_templates_yaml, header_enrichment_yaml=header_enrichment_yaml,
                                          commands_template=he_commands)
    pru_mop = create_policy_rule_unit_mop(policy_rule_unit_yaml=pru_yaml, policy_rule_commands_template=pr_commands)
    pr_mop = create_policy_rule_mop(policy_rule_yaml=pr_yaml, policy_rule_commands_template=pr_commands)
    prb_mop = create_policy_rule_base_mop(cmg_policy_rule_base_yaml=cmg_policy_rule_base_yaml,
                                          policy_rule_commands_template=pr_commands)

    return {
        'ApplicationMOP': application_mop,
        'ChargingMOP': charging_mop,
        'PortListMOP': port_list_mop,
        'PrefixMOP': prefix_mop,
        'DNSMOP': dns_mop,
        'AppFilterMOP': app_filter_mop,
        'HeaderEnrichmentMOP': he_mop,
        'PolicyRuleunitMOP': pru_mop,
        'PolicyRuleMOP': pr_mop,
        'PolicyRuleBaseMOP': prb_mop
    }


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
    parser.add_argument("-rd", "--ruleDictionary", action="store_true",
                        help="Provide PATH to Policy-Rule Name conversion if needed.")
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
        path_dict = create_yaml_from_fng(os.path.abspath(args.flexiNG))
        print(
            'BaseYAML Files were created on the following Paths:\n\nFilterBaseYAML:{filter_base_path}\n'
            'PolicyRuleYAML: {pr_path}\nPolicyRuleBaseYAML: {prb_path}'
            '\nQosYAML: {qos_path}'.format(
                filter_base_path=path_dict.get('FilterBaseYAML'), pr_path=path_dict.get('PolicyRuleYAML'),
                prb_path=path_dict.get('PolicyRuleBaseYAML'),
                qos_path=path_dict.get('QoSYAML')
            ))
        return
    if args.cmgYAML and args.templates:
        print('#### Initializing script... ####\n\n')
        print("Creating all CMG MoP files, please wait.\n")
        path_dict = create_mop_from_cmg_yaml(cmg_yaml_dir=os.path.abspath(args.cmgYAML),
                                             templates_dir=os.path.abspath(args.templates))
        print('CMG MoP Files were created on the following Paths:\n\n'
              'Application MoP: {application_mop}\n'
              'Charging Rule Unit MoP: {charging_mop}\n'
              'Port List MoP: {port_list_mop}\n'
              'Prefix list MoP: {prefix_list_mop}\n'
              'DNS IP Cache MoP: {dns_mop}\n'
              'APP Filter MoP: {app_filter_mop}\n'
              'Header Enrichment MoP: {he_mop}\n'
              'Policy Rule Unit MoP: {pru_mop}\n'
              'Policy Rule MoP: {pr_mop}\n'
              'Policy Rule Base MoP: {prb_mop}'.format(application_mop=path_dict.get('ApplicationMOP'),
                                                       charging_mop=path_dict.get('ChargingMOP'),
                                                       port_list_mop=path_dict.get('PortListMOP'),
                                                       prefix_list_mop=path_dict.get('PrefixMOP'),
                                                       dns_mop=path_dict.get('DNSMOP'),
                                                       app_filter_mop=path_dict.get('AppFilterMOP'),
                                                       he_mop=path_dict.get('HeaderEnrichmentMOP'),
                                                       pru_mop=path_dict.get('PolicyRuleunitMOP'),
                                                       pr_mop=path_dict.get('PolicyRuleMOP'),
                                                       prb_mop=path_dict.get('PolicyRuleBaseMOP')
                                                       ))
        return
    elif args.baseYAML:
        print('#### Initializing script... ####\n\n')
        print("Creating all CMG YAML files, please wait.\n")
        path_dict = create_yaml_for_cmg(os.path.abspath(args.baseYAML))
        print('CMG YAML Files were created on the following Paths:\n'
              'Application YAML: {application_yaml}\n'
              'Charging YAML: {charging_yaml}\n'
              'HE Templates YAML: {he_templates_yaml}\n'
              'Header Enrichment YAML: {header_enrichment_yaml}\n'
              'Prefix List YAML: {prefix_yaml}\n'
              'DNS IP Cache YAML: {dns_ip_cache_yaml}\n'
              'Server Port YAML: {server_port_yaml}\n'
              'APP Filter YAML: {app_filter_yaml}\n'
              'Policy Rule Unit YAML: {pru_yaml}\n'
              'CMG Policy Rule YAML: {pr_yaml}\n'
              'CMG Policy Rule Base YAML: {prb_yaml}\n'.format(application_yaml=path_dict.get('ApplicationYAML'),
                                                               charging_yaml=path_dict.get('ChargingYAML'),
                                                               he_templates_yaml=path_dict.get('HETemplatesYAML'),
                                                               header_enrichment_yaml=path_dict.get(
                                                                   'HeaderEnrichmentYAML'),
                                                               prefix_yaml=path_dict.get('PrefixYAML'),
                                                               dns_ip_cache_yaml=path_dict.get('DnsIpCacheYAML'),
                                                               server_port_yaml=path_dict.get('ServerPortYAML'),
                                                               app_filter_yaml=path_dict.get('AppFilterYAML'),
                                                               pru_yaml=path_dict.get('PolicyRuleUnitYAML'),
                                                               pr_yaml=path_dict.get('CMGPolicyRule'),
                                                               prb_yaml=path_dict.get('CMGPolicyRuleBase'))
              )
        return
    elif args.cmgYAML:
        print("When inputing cmgYAML please provide Templates as well.")
        return
    else:
        print('If you have doubts on how to use this tool, please run it with --help command.')
        input()
        return


if __name__ == "__main__":
    main()
