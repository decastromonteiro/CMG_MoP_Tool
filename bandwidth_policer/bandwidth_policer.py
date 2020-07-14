from utils.utils import export_mop_file
from utils.yaml import export_yaml, read_yaml_file


def create_bandwidth_policer_yaml(qos_profile_yaml):
    qos_dict = read_yaml_file(qos_profile_yaml, 'QoSProfiles')
    policer_dict = dict()
    for qos_profile in qos_dict.keys():
        dl_bs = qos_dict.get(qos_profile).get('downlink').get('peak-burst-size')
        dl_dr = qos_dict.get(qos_profile).get('downlink').get('peak-data-rate')
        ul_bs = qos_dict.get(qos_profile).get('uplink').get('peak-burst-size')
        ul_dr = qos_dict.get(qos_profile).get('uplink').get('peak-data-rate')
        dl_policer_name = f"DL-BS{dl_bs}k-DR{dl_dr}k"
        ul_policer_name = f"UL-BS{ul_bs}k-DR{ul_dr}k"
        policer_dict.update(
            {dl_policer_name: {'rate': dl_dr, 'mbs': dl_bs, 'cir': None, 'cbs': None,
                               'type': 'single-bucket-bandwidth'},
             ul_policer_name: {'rate': ul_dr, 'mbs': ul_bs, 'cir': None, 'cbs': None,
                               'type': 'single-bucket-bandwidth'}
             }
        )

    return export_yaml(policer_dict, 'Policers')


def create_policer_aqp_yaml(policy_rule_yaml, qos_profile_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml, 'PolicyRule')
    qos_dict = read_yaml_file(qos_profile_yaml, 'QoSProfiles')
    aqp_policer_dict = dict()
    aqp_entry = 30000
    for policy_rule in policy_rule_dict.keys():
        filter_base_name = policy_rule_dict.get(policy_rule).get('pcc-filter-base-name')
        qos_profile = policy_rule_dict.get(policy_rule).get('qos-profile-name')
        if qos_profile:
            qos_parameters = qos_dict.get(qos_profile)
            dl_bs = qos_parameters.get('downlink').get('peak-burst-size')
            dl_dr = qos_parameters.get('downlink').get('peak-data-rate')
            ul_bs = qos_parameters.get('uplink').get('peak-burst-size')
            ul_dr = qos_parameters.get('uplink').get('peak-data-rate')
            dl_policer_name = f"DL-BS{dl_bs}k-DR{dl_dr}k"
            ul_policer_name = f"UL-BS{ul_bs}k-DR{ul_dr}k"
            if filter_base_name:
                application = filter_base_name
            else:
                application = policy_rule

            aqp_policer_dict.update(
                {
                    aqp_entry: {'application': application,
                                'characteristics': {'name': 'QoS', 'value': qos_profile},
                                'policer': ul_policer_name,
                                'traffic-direction': 'subscriber-to-network',
                                }
                }
            )
            aqp_entry += 10
            aqp_policer_dict.update(
                {
                    aqp_entry: {'application': application,
                                'characteristics': {'name': 'QoS', 'value': qos_profile},
                                'policer': dl_policer_name,
                                'traffic-direction': 'network-to-subscriber',
                                }
                }
            )
            aqp_entry += 10

    return export_yaml(aqp_policer_dict, 'AQP-Policers')


def create_bandwidth_policer_mop(policers_yaml, policers_command_yaml):
    policers_dict = read_yaml_file(policers_yaml, 'Policers')
    commands = read_yaml_file(policers_command_yaml, 'commands')
    provision_commands = commands.get('provision')
    list_of_commands = list()
    for policer in policers_dict.keys():
        policer_type = policers_dict.get(policer).get('type')
        list_of_commands.append(
            provision_commands.get('create_policer').format(policer=policer,
                                                            policer_type=policer_type)
        )
        if policer_type.startswith('single'):
            list_of_commands.append(
                provision_commands.get('config_rate').format(policer=policer,
                                                             rate=policers_dict.get(policer).get('rate')
                                                             )
            )
        else:
            list_of_commands.append(
                provision_commands.get('config_cir').format(policer=policer,
                                                            rate=policers_dict.get(policer).get('rate'),
                                                            cir=policers_dict.get(policer).get('cir')
                                                            )
            )
            list_of_commands.append(
                provision_commands.get('config_cbs').format(policer=policer,
                                                            cbs=policers_dict.get(policer).get('cbs')
                                                            )
            )
        list_of_commands.append(
            provision_commands.get('config_mbs').format(policer=policer,
                                                        mbs=policers_dict.get(policer).get('mbs'))
        )
    return export_mop_file('aa_bandwidth_policer', list_of_commands)


def create_bandwidth_policer_aqp_mop(aqp_policers_yaml, policers_command_yaml):
    aqp_policer_dict = read_yaml_file(aqp_policers_yaml, 'AQP-Policers')
    commands = read_yaml_file(policers_command_yaml, 'commands')
    provision_commands = commands.get('provision')
    list_of_commands = list()
    list_of_commands.append(
        provision_commands.get('aa_begin').format(partition="1:1")
    )
    for aqp_entry in aqp_policer_dict.keys():
        list_of_commands.append(
            provision_commands.get('create_aso').format(partition="1:1",
                                                        characteristic=aqp_policer_dict.get(aqp_entry).get(
                                                            'characteristics').get('name')

                                                        )
        )
        list_of_commands.append(
            provision_commands.get('aso_value').format(partition="1:1",
                                                       characteristic=aqp_policer_dict.get(aqp_entry).get(
                                                           'characteristics').get('name'),
                                                       aso_value=aqp_policer_dict.get(aqp_entry).get(
                                                           'characteristics').get('value')
                                                       )
        )
        list_of_commands.append(
            provision_commands.get('aso_value').format(partition="1:1",
                                                       characteristic=aqp_policer_dict.get(aqp_entry).get(
                                                           'characteristics').get('name'),
                                                       aso_value='off'
                                                       )
        )
        list_of_commands.append(
            provision_commands.get('aso_default_value').format(partition="1:1",
                                                               characteristic=aqp_policer_dict.get(aqp_entry).get(
                                                                   'characteristics').get('name'),
                                                               aso_value='off'
                                                               )
        )
        list_of_commands.append(
            provision_commands.get('create_aqp_entry').format(partition="1:1",
                                                              entry=aqp_entry)
        )
        list_of_commands.append(
            provision_commands.get('match_aqp_filter_application').format(partition="1:1",
                                                                          entry=aqp_entry,
                                                                          application=aqp_policer_dict.get(
                                                                              aqp_entry).get('application'))
        )
        list_of_commands.append(
            provision_commands.get('match_aqp_aso').format(partition="1:1",
                                                           entry=aqp_entry,
                                                           aso=aqp_policer_dict.get(aqp_entry).get(
                                                               'characteristics').get('name'),
                                                           aso_value=aqp_policer_dict.get(aqp_entry).get(
                                                               'characteristics').get('value'))
        )

        list_of_commands.append(
            provision_commands.get('match_traffic_direction').format(partition="1:1",
                                                                     entry=aqp_entry,
                                                                     traffic_direction=aqp_policer_dict.get(
                                                                         aqp_entry).get(
                                                                         'traffic-direction'))
        )

        list_of_commands.append(
            provision_commands.get('aqp_action').format(partition="1:1",
                                                        entry=aqp_entry,
                                                        policer=aqp_policer_dict.get(aqp_entry).get(
                                                            'policer'))
        )

        list_of_commands.append(
            provision_commands.get('aqp_no_shut').format(partition="1:1",
                                                         entry=aqp_entry)
        )

    list_of_commands.append(
        provision_commands.get('aa_commit').format(partition="1:1")
    )

    return export_mop_file('aa_aqp_policers', list_of_commands)
