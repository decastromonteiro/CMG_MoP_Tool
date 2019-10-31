import os
from charging.charging_rule_unit import create_cru_string
from utils.yaml import YAML
import re


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def export_yaml(data, project_name='PolicyRule'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({project_name: data})
    return path


def create_pr_to_charging_rule(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')

    output_dict = dict()

    for key in policy_rule_dict:
        final_string = create_cru_string(policy_rule_dict.get(key))

        output_dict.update(
            {key: final_string}
        )

    return output_dict


def create_policy_rule_unit_yaml(policy_rule_yaml):
    flow_gate_status_dict = {'charge-v': 'allow', 'pass': 'allow', 'drop': 'drop', 'deny': 'drop'}
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    policy_rule_unit_dict = dict()

    for key in policy_rule_dict:
        fb = policy_rule_dict.get(key).get('pcc-filter-base-name')
        if not fb or fb == 'null':
            policy_rule = key
        else:
            policy_rule = fb
        flow_gate_status = policy_rule_dict.get(key).get('pcc-rule-action')
        policy_rule_unit_dict.update(
            {policy_rule + '_PRU': {'aa-charging-group': policy_rule,
                                    'flow-gate-status': flow_gate_status_dict.get(flow_gate_status, flow_gate_status)}
             }
        )

    return export_yaml(policy_rule_unit_dict, project_name='PolicyRuleUnit')


def create_policy_rule_yaml(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')

    output_policy_rule_dict = dict()
    pr_to_cru_dict = create_pr_to_charging_rule(policy_rule_yaml)

    for key in policy_rule_dict:
        fb = policy_rule_dict.get(key).get('pcc-filter-base-name')
        if not fb or fb == 'null':
            policy_rule_unit = key + '_PRU'
        else:
            policy_rule_unit = fb + '_PRU'
        output_policy_rule_dict.update(
            {
                key: {
                    'policy-rule-unit': policy_rule_unit,
                    'charging-rule-unit': pr_to_cru_dict.get(key),
                    'precedence': policy_rule_dict.get(key).get('precedence'),
                    'action-rule-unit': policy_rule_dict.get(key).get('qos-profile-name')
                }
            }
        )

    return export_yaml(output_policy_rule_dict, project_name='CMGPolicyRule')


def create_policy_rule_base_yaml(policy_rule_base_yaml):
    prb_dict = read_yaml_file(policy_rule_base_yaml).get('PolicyRuleBase')
    prb_output_dict = dict()
    for key in prb_dict:
        prb_output_dict.update({key: {'policy-rules': prb_dict.get(key), 'characteristics': None}})

    return export_yaml(prb_output_dict, project_name='CMGPolicyRuleBase')


def create_policy_rule_unit_mop(policy_rule_unit_yaml, policy_rule_commands_template):
    pru_dict = read_yaml_file(policy_rule_unit_yaml).get('PolicyRuleUnit')
    provision_command_dict = read_yaml_file(policy_rule_commands_template).get('commands').get('provision')

    pr_base_commands = list()
    pr_base_commands.append(provision_command_dict.get('begin'))
    for key in pru_dict:
        pr_base_commands.append(provision_command_dict.get('rule_unit').format(
            policy_rule_unit=key, charging_group=pru_dict.get(key).get('aa-charging-group')
        ))
        pr_base_commands.append(provision_command_dict.get('flow-gate-status').format(
            policy_rule_unit=key, flow_gate_status=pru_dict.get(key).get('flow-gate-status')
        ))
    pr_base_commands.append(provision_command_dict.get('commit'))

    with open('mop_policy_rule_unit.txt', 'w') as fout:
        for command in pr_base_commands:
            fout.write(command)
            fout.write('\n')
    return os.path.abspath('mop_policy_rule_unit.txt')


def create_policy_rule_mop(policy_rule_yaml, policy_rule_commands_template):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('CMGPolicyRule')
    provision_command_dict = read_yaml_file(policy_rule_commands_template).get('commands').get('provision')

    pr_base_commands = list()
    pr_base_commands.append(provision_command_dict.get('begin'))
    for key in policy_rule_dict:
        pr_base_commands.append(
            provision_command_dict.get('rule').format(
                policy_rule=key,
                rule_unit=policy_rule_dict.get(key).get('policy-rule-unit'),
                charging_rule_unit=policy_rule_dict.get(key).get('charging-rule-unit'),
                precedence=policy_rule_dict.get(key).get('precedence'),
                action_rule_unit='' if policy_rule_dict.get(key).get(
                    'action-rule-unit') == 'null' else 'action-rule-unit {}'.format(
                    policy_rule_dict.get(key).get('action-rule-unit')
                )
            )
        )
    pr_base_commands.append(provision_command_dict.get('commit'))

    with open('mop_policy_rule.txt', 'w') as fout:
        for command in pr_base_commands:
            fout.write(command)
            fout.write('\n')

    return os.path.abspath('mop_policy_rule.txt')


def create_policy_rule_base_mop(cmg_policy_rule_base_yaml, policy_rule_commands_template):
    pr_base_dict = read_yaml_file(cmg_policy_rule_base_yaml).get('CMGPolicyRuleBase')
    provision_command_dict = read_yaml_file(policy_rule_commands_template).get('commands').get('provision')

    pr_base_commands = list()
    pr_base_commands.append(provision_command_dict.get('begin'))
    for key in pr_base_dict:
        for policy_rule in pr_base_dict.get(key).get('policy-rules'):
            pr_base_commands.append(provision_command_dict.get('rule_base').format(
                policy_rule_base=key, policy_rule=policy_rule
            ))

    pr_base_commands.append(provision_command_dict.get('commit'))

    with open('mop_policy_rule_base.txt', 'w') as fout:
        for command in pr_base_commands:
            fout.write(command)
            fout.write('\n')

    return os.path.abspath('mop_policy_rule_base.txt')


def main():
    pru_yaml = create_policy_rule_unit_yaml(
        r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml'
    )

    pr_yaml = create_policy_rule_yaml(r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml')

    create_policy_rule_base_mop(r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRuleBase.yaml',
                                r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\policy_rule_commands.yaml')

    create_policy_rule_unit_mop(pru_yaml,
                                r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\policy_rule_commands.yaml')

    create_policy_rule_mop(pr_yaml,
                           r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\policy_rule_commands.yaml')


if __name__ == "__main__":
    main()
