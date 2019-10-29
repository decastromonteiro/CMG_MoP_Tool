import os

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


def create_charging_rule_to_pr(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')

    output_dict = dict()

    for key in policy_rule_dict:
        mk = policy_rule_dict.get(key).get('monitoring-key')
        rg = policy_rule_dict.get(key).get('rating-group')
        sid = policy_rule_dict.get(key).get('service-id')

        mk_string = 'MK{}'.format(mk) if mk != 'null' else ''
        rg_string = 'RG{}'.format(rg) if rg != 'null' else ''
        sid_string = 'SID{}'.format(sid) if sid != 'null' else ''

        final_string = rg_string + sid_string + mk_string

        output_dict.update(
            {key: final_string}
        )

    return output_dict


def create_policy_rule_unit_yaml(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    policy_rule_unit_dict = dict()

    for key in policy_rule_dict:
        policy_rule_unit_dict.update(
            {key + '_PRU': {'aa-charging-group': key}
             }
        )

    return export_yaml(policy_rule_unit_dict, project_name='PolicyRuleUnit')


def create_policy_rule_yaml(policy_rule_yaml, policy_rule_unit_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    policy_rule_unit_dict = read_yaml_file(policy_rule_unit_yaml).get('PolicyRuleUnit')

    pattern = '(.+)_PRU'
    output_policy_rule_dict = dict()
    cru_to_pr_dict = create_charging_rule_to_pr(policy_rule_yaml)
    for key in policy_rule_unit_dict:
        policy_rule = re.findall(pattern, key)[0]
        output_policy_rule_dict.update(
            {
                policy_rule: {
                    'policy-rule-unit': key,
                    'charging-rule-unit': cru_to_pr_dict.get(policy_rule),
                    'precedence': policy_rule_dict.get(policy_rule).get('precedence'),
                    'action-rule-unit': policy_rule_dict.get(policy_rule).get('qos-profile-name')
                }
            }
        )

    return export_yaml(output_policy_rule_dict)


def create_policy_rule_unit_mop(policy_rule_unit_yaml, policy_rule_commands_template):
    pru_dict = read_yaml_file(policy_rule_unit_yaml).get('PolicyRuleUnit')
    provision_command_dict = read_yaml_file(policy_rule_commands_template).get('commands').get('provision')

    pr_base_commands = list()
    pr_base_commands.append(provision_command_dict.get('begin'))
    for key in pru_dict:
        pr_base_commands.append(provision_command_dict.get('rule_unit').format(
            policy_rule_unit=key, charging_group=pru_dict.get(key).get('aa-charging-group')
        ))

    pr_base_commands.append(provision_command_dict.get('commit'))

    with open('mop_policy_rule_unit.txt', 'w') as fout:
        for command in pr_base_commands:
            fout.write(command)
            fout.write('\n')
    return os.path.abspath('mop_policy_rule_unit.txt')


def create_policy_rule_mop(policy_rule_yaml, policy_rule_commands_template):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
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


def create_policy_rule_base_mop(policy_rule_base_yaml, policy_rule_commands_template):
    pr_base_dict = read_yaml_file(policy_rule_base_yaml).get('PolicyRuleBase')
    provision_command_dict = read_yaml_file(policy_rule_commands_template).get('commands').get('provision')

    pr_base_commands = list()
    pr_base_commands.append(provision_command_dict.get('begin'))
    for key in pr_base_dict:
        for policy_rule in pr_base_dict.get(key):
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

    pr_yaml = create_policy_rule_yaml(r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml',
                                      pru_yaml)

    create_policy_rule_base_mop(r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRuleBase.yaml',
                                r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\policy_rule_commands.yaml')

    create_policy_rule_unit_mop(pru_yaml,
                                r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\policy_rule_commands.yaml')

    create_policy_rule_mop(pr_yaml,
                           r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\policy_rule_commands.yaml')


if __name__ == "__main__":
    main()
