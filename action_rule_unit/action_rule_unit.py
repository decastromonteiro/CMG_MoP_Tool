from utils.yaml import read_yaml_file, export_yaml
from utils.utils import export_mop_file


def create_action_rule_yaml(policy_rule_yaml, policer_aqp_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml, "PolicyRule")
    policer_aqp_dict = read_yaml_file(policer_aqp_yaml, "AQP-Policers")
    output_action_rule_dict = dict()

    for policy_rule in policy_rule_dict.keys():
        action = policy_rule_dict.get(policy_rule).get(
            "pcc-rule-action"
        )
        if action == "redirect":
            output_action_rule_dict.update({
                "redirect": {
                    "action": "rule-level-redirect"
                }
            })
            break
    for policer in policer_aqp_dict:
        application = policer_aqp_dict[policer]["application"]
        for aso in policer_aqp_dict[policer]["characteristics"]:
            value = aso["value"]
            used_policer = f"{application}-{value}"
            if used_policer not in output_action_rule_dict:
                output_action_rule_dict.update({
                    used_policer: {
                        "action": "characteristic",
                        "characteristic": f"{application}-QoS",
                        "value": value
                    }
                })
    
    return export_yaml(output_action_rule_dict, project_name="ActionRuleUnit")


def create_action_rule_unit_mop(
    action_rule_unit_yaml, policy_rule_commands_template
):
    aru_dict = read_yaml_file(action_rule_unit_yaml).get("ActionRuleUnit")
    provision_command_dict = (
        read_yaml_file(policy_rule_commands_template)
        .get("commands")
        .get("provision")
    )

    pr_base_commands = list()
    pr_base_commands.append(provision_command_dict.get("begin"))
    for key in aru_dict:
        if key == "redirect":
            pr_base_commands.append(provision_command_dict.get("create_redirect_aru"))
        else:
            pr_base_commands.append(provision_command_dict.get("create_aru").format(
                aru_name=key,
                aso=aru_dict[key]["characteristic"],
                aso_value=aru_dict[key]["value"]
            ))
    
    return export_mop_file("action_rule_unit_mop", pr_base_commands)
