from charging.charging_rule_unit import create_cru_string
from utils.yaml import read_yaml_file, export_yaml
from utils.utils import export_mop_file
import re


def create_pr_to_charging_rule(policy_rule_yaml, mk_to_ascii):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get("PolicyRule")

    output_dict = dict()

    for key in policy_rule_dict:
        final_string = create_cru_string(
            policy_rule_dict.get(key), mk_to_ascii
        )

        output_dict.update({key: final_string})

    return output_dict


def create_policy_rule_unit_yaml(policy_rule_yaml, unique_pru_yaml, pdr_yaml):
    flow_gate_status_dict = {
        "charge-v": "allow",
        "pass": "allow",
        "drop": "drop",
        "deny": "drop",
        "redirect": "allow",
    }
    unique_pru_dict = read_yaml_file(unique_pru_yaml, "UniquePolicyRuleUnit")
    policy_rule_dict = read_yaml_file(policy_rule_yaml, "PolicyRule")
    if pdr_yaml:
        pdr_dict = read_yaml_file(pdr_yaml, "PDR")
    else:
        pdr_dict = None
    policy_rule_unit_dict = dict()

    for policy_rule in policy_rule_dict.keys():
        filter_base = policy_rule_dict.get(policy_rule).get(
            "pcc-filter-base-name"
        )
        flow_gate_status = policy_rule_dict.get(policy_rule).get(
            "pcc-rule-action"
        )
        if filter_base:
            concat = f"{filter_base}{flow_gate_status}"
        else:
            concat = f"{policy_rule}{flow_gate_status}"
        if not unique_pru_dict.get(concat).startswith("SPI"):
            if None:  # Create Group of Rule Def if statement
                pass
            else:
                pru_name = unique_pru_dict.get(concat)
                charging_group = filter_base if filter_base else policy_rule
                policy_rule_unit_dict.update(
                    {
                        pru_name: {
                            "aa-charging-group": charging_group,
                            "flow-gate-status": flow_gate_status_dict.get(
                                flow_gate_status, flow_gate_status
                            ),
                        }
                    }
                )
                if pdr_dict:
                    policy_rule_unit_dict[pru_name]["pdr-id"] = pdr_dict.get(
                        pru_name
                    )

    return export_yaml(policy_rule_unit_dict, project_name="PolicyRuleUnit")


def create_policy_rule_yaml(policy_rule_yaml, unique_pru_yaml, mk_to_ascii):
    policy_rule_dict = read_yaml_file(policy_rule_yaml, "PolicyRule")
    unique_pru_dict = read_yaml_file(unique_pru_yaml, "UniquePolicyRuleUnit")
    output_policy_rule_dict = dict()
    pr_to_cru_dict = create_pr_to_charging_rule(policy_rule_yaml, mk_to_ascii)

    for policy_rule in policy_rule_dict.keys():
        filter_base = policy_rule_dict.get(policy_rule).get(
            "pcc-filter-base-name"
        )
        flow_gate_status = policy_rule_dict.get(policy_rule).get(
            "pcc-rule-action"
        )
        if filter_base:
            concat = f"{filter_base}{flow_gate_status}"
        else:
            concat = f"{policy_rule}{flow_gate_status}"
        output_policy_rule_dict.update(
            {
                policy_rule: {
                    "policy-rule-unit": unique_pru_dict.get(concat),
                    "charging-rule-unit": pr_to_cru_dict.get(policy_rule),
                    "precedence": policy_rule_dict.get(policy_rule).get(
                        "precedence"
                    ),
                    "action-rule-unit": policy_rule_dict.get(policy_rule).get(
                        "qos-profile-name"
                    ),
                }
            }
        )

    return export_yaml(output_policy_rule_dict, project_name="CMGPolicyRule")


def create_policy_rule_base_yaml(policy_rule_base_yaml):
    prb_dict = read_yaml_file(policy_rule_base_yaml).get("PolicyRuleBase")
    prb_output_dict = dict()
    for key in prb_dict:
        prb_output_dict.update(
            {key: {"policy-rules": prb_dict.get(key), "characteristics": None}}
        )

    return export_yaml(prb_output_dict, project_name="CMGPolicyRuleBase")


def create_policy_rule_unit_mop(
    policy_rule_unit_yaml, policy_rule_commands_template
):
    pru_dict = read_yaml_file(policy_rule_unit_yaml).get("PolicyRuleUnit")
    provision_command_dict = (
        read_yaml_file(policy_rule_commands_template)
        .get("commands")
        .get("provision")
    )

    pr_base_commands = list()
    pr_base_commands.append(provision_command_dict.get("begin"))
    for key in pru_dict:
        pr_base_commands.append(
            provision_command_dict.get("rule_unit").format(
                policy_rule_unit=key,
                charging_group=pru_dict.get(key).get("aa-charging-group"),
            )
        )
        pr_base_commands.append(
            provision_command_dict.get("flow-gate-status").format(
                policy_rule_unit=key,
                flow_gate_status=pru_dict.get(key).get("flow-gate-status"),
            )
        )
        if pru_dict.get(key).get("pdr-id"):
            pr_base_commands.append(
                provision_command_dict.get("rule_unit_pdrid").format(
                    policy_rule_unit=key,
                    pdr_id=pru_dict.get(key).get("pdr-id"),
                )
            )
    pr_base_commands.append(provision_command_dict.get("commit"))

    return export_mop_file("policy_rule_unit_mop", pr_base_commands)


def create_policy_rule_mop(policy_rule_yaml, policy_rule_commands_template):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get("CMGPolicyRule")
    provision_command_dict = (
        read_yaml_file(policy_rule_commands_template)
        .get("commands")
        .get("provision")
    )

    pr_base_commands = list()
    pr_base_commands.append(provision_command_dict.get("begin"))
    for key in policy_rule_dict:
        aru = policy_rule_dict.get(key).get("action-rule-unit")
        aru = aru if aru and aru != "null" else None
        pr_base_commands.append(
            provision_command_dict.get("rule").format(
                policy_rule=key,
                rule_unit=policy_rule_dict.get(key).get("policy-rule-unit"),
                charging_rule_unit=policy_rule_dict.get(key).get(
                    "charging-rule-unit"
                ),
                precedence=policy_rule_dict.get(key).get("precedence"),
                action_rule_unit="action-rule-unit {}".format(aru)
                if aru
                else "",
            )
        )
    pr_base_commands.append(provision_command_dict.get("commit"))

    return export_mop_file("policy_rule_mop", pr_base_commands)


def create_policy_rule_upf_mop(
    policy_rule_yaml, policy_rule_commands_template, sru_list_yaml
):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get("CMGPolicyRule")
    sru_list_dict = read_yaml_file(sru_list_yaml, "SRUList")
    provision_command_dict = (
        read_yaml_file(policy_rule_commands_template)
        .get("commands")
        .get("provision")
    )
    rg_pattern = r"RG(\d+)"
    pr_base_commands = list()
    pr_base_commands.append(provision_command_dict.get("begin"))
    for key in policy_rule_dict:
        aru = policy_rule_dict.get(key).get("action-rule-unit")
        aru = aru if aru and aru != "null" else None
        sru_list = int(
            re.match(
                rg_pattern, policy_rule_dict.get(key).get("charging-rule-unit")
            ).group(1)
        )
        pr_base_commands.append(
            provision_command_dict.get("rule_upf").format(
                policy_rule=key,
                rule_unit=policy_rule_dict.get(key).get("policy-rule-unit"),
                sru_list=sru_list,
                precedence=policy_rule_dict.get(key).get("precedence"),
                action_rule_unit="action-rule-unit {}".format(aru)
                if aru
                else "",
            )
        )

    pr_base_commands.append(provision_command_dict.get("commit"))

    return export_mop_file("upf_policy_rule_mop", pr_base_commands)


def create_policy_rule_base_mop(
    cmg_policy_rule_base_yaml, policy_rule_commands_template
):
    pr_base_dict = read_yaml_file(cmg_policy_rule_base_yaml).get(
        "CMGPolicyRuleBase"
    )
    provision_command_dict = (
        read_yaml_file(policy_rule_commands_template)
        .get("commands")
        .get("provision")
    )

    pr_base_commands = list()
    pr_base_commands.append(provision_command_dict.get("begin"))
    for key in pr_base_dict:
        for policy_rule in pr_base_dict.get(key).get("policy-rules"):
            pr_base_commands.append(
                provision_command_dict.get("rule_base").format(
                    policy_rule_base=key, policy_rule=policy_rule
                )
            )

    pr_base_commands.append(provision_command_dict.get("commit"))

    return export_mop_file("policy_rule_base_mop", pr_base_commands)


def main():
    pass


if __name__ == "__main__":
    main()
