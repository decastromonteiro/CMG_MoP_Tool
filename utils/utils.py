import os
from utils.yaml import read_yaml_file
from utils.yaml import export_yaml
import traceback
import re

flow_gate_status_dict = {
    "charge-v": "allow",
    "pass": "allow",
    "drop": "drop",
    "deny": "drop",
    "redirect": "allow",
}


def export_mop_file(mop_name, list_of_commands):
    with open("{}.txt".format(mop_name), "w") as fout:
        for command in list_of_commands:
            fout.write(command)
            fout.write("\n")

    return os.path.abspath("{}.txt".format(mop_name))


def check_spi_rule(
    filter_base_yaml, policy_rule_yaml, domain_name=False, ip_address=False
):
    filter_base_dict = read_yaml_file(filter_base_yaml, "FilterBase")
    pr_dict = read_yaml_file(policy_rule_yaml, "PolicyRule")

    for pr in pr_dict.keys():
        pr_parameters = pr_dict.get(pr)
        he = pr_parameters.get("header-enrichment-type")
        redirect = pr_parameters.get("redirect-uri")
        filter_base = pr_parameters.get("pcc-filter-base-name")
        if filter_base_dict.get(filter_base):
            try:
                if (
                    (he == "null") or (he == "cisco: None") or (not he)
                ) and not redirect:
                    spi_check_set = set()
                    # Same Filter Base might be used several times, therefore SPI may already be present
                    # (if its false, it will forever be false)
                    # (if its true, and it made the #1 criteria, it will continue true)
                    if isinstance(
                        filter_base_dict.get(filter_base).get("SPI"), bool
                    ):
                        continue
                    else:
                        for filter_id in filter_base_dict.get(filter_base):
                            filter_dict = filter_base_dict.get(
                                filter_base
                            ).get(filter_id)
                            if domain_name and ip_address:
                                if (
                                    filter_dict.get("host-name")
                                    or filter_dict.get("l7-uri")
                                    or filter_dict.get("signature")
                                    or filter_dict.get("http-user-agent")
                                ):
                                    spi_check_set.add(False)
                            elif domain_name:
                                if (
                                    filter_dict.get("host-name")
                                    or filter_dict.get("l7-uri")
                                    or filter_dict.get("signature")
                                    or filter_dict.get("destination-address")
                                    or filter_dict.get("http-user-agent")
                                ):
                                    spi_check_set.add(False)
                            elif ip_address:
                                if (
                                    filter_dict.get("host-name")
                                    or filter_dict.get("l7-uri")
                                    or filter_dict.get("signature")
                                    or filter_dict.get("domain-name")
                                    or filter_dict.get("http-user-agent")
                                ):
                                    spi_check_set.add(False)
                            else:
                                spi_check_set.add(False)
                        if False not in spi_check_set:
                            filter_base_dict[filter_base]["SPI"] = True
                        else:
                            filter_base_dict[filter_base]["SPI"] = False

                else:
                    filter_base_dict[filter_base]["SPI"] = False

            except:
                print(
                    f" FilterBase -- {filter_base} -- referecend by PR {pr}  does not exist in FilterBase.yaml."
                )
                traceback.print_exc()

    for filter_base in list(filter_base_dict):
        if not isinstance(filter_base_dict.get(filter_base).get("SPI"), bool):
            filter_base_dict.pop(filter_base)

    return export_yaml(filter_base_dict, "FilterBase")


def check_spi_rule_filters(
    policy_rule_yaml, domain_name=False, ip_address=False
):
    pr_dict = read_yaml_file(policy_rule_yaml, "PolicyRule")
    for pr in pr_dict.keys():
        pr_parameters = pr_dict.get(pr)
        he = pr_parameters.get("header-enrichment-type")
        redirect = pr_parameters.get("redirect-uri")
        if pr_parameters.get("Filters"):
            try:
                if (
                    (he == "null") or (he == "cisco: None") or (not he)
                ) and not redirect:
                    spi_check_set = set()
                    # Same Filter Base might be used several times, therefore SPI may already be present
                    # (if its false, it will forever be false)
                    # (if its true, and it made the #1 criteria, it will continue true)
                    if isinstance(
                        pr_parameters.get("Filters").get("SPI"), bool
                    ):
                        continue
                    else:
                        for filter_id in pr_parameters.get("Filters"):
                            filter_dict = pr_parameters.get("Filters").get(
                                filter_id
                            )
                            if domain_name and ip_address:
                                if (
                                    filter_dict.get("host-name")
                                    or filter_dict.get("l7-uri")
                                    or filter_dict.get("signature")
                                    or filter_dict.get("http-user-agent")
                                ):
                                    spi_check_set.add(False)
                            elif domain_name:
                                if (
                                    filter_dict.get("host-name")
                                    or filter_dict.get("l7-uri")
                                    or filter_dict.get("signature")
                                    or filter_dict.get("destination-address")
                                    or filter_dict.get("http-user-agent")
                                ):
                                    spi_check_set.add(False)
                            elif ip_address:
                                if (
                                    filter_dict.get("host-name")
                                    or filter_dict.get("l7-uri")
                                    or filter_dict.get("signature")
                                    or filter_dict.get("domain-name")
                                    or filter_dict.get("http-user-agent")
                                ):
                                    spi_check_set.add(False)
                            else:
                                spi_check_set.add(False)
                        if False not in spi_check_set:
                            pr_parameters["Filters"]["SPI"] = True
                        else:
                            pr_parameters["Filters"]["SPI"] = False

                else:
                    pr_parameters["Filters"]["SPI"] = False

            except:
                print(f" Filters referecend by PR {pr} has an issue.")
                traceback.print_exc()

    return export_yaml(pr_dict, "PolicyRule")


def check_spi_filter(
    filter_base_yaml, policy_rule_yaml, domain_name=False, ip_address=False
):
    filter_base_dict = read_yaml_file(filter_base_yaml, "FilterBase")
    pr_dict = read_yaml_file(policy_rule_yaml, "PolicyRule")

    for pr in pr_dict.keys():
        pr_parameters = pr_dict.get(pr)
        he = pr_parameters.get("header-enrichment-type")
        redirect = pr_parameters.get("redirect-uri")
        filter_base = pr_parameters.get("pcc-filter-base-name")
        if filter_base_dict.get(filter_base):
            try:
                if (
                    (he == "null") or (he == "cisco: None") or (not he)
                ) and not redirect:
                    # Same Filter Base might be used several times, therefore SPI may already be present
                    # (if its false, it will forever be false)
                    # (if its true, and it made the #1 criteria, it will continue true)
                    if isinstance(
                        filter_base_dict.get(filter_base).get("SPI"), bool
                    ):
                        continue
                    for filter_id in filter_base_dict.get(filter_base):
                        filter_dict = filter_base_dict.get(filter_base).get(
                            filter_id
                        )
                        if domain_name and ip_address:
                            if (
                                filter_dict.get("host-name")
                                or filter_dict.get("l7-uri")
                                or filter_dict.get("signature")
                            ):
                                filter_dict["SPI"] = False
                            else:
                                filter_dict["SPI"] = True
                        elif domain_name:
                            if (
                                filter_dict.get("host-name")
                                or filter_dict.get("l7-uri")
                                or filter_dict.get("signature")
                                or filter_dict.get("destination-address")
                            ):
                                filter_dict["SPI"] = False
                            else:
                                filter_dict["SPI"] = True
                        elif ip_address:
                            if (
                                filter_dict.get("host-name")
                                or filter_dict.get("l7-uri")
                                or filter_dict.get("signature")
                                or filter_dict.get("domain-name")
                            ):
                                filter_dict["SPI"] = False
                            else:
                                filter_dict["SPI"] = True
                        else:
                            filter_dict["SPI"] = False
                    filter_base_dict[filter_base]["SPI"] = True
                else:
                    filter_base_dict[filter_base]["SPI"] = False

            except:
                print(
                    f" FilterBase -- {filter_base} -- referecend by PR {pr}  does not exist in FilterBase.yaml."
                )
                traceback.print_exc()

    for filter_base in list(filter_base_dict):
        if not isinstance(filter_base_dict.get(filter_base).get("SPI"), bool):
            filter_base_dict.pop(filter_base)

    return export_yaml(filter_base_dict, "FilterBase")


def create_unique_pru(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml, "PolicyRule")
    unique_pru_dict = dict()
    used_filterbase_dict = dict()
    for pr_name in policy_rule_dict.keys():
        filter_base = policy_rule_dict.get(pr_name).get("pcc-filter-base-name")
        flow_gate_status = policy_rule_dict.get(pr_name).get("pcc-rule-action")
        if filter_base:
            concat = f"{filter_base}{flow_gate_status}"
        else:
            concat = f"{pr_name}{flow_gate_status}"
        if not unique_pru_dict.get(concat):
            if filter_base:
                if not used_filterbase_dict.get(filter_base):
                    used_filterbase_dict.update({filter_base: 1})
                    unique_pru_dict.update({concat: f"{filter_base}_PRU"})
                else:
                    used_filterbase_dict[filter_base] += 1
                    unique_pru_dict.update(
                        {
                            concat: f"{filter_base}---{used_filterbase_dict[filter_base]}_PRU"
                        }
                    )

            else:
                unique_pru_dict.update({concat: f"{pr_name}_PRU"})
    return export_yaml(unique_pru_dict, "UniquePolicyRuleUnit")


def check_name_length(yaml_input, object_name, max_len):
    object_dict = read_yaml_file(yaml_input, object_name)
    for _object in object_dict:
        if len(_object) > max_len:
            print(
                f"WARNING: The {object_name}: {_object} has a bigger name than {max_len} chars, "
                f"please review it and change it accordingly. "
                f"Its current length is {len(_object)} chars."
            )


def create_rule_filter_dict(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get("PolicyRule")
    policy_rule_filters = dict()
    for policy_rule in policy_rule_dict:
        if policy_rule_dict.get(policy_rule).get("Filters"):
            policy_rule_filters.update(
                {policy_rule: policy_rule_dict.get(policy_rule).get("Filters")}
            )
    return policy_rule_filters


def chuncks(lista, size):
    for i in range(0, len(lista), size):
        yield lista[i : i + size]


def aggregate_address(input_dict, spi_mode):
    if input_dict:
        aggregation_list = dict()
        for key in input_dict:
            if spi_mode:
                if input_dict.get(key).pop("SPI"):
                    list_of_filters_dict = input_dict.get(key)
                    aggregate_addresses = dict()
                    filter_base_aggregation = dict()
                    for filter_name in list_of_filters_dict:
                        if list_of_filters_dict.get(filter_name).get(
                            "destination-address"
                        ) or list_of_filters_dict.get(filter_name).get(
                            "ipv6-destination-address"
                        ):
                            address = None
                            aggregation_string = None
                            if list_of_filters_dict.get(filter_name).get(
                                "destination-address"
                            ):
                                address = list_of_filters_dict.get(
                                    filter_name
                                ).get("destination-address")
                                if ":" not in address:
                                    aggregation_string = (
                                        "v4Protocol{}Port{}Domain{}Host{}URI{}"
                                    )
                                else:
                                    aggregation_string = (
                                        "v6Protocol{}Port{}Domain{}Host{}URI{}"
                                    )
                            elif list_of_filters_dict.get(filter_name).get(
                                "ipv6-destination-address"
                            ):
                                address = list_of_filters_dict.get(
                                    filter_name
                                ).get("ipv6-destination-address")
                                aggregation_string = (
                                    "v6Protocol{}Port{}Domain{}Host{}URI{}"
                                )

                            protocol = list_of_filters_dict.get(
                                filter_name
                            ).get("protocol-id", "0000")
                            ports = list_of_filters_dict.get(filter_name).get(
                                "destination-port-list", "0000"
                            )
                            domain = list_of_filters_dict.get(filter_name).get(
                                "domain-name", "0000"
                            )
                            host = list_of_filters_dict.get(filter_name).get(
                                "host-name", "0000"
                            )
                            uri = list_of_filters_dict.get(filter_name).get(
                                "l7-uri", "0000"
                            )

                            protocol = protocol if protocol else "0000"
                            ports = ports if ports else "0000"
                            domain = domain if domain else "0000"
                            host = host if host else "0000"
                            uri = uri if uri else "0000"

                            aggregation_string = aggregation_string.format(
                                protocol, ports, domain, host, uri
                            )

                            if not aggregate_addresses.get(aggregation_string):
                                aggregate_addresses.update(
                                    {aggregation_string: list()}
                                )
                            if address:
                                aggregate_addresses.get(
                                    aggregation_string
                                ).append(address)

                    filter_base_aggregation.update({key: aggregate_addresses})
                    aggregation_list.update(filter_base_aggregation)
            else:
                if not input_dict.get(key).pop("SPI"):
                    list_of_filters_dict = input_dict.get(key)
                    aggregate_addresses = dict()
                    filter_base_aggregation = dict()
                    for filter_name in list_of_filters_dict:
                        if list_of_filters_dict.get(filter_name).get(
                            "destination-address"
                        ) or list_of_filters_dict.get(filter_name).get(
                            "ipv6-destination-address"
                        ):
                            address = None
                            aggregation_string = None
                            if list_of_filters_dict.get(filter_name).get(
                                "destination-address"
                            ):
                                address = list_of_filters_dict.get(
                                    filter_name
                                ).get("destination-address")
                                if ":" not in address:
                                    aggregation_string = (
                                        "v4Protocol{}Port{}Domain{}Host{}URI{}"
                                    )
                                else:
                                    aggregation_string = (
                                        "v6Protocol{}Port{}Domain{}Host{}URI{}"
                                    )
                            elif list_of_filters_dict.get(filter_name).get(
                                "ipv6-destination-address"
                            ):
                                address = list_of_filters_dict.get(
                                    filter_name
                                ).get("ipv6-destination-address")
                                aggregation_string = (
                                    "v6Protocol{}Port{}Domain{}Host{}URI{}"
                                )

                            protocol = list_of_filters_dict.get(
                                filter_name
                            ).get("protocol-id", "0000")
                            ports = list_of_filters_dict.get(filter_name).get(
                                "destination-port-list", "0000"
                            )
                            domain = list_of_filters_dict.get(filter_name).get(
                                "domain-name", "0000"
                            )
                            host = list_of_filters_dict.get(filter_name).get(
                                "host-name", "0000"
                            )
                            uri = list_of_filters_dict.get(filter_name).get(
                                "l7-uri", "0000"
                            )

                            protocol = protocol if protocol else "0000"
                            ports = ports if ports else "0000"
                            domain = domain if domain else "0000"
                            host = host if host else "0000"
                            uri = uri if uri else "0000"

                            aggregation_string = aggregation_string.format(
                                protocol, ports, domain, host, uri
                            )

                            if not aggregate_addresses.get(aggregation_string):
                                aggregate_addresses.update(
                                    {aggregation_string: list()}
                                )
                            if address:
                                aggregate_addresses.get(
                                    aggregation_string
                                ).append(address)

                    filter_base_aggregation.update({key: aggregate_addresses})
                    aggregation_list.update(filter_base_aggregation)
        return aggregation_list


def get_filter_base(filter_base_yaml, spi_mode):
    filter_base_list = read_yaml_file(filter_base_yaml).get("FilterBase")
    if filter_base_list:
        return aggregate_address(filter_base_list, spi_mode)
    return None


def get_filter(policy_rule_yaml, spi_mode):
    policy_rule_filters = create_rule_filter_dict(policy_rule_yaml)
    if policy_rule_filters:
        return aggregate_address(policy_rule_filters, spi_mode)
    return None


def try_to_group_by_app_name(application_yaml):
    charging_group_dict = dict()
    pattern = re.compile(r"(\S+)(-\d+)")
    application_list = read_yaml_file(application_yaml).get("Application")
    for application in application_list:
        match = pattern.match(application)
        print(match)
        if match:
            charging_group = match.group(1)
        else:
            charging_group = application
        if charging_group in charging_group_dict:
            charging_group_dict[charging_group].append(application)
        else:
            charging_group_dict.update({charging_group: [application]})
    export_yaml(charging_group_dict, project_name="ChargingGroup")
