import re
# todo: deal with group-of-ruledefs when rule is dynamic
from utils.utils import check_spi_rule, check_spi_filter
from utils.yaml import read_yaml_file, export_yaml
import ipaddress
import logging
from utils.header_fields_convertion import cisco_to_cmg_he_conversion
from urllib.parse import urlparse

# Initiate Logging
logging.basicConfig(filename='cisco_parser.log', filemode='w', format='%(levelname)s:%(message)s', level=logging.INFO)


# Context Config Extractor
def get_context_config(cisco_input, start, end, yaml_name, exclusion=None):
    # rule_name Pattern
    name_pattern = r'{} (.+)'.format(start)
    pattern = re.compile(name_pattern)
    # Variables to hold ruledef parameters
    d = dict()
    context_name = None
    # Main Logic
    with open(cisco_input) as fin:
        for line in fin:
            line = line.strip()
            # Check for exclusion
            if exclusion:
                if line.startswith(exclusion):
                    continue
            if line.startswith(start):
                match_name = re.findall(pattern, line)
                if match_name:
                    context_name = match_name[0]
                    child_list = list()
                    d.update({
                        context_name:
                            {'child': child_list}
                    })
            # Catch all parameters that can be configured inside the rule-def
            if context_name:
                if not line.startswith(end):
                    try:
                        if not line.startswith(start):
                            child_list.append(line)
                    except UnboundLocalError:
                        logging.info(f'Context: Context Config could not process -- {context_name} -- correctly')
                else:
                    context_name = None
    return export_yaml(d, project_name=yaml_name)


# Raw YAML Parsers
def parse_raw_host_pool(raw_host_pool_path):
    ip_address_host_pool_pattern = 'ip (.+)'
    range_pattern = 'range (.+) to (.+)'
    host_pool_dict = dict()
    raw_host_pool_dict = read_yaml_file(raw_host_pool_path, 'RawHostPool')
    for host_pool in raw_host_pool_dict:
        parameters = raw_host_pool_dict.get(host_pool).get('child')
        host_pool_dict.update({
            host_pool: list()
        })
        for parameter in parameters:
            parameter = parameter.strip()
            if parameter.startswith('ip'):
                ip_address = re.findall(ip_address_host_pool_pattern, parameter)[0]
                if ip_address.startswith('range'):
                    # "range 209.117.21.129 to 209.117.21.142"
                    match = re.match(range_pattern, ip_address)
                    if match:
                        ip_address = [ipaddr.exploded for ipaddr in ipaddress.summarize_address_range(
                            ipaddress.ip_address(match.group(1)),
                            ipaddress.ip_address(match.group(2))
                        )
                                      ]
                if host_pool:
                    if isinstance(ip_address, list):
                        host_pool_dict.get(host_pool).extend(ip_address)
                    else:
                        host_pool_dict.get(host_pool).append(ip_address)
            else:
                logging.info(
                    f'HostPool: The line -- {parameter} -- beloging to host-pool -- {host_pool} -- '
                    f'was not processed by the script.')

    return export_yaml(host_pool_dict, project_name='HostPool')


def parse_raw_rulebase(raw_rulebase_path, group_of_ruledefs_path):
    # Patterns
    wo_mk_pattern = r'action priority (\d+) ruledef (\S+) charging-action (\S+)'
    with_mk_pattern = r'action priority (\d+) ruledef (\S+) charging-action (\S+) monitoring-key (\S+)'
    dynamic_pattern = r'action priority (\d+) dynamic-only ruledef (\S+) charging-action (\S+)'
    dynamic_mk_pattern = r'action priority (\d+) dynamic-only ruledef (\S+) charging-action (\S+) monitoring-key (\S+)'
    group_ruledef_pattern = r'action priority (\d+) group-of-ruledefs (\S+) charging-action (\S+)'
    group_ruledef_pattern_mk = r'action priority (\d+) group-of-ruledefs (\S+) charging-action (\S+) ' \
                               r'monitoring-key (\S+)'
    dyn_group_ruledef_pattern = r'action priority (\d+) dynamic-only group-of-ruledefs (\S+) charging-action (\S+)'
    dyn_group_ruledef_pattern_mk = r'action priority (\d+) dynamic-only group-of-ruledefs (\S+) ' \
                                   r'charging-action (\S+) monitoring-key (\S+)'

    raw_rule_base = read_yaml_file(raw_rulebase_path, 'RawRuleBase')
    group_of_ruledef_dict = read_yaml_file(group_of_ruledefs_path).get('GroupRuleDefCisco')
    rule_base_dict = dict()
    for rulebase in raw_rule_base:
        parameter_dict = dict()
        parameters = raw_rule_base.get(rulebase).get('child')
        rule_base_dict.update({
            rulebase:
                parameter_dict

        })
        for parameter in parameters:
            try:
                if ('dynamic-only group-of-ruledefs' in parameter) and ('monitoring-key' in parameter):
                    match = re.match(dyn_group_ruledef_pattern_mk, parameter)
                    ruledef_list = group_of_ruledef_dict.get(match.group(2))
                    precedence = int(match.group(1))
                    for ruledef in ruledef_list:
                        parameter_dict.update(
                            {f"{ruledef}+++{match.group(2)}":
                                {
                                    'precedence': precedence,
                                    'charging-action': match.group(3),
                                    'monitoring-key': match.group(4),
                                    'dynamic': True
                                }}
                        )
                        # Make precedence unique for ruledefs inside of group-of-ruledefs
                        precedence += 2
                elif 'dynamic-only group-of-ruledefs' in parameter:
                    match = re.match(dyn_group_ruledef_pattern, parameter)
                    ruledef_list = group_of_ruledef_dict.get(match.group(2))
                    precedence = int(match.group(1))
                    for ruledef in ruledef_list:
                        parameter_dict.update(
                            {f"{ruledef}+++{match.group(2)}":
                                {
                                    'precedence': precedence,
                                    'charging-action': match.group(3),
                                    'monitoring-key': None,
                                    'dynamic': True
                                }}
                        )
                        # Make precedence unique for ruledefs inside of group-of-ruledefs
                        precedence += 2
                elif ('group-of-ruledefs' in parameter) and ('monitoring-key' in parameter):
                    match = re.match(group_ruledef_pattern_mk, parameter)
                    ruledef_list = group_of_ruledef_dict.get(match.group(2))
                    precedence = int(match.group(1))
                    for ruledef in ruledef_list:
                        parameter_dict.update(
                            {f"{ruledef}+++{match.group(2)}":
                                {
                                    'precedence': precedence,
                                    'charging-action': match.group(3),
                                    'monitoring-key': match.group(4),
                                    'dynamic': False
                                }}
                        )
                        # Make precedence unique for ruledefs inside of group-of-ruledefs
                        precedence += 2
                elif 'group-of-ruledefs' in parameter:
                    match = re.match(group_ruledef_pattern, parameter)
                    ruledef_list = group_of_ruledef_dict.get(match.group(2))
                    precedence = int(match.group(1))
                    for ruledef in ruledef_list:
                        parameter_dict.update(
                            {f"{ruledef}+++{match.group(2)}":
                                {
                                    'precedence': precedence,
                                    'charging-action': match.group(3),
                                    'monitoring-key': None,
                                    'dynamic': False
                                }}
                        )
                        # Make precedence unique for ruledefs inside of group-of-ruledefs
                        precedence += 2
                elif ('dynamic-only ruledef' in parameter) and ('monitoring-key' in parameter):
                    match = re.match(dynamic_mk_pattern, parameter)
                    parameter_dict.update(
                        {match.group(2):
                            {
                                'precedence': match.group(1),
                                'charging-action': match.group(3),
                                'monitoring-key': match.group(4),
                                'dynamic': True
                            }}
                    )
                elif 'dynamic-only ruledef' in parameter:
                    match = re.match(dynamic_pattern, parameter)
                    parameter_dict.update(
                        {match.group(2):
                            {
                                'precedence': match.group(1),
                                'charging-action': match.group(3),
                                'monitoring-key': None,
                                'dynamic': True
                            }}
                    )
                elif ('ruledef' in parameter) and ('monitoring-key' in parameter):
                    match = re.match(with_mk_pattern, parameter)
                    parameter_dict.update(
                        {match.group(2):
                            {
                                'precedence': match.group(1),
                                'charging-action': match.group(3),
                                'monitoring-key': match.group(4),
                                'dynamic': False
                            }}
                    )
                elif 'ruledef' in parameter:
                    match = re.match(wo_mk_pattern, parameter)
                    parameter_dict.update(
                        {match.group(2):
                            {
                                'precedence': match.group(1),
                                'charging-action': match.group(3),
                                'monitoring-key': None,
                                'dynamic': False
                            }}
                    )
                else:
                    logging.info(
                        f'PolicyRuleBase: The line -- {parameter} -- belonging to -- {rulebase} -- '
                        f'was not processed by the script.')
            except:
                logging.info(
                    f'PolicyRuleBase: The line -- {parameter} -- belonging to -- {rulebase} -- '
                    f'was not processed by the script.')

    return export_yaml(rule_base_dict, project_name='PolicyRuleBaseCisco')


def parse_raw_group_of_ruledef(raw_group_of_ruledef_path):
    rule_name_pattern = r'\d+ ruledef (.+)'
    group_of_ruledef_dict = dict()
    raw_group_ruledef_dict = read_yaml_file(raw_group_of_ruledef_path, 'RawGroupofRuleDef')
    for group_of_rule_def in raw_group_ruledef_dict:
        parameters = raw_group_ruledef_dict.get(group_of_rule_def).get('child')
        group_of_ruledef_dict.update(
            {group_of_rule_def: list()}
        )
        for parameter in parameters:
            if parameter.startswith('add-ruledef'):
                match_ruledef = re.findall(rule_name_pattern, parameter)
                if match_ruledef:
                    ruledef_name = match_ruledef[0]
                    group_of_ruledef_dict.get(group_of_rule_def).append(ruledef_name)
            else:
                logging.info(
                    f'GroupRuleDef: The line {parameter} belonging to Group-of-RuleDefs {group_of_rule_def} was '
                    f'not processed by the script.')

    return export_yaml(group_of_ruledef_dict, project_name='GroupRuleDefCisco')


def parse_raw_ruledef(raw_rule_def_path, parsed_host_pool_path):
    # Patterns
    ip_address_pattern = r'ip server-ip-address = (.+)'
    host_pool_pattern = r'ip server-ip-address range host-pool (.+)'
    www_url_pattern = r'www url (.+)'
    http_url_pattern = r'http url (.+)'
    secure_http_pattern = r'secure-http any-match = (.+)'
    tcp_port_pattern = r'tcp either-port (?:=|range) (.+)'
    udp_port_pattern = r'udp either-port (?:=|range) (.+)'
    protocol_signature = r'p2p protocol = (.+)'
    http_host = r'http host (.+)'
    tls_sni = r'p2p app-identifier tls-sni (.+)'
    quic_sni = r'p2p app-identifier quic-sni (.+)'
    ip_server_domain_pattern = r'ip server-domain-name (.+)'
    dst_address_pattern = r'ip dst-address = (.+)'
    www_domain_pattern = r'www domain (.+)'
    http_domain_pattern = r'http domain (.+)'
    www_host_pattern = r'www host (.+)'

    patterns = [ip_address_pattern,
                host_pool_pattern,
                www_url_pattern,
                http_url_pattern,
                secure_http_pattern,
                tcp_port_pattern,
                udp_port_pattern,
                protocol_signature,
                http_host,
                tls_sni,
                ip_server_domain_pattern,
                dst_address_pattern,
                www_domain_pattern,
                http_domain_pattern,
                www_host_pattern,
                quic_sni]

    complex_pattern = re.compile('|'.join([f'({i})' for i in patterns]))

    #
    ruledef_dict = dict()
    # Load RawRuleDef
    raw_rule_def = read_yaml_file(raw_rule_def_path, 'RawRuleDef')
    # Load Host Pool
    host_pool_dict = read_yaml_file(parsed_host_pool_path, 'HostPool')

    # Start Parser
    for rule_def in raw_rule_def:
        filters = raw_rule_def.get(rule_def).get('child')
        filter_dict = dict()
        ruledef_dict.update(
            {rule_def: {
                'Filters': filter_dict
            }}
        )
        if 'multi-line-or all-lines' in filters:
            count = 0
            filters.remove('multi-line-or all-lines')
            if any("either-port" in item for item in filters):
                port = ",".join(

                    set([(complex_pattern.match(item).group(12) or complex_pattern.match(item).group(14)) for item in
                         filters if
                         ("either-port" in item)])
                )
                if any("tcp either-port" in item for item in filters) and any(
                        "udp either-port" in item for item in filters):
                    protocol_id = "6,17"
                elif any("tcp either-port" in item for item in filters):
                    protocol_id = "6"
                else:
                    protocol_id = "17"
                filter_dict.update({count: {
                    "destination-address": None,
                    "url": None,
                    "protocol-id": protocol_id,
                    "port": port,
                    "signature": None,
                    "http-host": None,
                    "domain-name": None
                }}
                )
                count += 1
            # Remove port association parameters from filter
            filters = (item for item in filters if 'either-port' not in item)
            for parameter in filters:
                match = complex_pattern.match(parameter)
                try:
                    if match.group(4):
                        ip_addr_list = host_pool_dict.get(match.group(4))
                        for ip in ip_addr_list:
                            filter_dict.update({count: {
                                "destination-address": ip,
                                "url": pattern_conversion(match.group(6)) or pattern_conversion(
                                    match.group(8)),
                                "protocol-id": None,
                                "port": None,
                                "signature": match.group(16),
                                "http-host": pattern_conversion(match.group(18)) or pattern_conversion(
                                    match.group(20)) or pattern_conversion(match.group(30)) or pattern_conversion(
                                    match.group(32)),
                                "domain-name": pattern_conversion(match.group(22)) or pattern_conversion(
                                    match.group(26)) or pattern_conversion(match.group(28))
                            }}
                            )
                            count += 1
                    else:
                        filter_dict.update(
                            {count: {
                                "destination-address": match.group(2) or match.group(24),
                                "url": pattern_conversion(match.group(6)) or pattern_conversion(
                                    match.group(8)),
                                "protocol-id": None,
                                "port": None,
                                "signature": match.group(16),
                                "http-host": pattern_conversion(match.group(18)) or pattern_conversion(
                                    match.group(20)) or pattern_conversion(match.group(30)) or pattern_conversion(
                                    match.group(32)),
                                "domain-name": pattern_conversion(match.group(22)) or pattern_conversion(
                                    match.group(26)) or pattern_conversion(match.group(28))
                            }}
                        )
                        count += 1
                except AttributeError:
                    logging.info(
                        f'RuleDef: The line -- {parameter} -- belonging to -- {rule_def} -- '
                        f'was not processed by the script.')

        else:
            destination_address = None
            host_pool = None
            url = None
            protocol_id = None
            port = None
            signature = None
            http_host = None
            domain_name = None
            for parameter in filters:
                match = complex_pattern.match(parameter)
                if match:
                    tcp = match.group(12)
                    udp = match.group(14)

                    destination_address = (match.group(2) or match.group(24)) if (
                            match.group(2) or match.group(24)) else destination_address
                    host_pool = match.group(4) if match.group(4) else host_pool
                    url = (pattern_conversion(match.group(6)) or pattern_conversion(
                        match.group(8))) if (pattern_conversion(match.group(6)) or pattern_conversion(
                        match.group(8))) else url
                    protocol_id = protocol_id_calc(tcp, udp) if protocol_id_calc(tcp, udp) else protocol_id
                    port = (tcp or udp) if (tcp or udp) else port
                    signature = match.group(16) if match.group(16) else signature
                    http_host = (pattern_conversion(match.group(18)) or pattern_conversion(
                        match.group(20)) or pattern_conversion(match.group(30)) or pattern_conversion(
                        match.group(32))) if (pattern_conversion(match.group(18)) or pattern_conversion(
                        match.group(20)) or pattern_conversion(match.group(30)) or pattern_conversion(
                        match.group(32))) else http_host
                    domain_name = (pattern_conversion(match.group(22)) or pattern_conversion(
                        match.group(26)) or pattern_conversion(match.group(28))) if (
                            pattern_conversion(match.group(22)) or pattern_conversion(
                        match.group(26)) or pattern_conversion(match.group(28))) else domain_name
                else:
                    logging.info(
                        f'RuleDef: The line -- {parameter} -- belonging to -- {rule_def} -- '
                        f'was not processed by the script.')
            if host_pool:
                ip_addr_list = host_pool_dict.get(host_pool)
                count = 0
                for ip in ip_addr_list:
                    filter_dict.update(
                        {count: {
                            "destination-address": ip,
                            "url": url,
                            "protocol-id": protocol_id,
                            "port": port,
                            "signature": signature,
                            "http-host": http_host,
                            "domain-name": domain_name
                        }}
                    )
                    count += 1
            else:
                filter_dict.update(
                    {0: {
                        "destination-address": destination_address,
                        "url": url,
                        "protocol-id": protocol_id,
                        "port": port,
                        "signature": signature,
                        "http-host": http_host,
                        "domain-name": domain_name
                    }}
                )

    return export_yaml(ruledef_dict, project_name='RuleDef')


def parse_raw_charging_action(raw_charging_action_path):
    contend_id_pattern = r'content-id (\d+)'
    service_id_pattern = r'service-identifier (\d+)'
    rating_group_pattern = r'cca charging credit rating-group (\d+)'
    flow_action_pattern = r'flow action (.+)'
    flow_limit_pattern = r'flow limit-for-bandwidth direction (\S+) peak-data-rate (\d+) ' \
                         r'peak-burst-size (\d+) violate-action (\S+)'
    enc_header_enrich_pattern = r'xheader-insert xheader-format (\S+) encryption (\S+) encrypted key (\S+)'
    header_enrich_pattern = r'xheader-insert xheader-format (\S+)'

    charging_action_dict = dict()

    raw_charging_action_dict = read_yaml_file(raw_charging_action_path, 'RawChargingAction')
    for charging_action in raw_charging_action_dict:
        parameter_dict = dict()
        flow_limit_dict = dict()
        charging_action_dict.update(
            {charging_action: parameter_dict}
        )
        parameters = raw_charging_action_dict.get(charging_action).get('child')
        # Define charging method
        if any('cca charging credit' in item for item in parameters):
            parameter_dict['charging-method'] = 'both'
        else:
            parameter_dict['charging-method'] = 'offline'
        # Loop to parse parameters
        for parameter in parameters:
            try:
                if parameter.startswith('content-id'):
                    match = re.match(contend_id_pattern, parameter)
                    parameter_dict['content-id'] = match.group(1)
                elif parameter.startswith('service-identifier'):
                    match = re.match(service_id_pattern, parameter)
                    parameter_dict['service-id'] = match.group(1)
                elif parameter.startswith('cca charging credit rating-group'):
                    match = re.match(rating_group_pattern, parameter)
                    parameter_dict['rating-group'] = match.group(1)
                elif parameter.startswith('flow action'):
                    match = re.match(flow_action_pattern, parameter)
                    parameter_dict['flow-action'] = match.group(1)
                elif parameter.startswith('flow limit'):
                    match = re.match(flow_limit_pattern, parameter)
                    flow_limit_dict.update(
                        {
                            match.group(1): {'peak-data-rate': match.group(2),
                                             'peak-burst-size': match.group(3),
                                             'violate-action': match.group(4)

                                             }
                        }
                    )
                    parameter_dict['flow-limit'] = flow_limit_dict
                elif 'encrypted' in parameter:
                    match = re.match(enc_header_enrich_pattern, parameter)
                    parameter_dict['header-enrich'] = {
                        'he-template': match.group(1),
                        'encryption': match.group(2),
                        'key': match.group(3)
                    }
                elif parameter.startswith('xheader-insert'):
                    match = re.match(header_enrich_pattern, parameter)
                    parameter_dict['header-enrich'] = {
                        'he-template': match.group(1),
                        'encryption': None,
                        'key': None
                    }

                else:
                    logging.info(
                        f'ChargingAction: The line -- {parameter} -- belonging to '
                        f'-- {charging_action} -- was not processed by the script.')
            except:
                logging.info(
                    f'ChargingAction: The line -- {parameter} -- belonging to '
                    f'-- {charging_action} -- was not processed by the script.')

    return export_yaml(charging_action_dict, 'ChargingActionCisco')


def parse_raw_he_template(raw_he_template_path, cmg_he=cisco_to_cmg_he_conversion):
    enc_variable_field_pattern = r'insert (.+) variable (.+) encrypt'
    variable_field_pattern = r'insert (.+) variable (.+)'
    constant_field_pattern = r'insert (.+) string-constant (.+)'
    he_template_dict = dict()

    raw_he_template_dict = read_yaml_file(raw_he_template_path, 'RawHETemplate')
    for he_template in raw_he_template_dict:
        field_dict = dict()
        he_template_dict.update(
            {he_template: {
                'fields': field_dict
            }}
        )
        parameters = raw_he_template_dict.get(he_template).get('child')
        if not parameters:
            continue
        field_count = 0
        for parameter in parameters:
            try:
                if 'encrypt' in parameter:
                    match = re.match(enc_variable_field_pattern, parameter)
                    field = match.group(2).replace('delete-existing', '').strip()
                    field_dict.update(
                        {field_count: {'field': cmg_he.get(field, field),
                                       'field_name': match.group(1),
                                       'encrypt': True}
                         }
                    )
                    field_count += 1
                elif 'variable' in parameter:
                    match = re.match(variable_field_pattern, parameter)
                    field = match.group(2).replace('delete-existing', '').strip()
                    field_dict.update(
                        {field_count: {'field': cmg_he.get(field, field),
                                       'field_name': match.group(1),
                                       'encrypt': False}
                         }
                    )
                    field_count += 1
                else:
                    match = re.match(constant_field_pattern, parameter)
                    field_dict.update(
                        {field_count: {'field': cmg_he.get("string-constant " + match.group(2),
                                                           "string-constant " + match.group(2)),
                                       'field_name': match.group(1),
                                       'encrypt': False}
                         }
                    )
                    field_count += 1
            except:
                logging.info(f'HE-TEMPLATE: The line -- {parameter} -- was not processed by the script')
    return export_yaml(he_template_dict, 'CiscoHETemplate')


# From Cisco to BaseYAML
def create_filterbase_yaml(parsed_ruledef_yaml):
    ruledef_dict = read_yaml_file(parsed_ruledef_yaml, 'RuleDef')
    filter_base_dict = dict()
    for ruledef in ruledef_dict.keys():
        filters_dict = dict()
        filters = ruledef_dict.get(ruledef).get('Filters')
        filter_base = ruledef
        filter_base_dict.update(
            {filter_base: filters_dict}
        )
        for filter_number in filters:
            if filters.get(filter_number).get('url'):
                parsed_url = urlparse(filters.get(filter_number).get('url'))
                host = parsed_url.netloc
                uri = parsed_url.path
                if uri and not host:
                    host, uri = uri, None
            else:
                host = filters.get(filter_number).get('http-host')
                uri = None
            destination_address = filters.get(filter_number).get('destination-address')
            destination_port_list = filters.get(filter_number).get('port')
            protocol_id = filters.get(filter_number).get('protocol-id')
            domain_name = filters.get(filter_number).get('domain-name')
            l7_uri = uri
            host_name = host
            signature = filters.get(filter_number).get('signature')

            filters_dict.update({filter_number: {'destination-address': destination_address,
                                                 'destination-port-list': destination_port_list,
                                                 'domain-name': domain_name,
                                                 'protocol-id': protocol_id,
                                                 'host-name': host_name,
                                                 'l7-uri': l7_uri,
                                                 'signature': signature
                                                 }
                                 }
                                )

    return export_yaml(filter_base_dict, 'FilterBase')


def create_policy_rule_yaml(parsed_rulebase_path, parsed_charging_action_path, unique_policy_rule_path,
                            unique_template_path):
    rulebase_dict = read_yaml_file(parsed_rulebase_path, 'PolicyRuleBaseCisco')
    charging_action_dict = read_yaml_file(parsed_charging_action_path, 'ChargingActionCisco')
    unique_policy_rule_dict = read_yaml_file(unique_policy_rule_path, 'UniquePolicyRule')
    unique_template_dict = read_yaml_file(unique_template_path, 'UniqueHETemplate')
    policy_rule_dict = dict()

    for rulebase in rulebase_dict.keys():
        ruledef_dict = rulebase_dict.get(rulebase)
        for ruledef in ruledef_dict.keys():
            ruledef_name, concat = policy_rule_dict_to_string(ruledef_dict.get(ruledef), ruledef)
            if not policy_rule_dict.get(concat):
                ruledef_parameters = ruledef_dict.get(ruledef)
                policy_rule_parameters = dict()
                policy_rule = unique_policy_rule_dict.get(concat)
                policy_rule_dict.update(
                    {policy_rule: policy_rule_parameters}
                )
                try:
                    charging_action_name = ruledef_dict.get(ruledef).get('charging-action')
                    charging_action = charging_action_dict.get(charging_action_name)
                    action, redirect_uri = parse_flow_action(charging_action.get('flow-action'))
                    if charging_action.get('flow-limit'):
                        downlink_bs = charging_action.get('flow-limit').get('downlink').get('peak-burst-size')
                        downlink_dr = charging_action.get('flow-limit').get('downlink').get('peak-data-rate')
                        uplink_bs = charging_action.get('flow-limit').get('downlink').get('peak-burst-size')
                        uplink_dr = charging_action.get('flow-limit').get('downlink').get('peak-data-rate')
                        qos_profile = create_qos_profile_name(downlink_bs, downlink_dr, uplink_bs, uplink_dr)
                    else:
                        qos_profile = None
                    he = charging_action.get('header-enrich')
                    if he:
                        concat = f"{he.get('he-template')}___{he.get('encryption')}___{he.get('key')}"
                        he_template = unique_template_dict.get(concat)
                    else:
                        he_template = None
                    policy_rule_parameters.update(
                        {
                            'Filters': None,
                            'charging-method': charging_action.get('charging-method'),
                            'header-enrichment-type': f'cisco: {he_template}',
                            'monitoring-key': ruledef_parameters.get('monitoring-key'),
                            'pcc-filter-base-name': ruledef_name,
                            'pcc-rule-action': action,
                            'precedence': ruledef_parameters.get('precedence'),
                            'qos-profile-name': qos_profile,
                            'rating-group': charging_action.get('content-id'),
                            'redirect-uri': redirect_uri,
                            'service-id': charging_action.get('service-id'),
                            'ocs-rating-group': charging_action.get('rating-group')
                        }
                    )
                except AttributeError:
                    print(ruledef, ruledef_parameters)

    return export_yaml(policy_rule_dict, 'PolicyRule')


def create_policy_rule_base_yaml(rulebase_path, unique_policy_rule_path):
    rulebase_dict = read_yaml_file(rulebase_path, 'PolicyRuleBaseCisco')
    unique_policy_rule_dict = read_yaml_file(unique_policy_rule_path, 'UniquePolicyRule')
    baseyaml_rulebase_dict = dict()
    for rulebase in rulebase_dict.keys():
        policy_rule_list = list()
        baseyaml_rulebase_dict.update(
            {rulebase: policy_rule_list}
        )
        ruledef_dict = rulebase_dict.get(rulebase)
        for ruledef in ruledef_dict.keys():
            ruledef_name, concat = policy_rule_dict_to_string(ruledef_dict.get(ruledef), ruledef)
            if not ruledef_dict.get(ruledef).get('dynamic'):
                policy_rule_list.append(unique_policy_rule_dict.get(concat))

    return export_yaml(baseyaml_rulebase_dict, 'PolicyRuleBase')


def create_qos_yaml(parsed_charging_action):
    ca_dict = read_yaml_file(parsed_charging_action, 'ChargingActionCisco')
    qos_dict = dict()

    for ca in ca_dict.keys():
        if ca_dict.get(ca).get('flow-limit'):
            downlink_bs = ca_dict.get(ca).get('flow-limit').get('downlink').get('peak-burst-size')
            downlink_dr = ca_dict.get(ca).get('flow-limit').get('downlink').get('peak-data-rate')
            uplink_bs = ca_dict.get(ca).get('flow-limit').get('downlink').get('peak-burst-size')
            uplink_dr = ca_dict.get(ca).get('flow-limit').get('downlink').get('peak-data-rate')
            qos_profile = create_qos_profile_name(downlink_bs, downlink_dr, uplink_bs, uplink_dr)
            qos_dict.update(
                {
                    qos_profile: {
                        'downlink': {'peak-burst-size': downlink_bs, 'peak-data-rate': downlink_dr},
                        'uplink': {'peak-burst-size': uplink_bs, 'peak-data-rate': uplink_dr}
                    }
                }
            )
    return export_yaml(qos_dict, 'QoSProfiles')


# Auxiliary Functions
def pattern_conversion(filter_string):
    if filter_string:
        if filter_string.startswith('='):
            return filter_string.replace('=', '').strip()
        elif filter_string.startswith('starts-with'):
            return filter_string.replace('starts-with', '').strip() + '*'
        elif filter_string.startswith('contains'):
            return '*' + filter_string.replace('contains', '').strip() + '*'
        elif filter_string.startswith('ends-with'):
            return '*' + filter_string.replace('ends-with', '').strip()
        else:
            return filter_string

    return None


def create_unique_policy_rules(parsed_rulebase_path):
    """
    This is an auxiliary function created to make each Policy Rule Name unique.
    This function receives the YAML file PolicyRuleBaseCisco
    Process this file in order to concatenate ruledef with charging-action and monitoring-key
    Creates a dictionary where the key is the concatenation and the value is ruledef concatenated with a number
    Example:
        RuleBase: 3si-rs
        Ruledef: blacklistblock_01
        Key: blacklistblock_01___drop___None
        Value: blacklistblock_01---1
    :return: dictionary
    """
    unique_pr_dict = dict()
    used_ruledef_dict = dict()
    rulebase_dict = read_yaml_file(parsed_rulebase_path, 'PolicyRuleBaseCisco')
    for rulebase in rulebase_dict.keys():
        ruledef_dict = rulebase_dict.get(rulebase)
        for ruledef in ruledef_dict.keys():
            ruledef_name, concat = policy_rule_dict_to_string(ruledef_dict.get(ruledef), ruledef)
            if not unique_pr_dict.get(concat):
                if not used_ruledef_dict.get(ruledef_name):
                    used_ruledef_dict.update({ruledef_name: 1})
                else:
                    used_ruledef_dict[ruledef_name] += 1
                unique_pr_dict.update({concat: f"{ruledef_name}---{used_ruledef_dict[ruledef_name]}"})

    return export_yaml(unique_pr_dict, 'UniquePolicyRule')


def protocol_id_calc(tcp, udp):
    if tcp:
        return "6"
    elif udp:
        return "17"
    else:
        return None


def parse_flow_action(flow_action):
    readdress_pattern = re.compile(r'readdress (.+)')
    redirect_url_pattern = re.compile(r'redirect-url (.+)')
    if flow_action:
        match = re.match(redirect_url_pattern, flow_action) or re.match(readdress_pattern, flow_action)
    else:
        match = None
    if match:
        redirect_uri = match.group(1)
        action = 'redirect'
    else:
        redirect_uri = None
        action = {'terminate-flow': 'drop', 'discard': 'drop'}.get(flow_action, 'charge-v')

    return action, redirect_uri


def policy_rule_dict_to_string(ruledef_parameter_dict, ruledef):
    """
    Receives dict of PR from Policy Rule Base
    Returns key, ruledef_name, concat string
    :param pr_dict:
    :return:
    """
    ruledef_group_pattern = r"(\S+)\+\+\+(\S+)"
    ruledef_name_match = re.match(ruledef_group_pattern, ruledef)
    if ruledef_name_match:
        ruledef_name = ruledef_name_match.group(1)
        ruledefgroup = ruledef_name_match.group(2)
    else:
        ruledef_name = ruledef
        ruledefgroup = None

    concat = f"{ruledef_name}___" \
             f"{ruledef_parameter_dict.get('charging-action')}___" \
             f"{ruledef_parameter_dict.get('monitoring-key')}___" \
             f"{ruledefgroup}"

    return ruledef_name, concat


def create_qos_profile_name(downlink_bs, downlink_dr, uplink_bs, uplink_dr):
    return f"DL-BS{downlink_bs}-DR{downlink_dr}-UL-BS{uplink_bs}-DR{uplink_dr}"


def make_unique_template(charging_action_yaml):
    unique_template_dict = dict()
    used_template_dict = dict()
    ca_dict = read_yaml_file(charging_action_yaml, 'ChargingActionCisco')
    for ca in ca_dict.keys():
        d = ca_dict.get(ca).get('header-enrich')
        if d:
            concat = f"{d.get('he-template')}___{d.get('encryption')}___{d.get('key')}"
            if not unique_template_dict.get(concat):
                if not used_template_dict.get(d.get('he-template')):
                    used_template_dict.update({d.get('he-template'): 1})
                else:
                    used_template_dict[d.get('he-template')] += 1
                unique_template_dict.update(
                    {concat: f"{d.get('he-template')}---{used_template_dict[d.get('he-template')]}"})

    return export_yaml(unique_template_dict, 'UniqueHETemplate')


if __name__ == "__main__":
    cisco_input = r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects' \
                  r'\CMG_MoP_Tool\new_cisco_input\SEPCF010_ecs.log'
    ar_cisco_input = r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects' \
                     r'\CMG_MoP_Tool\parsers\input_cisco\ECS-TOR-ASR5K5-1-2908 .log'

    # # Extract Objects from Cisco Config
    # raw_charging_action_path = get_context_config(ar_cisco_input, 'charging-action', '#exit', 'RawChargingAction')
    # raw_ruledef_path = get_context_config(ar_cisco_input, 'ruledef', '#exit', 'RawRuleDef')
    # raw_host_pool_path = get_context_config(ar_cisco_input, 'host-pool', '#exit', 'RawHostPool')
    # raw_rulebase_path = get_context_config(ar_cisco_input, 'rulebase', '#exit', 'RawRuleBase', exclusion='rulebase = ')
    # raw_group_of_ruledef_path = get_context_config(ar_cisco_input, 'group-of-ruledefs', '#exit', 'RawGroupofRuleDef')
    # raw_he_template_path = get_context_config(ar_cisco_input, 'xheader-format', '#exit', 'RawHETemplate')
    #
    # # Parse Raw YAML Files
    # host_pool_path = parse_raw_host_pool(raw_host_pool_path)
    # ruledef_path = parse_raw_ruledef(raw_ruledef_path, host_pool_path)
    # group_of_ruledef_path = parse_raw_group_of_ruledef(raw_group_of_ruledef_path)
    # parsed_rulebase_path = parse_raw_rulebase(raw_rulebase_path, group_of_ruledef_path)
    # he_template_path = parse_raw_he_template(raw_he_template_path)
    # charging_action_path = parse_raw_charging_action(raw_charging_action_path)
    # unique_template = make_unique_template(charging_action_path)
    # unique_policy_rule_path = create_unique_policy_rules(parsed_rulebase_path)
    #
    # # From Cisco YAML to BaseYAML
    # policy_rule_base_path = create_policy_rule_base_yaml(parsed_rulebase_path, unique_policy_rule_path)
    # create_qos_yaml(charging_action_path)
    # policy_rule_yaml = create_policy_rule_yaml(parsed_rulebase_path, charging_action_path, unique_policy_rule_path,
    #                                            unique_template)
    # filter_base_yaml = create_filterbase_yaml(ruledef_path)
    # filter_base_yaml = check_spi_filter(filter_base_yaml=filter_base_yaml,
    #                                     policy_rule_yaml=policy_rule_yaml,
    #                                     domain_name=True)
