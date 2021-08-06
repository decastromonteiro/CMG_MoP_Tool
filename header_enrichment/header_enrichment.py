from utils.yaml import read_yaml_file, export_yaml, YAML
from utils.utils import export_mop_file
from utils.header_fields_convertion import header_field_conversion
from parsers.tmo_cisco_parser import make_unique_template
import os
import re


def get_header_enrichment_profiles(policy_rule_yaml):
    header_enrichment_type = set()
    pr_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')

    for key in pr_dict:
        he_type = pr_dict.get(key).get('header-enrichment-type')
        he_type = he_type if ((he_type != 'null') or 'cisco' not in he_type) else None
        if he_type:
            if not he_type in header_enrichment_type:
                header_enrichment_type.add(he_type)
    return header_enrichment_type


def create_he_template_yaml(policy_rule_yaml, field_name_dict=None, he_template_dict=None):
    if not field_name_dict:
        field_name_dict = dict()
    header_enrichment_type_set = get_header_enrichment_profiles(policy_rule_yaml)
    count = 1
    header_enrichment_dict = dict()
    for he_template in header_enrichment_type_set:
        if any("cisco" in item for item in he_template):
            continue
        field_dict = dict()
        he_template_name = 'he_template_{}'.format(count)
        fields = sorted(he_template.split(','))
        he_template_fields = [header_field_conversion.get(item, item) for item in fields]
        header_enrichment_dict.update(
            {he_template_name: {'Description': he_template,
                                'Fields': field_dict}})
        for field in he_template_fields:
            field_dict.update({
                field_name_dict.get(field, field): field
            })
        count += 1

    return export_yaml(header_enrichment_dict, project_name='HETemplates')


def create_header_enrichment_yaml(policy_rule_yaml, he_templates_yaml):
    he_template_dicts = read_yaml_file(he_templates_yaml).get('HETemplates')
    pr_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    reverse_he_dict = dict()
    entry_number = 25000
    http_enrich_dict = dict()
    for he_template in he_template_dicts:
        reverse_he_dict.update({he_template_dicts.get(he_template).get('Description'): he_template})

    for key in pr_dict:
        fb = pr_dict.get(key).get('pcc-filter-base-name')
        if not fb or fb == 'null':
            application = key
        else:
            application = fb
        header_enrichment_type = pr_dict.get(key).get('header-enrichment-type')
        he_template = reverse_he_dict.get(header_enrichment_type)
        if he_template:
            if not http_enrich_dict.get(application):
                http_enrich_dict.update(
                    {application: {'he_template': he_template, 'entry': entry_number, 'application': application}}

                )
                entry_number += 10

    return export_yaml(http_enrich_dict, project_name='HTTPEnrich')


def create_header_enrichment_mop(he_template, header_enrichment_yaml, commands_template):
    he_template_dicts = read_yaml_file(he_template).get('HETemplates')
    http_enrich_dict = read_yaml_file(header_enrichment_yaml).get('HTTPEnrich')
    provision = read_yaml_file(commands_template).get('commands').get('provision')
    list_of_commands = list()
    for he_template in he_template_dicts:
        # Create Template
        list_of_commands.append(provision.get('create_template').format(he_name=he_template)
                                )
        # Add Template Description
        list_of_commands.append(provision.get('template_description').format(he_name=he_template,
                                                                             description=
                                                                             he_template_dicts.get(he_template).get(
                                                                                 'Description')))
        # Add Fields
        for field_name in he_template_dicts.get(he_template).get('Fields'):
            list_of_commands.append(
                provision.get('add_template_field').format(he_name=he_template,
                                                           field=he_template_dicts.get(he_template).get('Fields').get(
                                                               field_name),
                                                           field_name=field_name)
            )
            list_of_commands.append(
                provision.get('add_anti_spoof').format(he_name=he_template,
                                                       field=he_template_dicts.get(he_template).get('Fields').get(
                                                               field_name)

                )
            )
        list_of_commands.append(provision.get('he_template_no_shut').format(he_name=he_template))
    for pr_name in http_enrich_dict:
        list_of_commands.append(provision.get('create_aqp_entry').format(
            entry=http_enrich_dict.get(pr_name).get('entry')
        ))
        list_of_commands.append(provision.get('match_aqp_filter').format(
            entry=http_enrich_dict.get(pr_name).get('entry'),
            application=http_enrich_dict.get(pr_name).get('application')
        ))
        list_of_commands.append(provision.get('aqp_action').format(
            entry=http_enrich_dict.get(pr_name).get('entry'),
            he_name=http_enrich_dict.get(pr_name).get('he_template')
        ))
        list_of_commands.append(provision.get('aqp_no_shut').format(
            entry=http_enrich_dict.get(pr_name).get('entry')
        ))

    return export_mop_file('http_enrich_mop', list_of_commands)


# If from Cisco

def create_he_template_yaml_cisco(he_template_yaml, charging_action_yaml, unique_template_yaml):
    cisco_he_dict = read_yaml_file(he_template_yaml, 'CiscoHETemplate')
    ca_dict = read_yaml_file(charging_action_yaml, 'ChargingActionCisco')
    unique_template_dict = read_yaml_file(unique_template_yaml, 'UniqueHETemplate')
    he_template_dict = dict()
    # 'he-template'___'encryption'___'key'
    concat_pattern = re.compile(r"(\S+)___(\S+)___(\S+)")
    for concat in unique_template_dict:
        match = concat_pattern.match(concat)
        fields = cisco_he_dict.get(match.group(1)).get('fields')
        fields_dict = dict()
        for field_id in fields:
            if fields.get(field_id).get('encrypt'):
                encryption = match.group(2) if match.group(2) else None
                key = match.group(3) if match.group(3) else None
            else:
                encryption, key = None, None
            fields_dict.update(
                {field_id: {
                    'encrypt': fields.get(field_id).get('encrypt'),
                    'field': fields.get(field_id).get('field'),
                    'field_name': fields.get(field_id).get('field_name'),
                    'encryption': encryption,
                    'key': key
                }}
            )
        he_template_dict.update(
            {unique_template_dict.get(concat): {'fields': fields_dict}
             }
        )
    exp = YAML('HETemplates')
    return exp.write_to_yaml_noalias({'HETemplates': he_template_dict})


def create_he_template_mop_cisco(he_template_yaml, he_template_commands_yaml):
    he_template_dicts = read_yaml_file(he_template_yaml, 'HETemplates')
    provision = read_yaml_file(he_template_commands_yaml).get('commands').get('provision')
    list_of_commands = list()
    for he_template in he_template_dicts:
        # Create Template
        list_of_commands.append(provision.get('create_template').format(he_name=he_template)
                                )
        # Add Fields
        for field_id in he_template_dicts.get(he_template).get('fields'):
            field_parameters = he_template_dicts.get(he_template).get('fields').get(field_id)
            list_of_commands.append(
                provision.get('add_template_field').format(he_name=he_template,
                                                           field=field_parameters.get('field'),
                                                           field_name=field_parameters.get('field_name'))
            )
            if field_parameters.get('encrypt'):
                if not field_parameters.get('encryption'):
                    list_of_commands.append(
                        provision.get('cert_encode_field').format(he_name=he_template,
                                                                  field=field_parameters.get('field'),
                                                                  cert_profile='CERTIFICATE-PROFILE'

                                                                  )
                    )
                else:
                    # rc4md5-base64
                    list_of_commands.append(provision.get(
                        'key_encode_field').format(he_name=he_template, field=field_parameters.get('field'),
                                                   encode_type=field_parameters.get('encryption'),
                                                   encode_key=field_parameters.get('key')))

        list_of_commands.append(provision.get('he_template_no_shut').format(he_name=he_template))

    return export_mop_file('he_template_mop', list_of_commands)


def create_header_enrichment_yaml_cisco(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml, 'PolicyRule')
    entry_number = 25000
    http_enrich_dict = dict()

    aso_dict = dict()

    cisco_he_pattern = re.compile(r'cisco: (\S+)')

    for pr in policy_rule_dict:
        if policy_rule_dict.get(pr):
            he_template = cisco_he_pattern.match(policy_rule_dict.get(pr).get('header-enrichment-type')).group(1)
            if he_template != 'None':
                application = policy_rule_dict.get(pr).get('pcc-filter-base-name')
                if not aso_dict.get(application + he_template):
                    aso_dict.update(
                        {application + he_template: 1}
                    )
                    http_enrich_dict.update(
                        {entry_number: {'application': application, 'he_template': he_template}
                         }
                    )
                    entry_number += 10
    return export_yaml(http_enrich_dict, 'HTTPEnrich')


def create_he_aqp_mop_cisco(http_enrich_yaml, he_template_commands_yaml):
    http_enrich_dicts = read_yaml_file(http_enrich_yaml, 'HTTPEnrich')
    provision = read_yaml_file(he_template_commands_yaml).get('commands').get('provision')
    list_of_commands = list()
    for aqp_entry in http_enrich_dicts:
        # Create Template
        list_of_commands.append(provision.get('create_aqp_entry').format(entry=aqp_entry)
                                )
        application = http_enrich_dicts.get(aqp_entry).get('application')
        he_template = http_enrich_dicts.get(aqp_entry).get('he_template')
        # Match Expression
        list_of_commands.append(provision.get('match_aqp_filter').format(entry=aqp_entry,
                                                                         application=application)
                                )
        # Action Enrich
        list_of_commands.append(provision.get('aqp_action').format(entry=aqp_entry,
                                                                   he_name=he_template)
                                )

        # No shut
        list_of_commands.append(provision.get('aqp_no_shut').format(entry=aqp_entry)
                                )
    return export_mop_file('he_aqp_mop', list_of_commands)


def create_aux_list_he_template(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml, 'PolicyRule')
    d = dict()
    cisco_he_pattern = re.compile(r'cisco: (\S+)')
    for pr in policy_rule_dict:
        if policy_rule_dict.get(pr):
            he_template = cisco_he_pattern.match(policy_rule_dict.get(pr).get('header-enrichment-type')).group(1)
            if he_template != 'None':
                application = policy_rule_dict.get(pr).get('pcc-filter-base-name')
                if not d.get(application):
                    d.update({
                        application: [he_template]
                    })
                else:
                    if he_template not in d[application]:
                        d[application].append(he_template)

    return export_yaml(d, 'HETemplatesAUX')


# todo: create characteristics if there are more than one combination of application and he_template

def main():
    # # he_template_path = create_he_template_yaml(
    # #     r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml')
    # http_enrich_path = create_header_enrichment_yaml(
    #     r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml',
    #     r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\header_enrichment\HETemplates.yaml')
    # # he_template_path)
    #
    # create_header_enrichment_mop(  # he_template_path,
    #     r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\header_enrichment\HETemplates.yaml',
    #     http_enrich_path,
    #     r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\http_enrich.yaml')
    #

    # create_he_template_yaml_cisco(
    #     r"C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\parsers\CiscoHETemplate.yaml",
    #     r"C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\parsers\ChargingActionCisco.yaml",
    #     r"C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\parsers\UniqueHETemplate.yaml"
    # )

    # create_header_enrichment_yaml_cisco(
    #     r"C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml"
    # )

    create_aux_list_he_template(
        r"C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml"
    )


if __name__ == "__main__":
    main()
