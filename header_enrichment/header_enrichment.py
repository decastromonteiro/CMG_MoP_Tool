from utils.yaml import YAML
import os


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def export_yaml(data_input, project_name='HeaderEnrichment'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({project_name: data_input})
    return path


def get_header_enrichment_profiles(policy_rule_yaml):
    header_enrichment_type = set()
    pr_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')

    for key in pr_dict:
        he_type = pr_dict.get(key).get('header-enrichment-type')
        he_type = he_type if he_type != 'null' else None
        if he_type:
            if not he_type in header_enrichment_type:
                header_enrichment_type.add(he_type)
    return header_enrichment_type


def create_he_template_yaml(policy_rule_yaml):
    header_enrichment_type_set = get_header_enrichment_profiles(policy_rule_yaml)
    count = 1
    header_enrichment_dict = dict()
    for he_template in header_enrichment_type_set:
        he_template_name = 'he_template_{}'.format(count)
        he_template_fields = he_template.split(',')
        header_enrichment_dict.update(
            {he_template_name: {'Description': he_template, 'Fields': he_template_fields}}
        )
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

    return export_yaml(http_enrich_dict, project_name='HeaderEnrichment')


def create_header_enrichment_mop(he_template, header_enrichment_yaml, commands_template):
    he_template_dicts = read_yaml_file(he_template).get('HETemplates')
    http_enrich_dict = read_yaml_file(header_enrichment_yaml).get('HeaderEnrichment')
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
        for field in he_template_dicts.get(he_template).get('Fields'):
            list_of_commands.append(
                provision.get('add_template_field').format(he_name=he_template,
                                                           field=field,
                                                           field_name=field.upper())
            )
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

    with open('http_enrich_mop.txt', 'w') as fout:
        for command in list_of_commands:
            fout.write(command + '\n')

    return os.path.abspath('http_enrich_mop.txt')


def main():
    he_template_path = create_he_template_yaml(
        r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml')
    http_enrich_path = create_header_enrichment_yaml(
        r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\parsers\PolicyRule.yaml',
        he_template_path)

    create_header_enrichment_mop(he_template_path,
                                 http_enrich_path,
                                 r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\templates\http_enrich.yaml')


if __name__ == "__main__":
    main()
