import os

from utils.yaml import read_yaml_file, export_yaml
from utils.utils import export_mop_file
import re


def create_rule_redirect_dict(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    rule_redirect_dict = dict()
    for pr_name in policy_rule_dict:
        if policy_rule_dict.get(pr_name).get('redirect-uri') and policy_rule_dict.get(pr_name).get(
                'redirect-uri') != 'null':
            rule_redirect_dict.update(
                {
                    pr_name: policy_rule_dict.get(pr_name).get('redirect-uri')
                }
            )
    return rule_redirect_dict


def create_redirect_yaml(rule_redirect_dict, aso='REDIRECT', template=3):
    http_redirect_dict = dict()

    for rule in rule_redirect_dict:
        redirect_url = rule_redirect_dict.get(rule)
        http_redirect_dict.update(
            {
                rule: {
                    'template': template,
                    'description': None,
                    'client-reset': True,
                    'redirect-url': redirect_url,
                    'characteristics': {'name': aso, 'value': rule}
                }
            }
        )

    return export_yaml(http_redirect_dict, project_name='HTTP-Redirect')


def create_redirect_aqp_yaml(http_redirect_yaml, entry=13000, default_charging_group='default',
                             redirect_app_group='REDIRECT'):
    pattern = re.compile(r'(.+)---\d+')

    http_redirect_dict = read_yaml_file(http_redirect_yaml).get('HTTP-Redirect')
    aqp_redirect_dict = dict()
    for http_redirect_name in http_redirect_dict:
        if re.match(pattern, http_redirect_name):
            application = re.match(pattern, http_redirect_name).group(1)
        else:
            application = http_redirect_name
        aso = http_redirect_dict.get(http_redirect_name).get('characteristics').get('name')
        aso_value = http_redirect_dict.get(http_redirect_name).get('characteristics').get('value')
        aqp_redirect_dict.update({
            entry: {
                'application': application,
                'characteristics': {'name': aso, 'value': aso_value},
                'http-redirect': http_redirect_name,
                'charging-group': None,
                'app-group': None
            },
            entry + 10: {
                'application': None,
                'characteristics': {'name': aso, 'value': aso_value},
                'http-redirect': http_redirect_name,
                'charging-group': default_charging_group,
                'app-group': None
            },
            entry + 20: {
                'application': None,
                'characteristics': {'name': aso, 'value': aso_value},
                'http-redirect': http_redirect_name,
                'charging-group': None,
                'app-group': redirect_app_group
            }
        })
        entry += 30

    return export_yaml(aqp_redirect_dict, project_name='AQP-HTTP-Redirect')


def create_http_redirect_mop(http_redirect_yaml, http_redirect_template):
    http_redirect_dict = read_yaml_file(http_redirect_yaml).get('HTTP-Redirect')
    provision_commands = read_yaml_file(http_redirect_template).get('commands').get('provision')

    list_of_commands = list()
    for entry in http_redirect_dict:
        list_of_commands.extend([
            provision_commands.get('create_http_redirect').format(http_redirect_name=entry),
            provision_commands.get('template_http_redirect').format(http_redirect_name=entry,
                                                                    template_number=http_redirect_dict.get(entry).get(
                                                                        'template')),
            provision_commands.get('redirect_url').format(http_redirect_name=entry,
                                                          redirect_url=http_redirect_dict.get(entry).get(
                                                              'redirect-url'
                                                          ))

        ])
        if http_redirect_dict.get(entry).get('description'):
            list_of_commands.append(provision_commands.get('description').format(http_redirect_name=entry,
                                                                                 description=http_redirect_dict.get(
                                                                                     entry).get(
                                                                                     'description')
                                                                                 )
                                    )
        if http_redirect_dict.get(entry).get('client-reset'):
            list_of_commands.append(provision_commands.get('client_reset').format(http_redirect_name=entry)
                                    )
    return export_mop_file('aa_http_redirect', list_of_commands)


def create_aqp_http_redirect_mop(aqp_http_redirect_yaml, http_redirect_template):
    http_redirect_dict = read_yaml_file(aqp_http_redirect_yaml).get('AQP-HTTP-Redirect')
    provision_commands = read_yaml_file(http_redirect_template).get('commands').get('provision')

    list_of_commands = list()
    list_of_commands.append(
        provision_commands.get('aa_begin').format(partition='1:1')
    )
    for entry in http_redirect_dict:
        list_of_commands.extend([
            provision_commands.get('create_aso').format(partition='1:1',
                                                        characteristic=http_redirect_dict.get(entry).get(
                                                            'characteristics').get('name')
                                                        ),
            provision_commands.get('aso_value').format(partition='1:1',
                                                       characteristic=http_redirect_dict.get(entry).get(
                                                           'characteristics').get('name'),
                                                       aso_value=http_redirect_dict.get(entry).get(
                                                           'characteristics').get('value')
                                                       ),
            provision_commands.get('aso_value').format(partition='1:1',
                                                       characteristic=http_redirect_dict.get(entry).get(
                                                           'characteristics').get('name'),
                                                       aso_value='off'
                                                       ),
            provision_commands.get('aso_default_value').format(partition='1:1',
                                                               characteristic=http_redirect_dict.get(entry).get(
                                                                   'characteristics').get('name'),
                                                               aso_value='off'
                                                               ),
            provision_commands.get('create_aqp_entry').format(partition='1:1', entry=entry),

            provision_commands.get('match_aqp_aso').format(partition='1:1', entry=entry,
                                                           aso=http_redirect_dict.get(entry).get('characteristics').get(
                                                               'name'),
                                                           aso_value=http_redirect_dict.get(entry).get(
                                                               'characteristics').get('value')),
            provision_commands.get('aqp_action').format(partition='1:1', entry=entry,
                                                        http_redirect_name=http_redirect_dict.get(entry).get(
                                                            'http-redirect')),
            provision_commands.get('aqp_action_drop').format(partition='1:1', entry=entry),

            provision_commands.get('aqp_no_shut').format(partition='1:1', entry=entry)

        ])
        if http_redirect_dict.get(entry).get('app-group'):
            list_of_commands.append(
                provision_commands.get('match_aqp_filter_app_group').format(partition='1:1',
                                                                            entry=entry,
                                                                            app_group=http_redirect_dict.get(
                                                                                entry).get(
                                                                                'app-group')
                                                                            )
            )
        if http_redirect_dict.get(entry).get('charging-group'):
            list_of_commands.append(
                provision_commands.get('match_aqp_filter_charging_group').format(partition='1:1',
                                                                                 entry=entry,
                                                                                 charging_group=http_redirect_dict.get(
                                                                                     entry).get(
                                                                                     'charging-group')
                                                                                 )
            )
        if http_redirect_dict.get(entry).get('application'):
            list_of_commands.append(
                provision_commands.get('match_aqp_filter_application').format(partition='1:1',
                                                                              entry=entry,
                                                                              application=http_redirect_dict.get(
                                                                                  entry).get(
                                                                                  'application')
                                                                              )
            )
    list_of_commands.append(
        provision_commands.get('aa_commit').format(partition='1:1')
    )
    return export_mop_file('aa_aqp_http_redirect', list_of_commands)


def main():
    pass


if __name__ == "__main__":
    main()
