from utils.yaml import YAML
import re


def read_yaml_file(file_input):
    ry = YAML()
    d = ry.read_yaml(file_input)
    return d


def export_yaml(data, project_name='AppFilter'):
    wy = YAML(project_name=project_name)
    path = wy.write_to_yaml({project_name: data})
    return path


def create_rule_redirect_dict(policy_rule_yaml):
    policy_rule_dict = read_yaml_file(policy_rule_yaml).get('PolicyRule')
    rule_redirect_dict = dict()
    for pr_name in policy_rule_dict:
        if policy_rule_dict.get(pr_name).get('redirect-uri'):
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
    pattern = re.compile(r'(.+)--\d+')

    http_redirect_dict = read_yaml_file(http_redirect_yaml).get('HTTP-Redirect')
    aqp_redirect_dict = dict()
    for http_redirect_name in http_redirect_dict:
        application = re.match(pattern, http_redirect_name).group(1)
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


def create_http_redirect_mop(http_redirect_yaml, aqp_http_redirect_yaml):
    pass


def main():
    create_redirect_aqp_yaml(
        create_redirect_yaml(
            create_rule_redirect_dict(r'C:\Users\ledecast\PycharmProjects\CMG_MoP_Tool\BaseYAML\PolicyRule.yaml')
        )
    )


if __name__ == "__main__":
    main()
