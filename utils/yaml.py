import yaml
import os
from collections import OrderedDict


class YAML:

    def __init__(self, project_name=None):
        self.project_name = project_name

    def write_to_yaml(self, data):
        def setup_yaml():
            """ https://stackoverflow.com/a/8661021 """
            represent_dict_order = lambda self, data: self.represent_mapping('tag:yaml.org,2002:map', data.items())
            yaml.add_representer(OrderedDict, represent_dict_order)

        setup_yaml()
        with open('{}.yaml'.format(self.project_name), 'w') as fout:
            yaml.dump(data, fout, default_flow_style=False, allow_unicode=True)
            return os.path.abspath(self.project_name + '.yaml')

    @staticmethod
    def read_yaml(yaml_input, loader=yaml.FullLoader):
        with open(yaml_input) as fin:
            return yaml.load(fin, Loader=loader)
