import yaml
import os
from collections import OrderedDict


class YAML:

    def __init__(self, project_name=None):
        self.project_name = project_name

    def write_to_yaml(self, data, path=None):
        def setup_yaml():
            """ https://stackoverflow.com/a/8661021 """
            represent_dict_order = lambda self, data: self.represent_mapping('tag:yaml.org,2002:map', data.items())
            yaml.add_representer(OrderedDict, represent_dict_order)

        setup_yaml()
        # noalias_dumper = yaml.dumper.SafeDumper
        # noalias_dumper.ignore_aliases = lambda self, data: True

        if path:
            final_path = os.path.abspath(os.path.join(path, '{}.yaml'.format(self.project_name)))
        else:
            final_path = os.path.abspath('{}.yaml'.format(self.project_name))
        with open(final_path, 'w') as fout:
            yaml.dump(data, fout, default_flow_style=False, allow_unicode=True)
            return final_path

    @staticmethod
    def read_yaml(yaml_input, loader=yaml.FullLoader):
        with open(yaml_input) as fin:
            return yaml.load(fin, Loader=loader)

    def write_to_yaml_noalias(self, data):
        noalias_dumper = yaml.dumper.SafeDumper
        noalias_dumper.ignore_aliases = lambda self, data: True
        with open('{}.yaml'.format(self.project_name), 'w') as fout:
            yaml.dump(data, fout, default_flow_style=False, allow_unicode=True, Dumper=noalias_dumper)
            return os.path.abspath(self.project_name + '.yaml')


# todo: Make ordereddict work with noalias_dumper


def read_yaml_file(file_input, main_key=None):
    ry = YAML()
    d = ry.read_yaml(file_input)
    if main_key:
        d = ry.read_yaml(file_input).get(main_key)
        return d
    return d


def export_yaml(dictionary, project_name='Default', path=None):
    wy = YAML(project_name=project_name)

    final_path = wy.write_to_yaml({project_name: dictionary}, path=path)
    return final_path
