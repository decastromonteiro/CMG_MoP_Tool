import re
import os


def parse_tree(lines, indentation):
    stack = []
    for line in lines:
        if line.strip().startswith('#'):
            continue
        elif line.strip().startswith('echo'):
            continue
        elif line.strip().startswith('exit'):
            continue
        elif not line.strip():
            continue
        line = line.rstrip()
        indent = len(line) - len(line.strip())
        pattern = '^(?P<indent>(?: {%s})*)(?P<name>\S.*)' % indent
        regex = re.compile(r'{}'.format(pattern))
        match = regex.match(line)
        if not match:
            raise ValueError(
                'Indentation is not right: "{}"'.format(line)
            )

        level = len(match.group('indent')) // indentation

        if level > len(stack):
            raise ValueError('Indentation too deep: "{0}"'.format(line))
        stack[level:] = [match.group('name')]
        yield stack


def convert_to_flat(file_input, indentation=4):
    with open(file_input) as fin:
        file_name = os.path.splitext(os.path.basename(file_input))[0]
        file_output = f"{file_name}_FLAT.txt"
        with open(file_output, 'w') as fout:
            for stack in parse_tree(fin, indentation):
                fout.write(('/{}{}'.format(" ".join(stack), '\n')))
    return os.path.abspath(file_output)
