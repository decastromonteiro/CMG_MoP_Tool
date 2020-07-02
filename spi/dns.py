from utils.yaml import read_yaml_file, export_yaml
from utils.utils import export_mop_file


def create_dns_snoop_yaml(filter_base_yaml):
    fqdn_dict = dict()
    filter_base_dict = read_yaml_file(filter_base_yaml, 'FilterBase')
    for application in filter_base_dict:
        domain_list = list()
        if filter_base_dict.get(application).pop('SPI'):
            filters = filter_base_dict.get(application)
            for key in filters:
                domain = filters.get(key).get('domain-name')
                if domain:
                    if not domain.startswith('*'):
                        domain = '^' + domain
                    if not domain.endswith('*'):
                        domain = domain + '$'
                    domain_list.append(domain.replace('.', '\.'))

            if domain_list:
                fqdn_dict.update(
                    {
                        application: domain_list
                    }
                )

    return export_yaml(fqdn_dict, 'FQDNList')


def create_dns_snoop_mop(dns_snoop_yaml, spi_dns_commands_yaml):
    fqdn_dict = read_yaml_file(dns_snoop_yaml, 'FQDNList')
    provision_commands = read_yaml_file(spi_dns_commands_yaml).get('commands').get('provision')
    list_of_commands = list()
    for fqdn_name in fqdn_dict.keys():
        list_of_commands.extend(
            [provision_commands.get('add_domain').format(
                fqdn_list_name=fqdn_name,
                fqdn_name_id=i + 1,
                fqdn_name_string=fqdn
            ) for i, fqdn in enumerate(fqdn_dict.get(fqdn_name))]
        )

    return export_mop_file('spi_fqdn_list_mop', list_of_commands)


if __name__ == "__main__":
    create_dns_snoop_mop(
        r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\dns_ip_cache\FQDNList.yaml',
        r'C:\Users\ledecast\OneDrive - Nokia\Projetos\Python\PycharmProjects\CMG_MoP_Tool\templates\dns_sniffing_spi.yaml')
