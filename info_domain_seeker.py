from rich.console import Console
import argparse
from whois import whois
from ipaddress import IPv4Address, AddressValueError
import dns.resolver
import json
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import socket
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


class InfoDomainSeeker:
    def __init__(self):
        self.console = Console()
        self.args = self.initialize_argparse()
        self.print_banner()

        self.domains_file_path = self.args.domains_file_path
        self.domains = [self.args.domain] if self.args.domain else []

        self.dns_resolvers_file_path = self.args.dns_resolvers_file_path
        self.dns_resolvers = ['8.8.8.8'] if not self.args.dns_resolver and not self.dns_resolvers_file_path else [self.args.dns_resolver] if self.args.dns_resolver else []

        self.record_type = self.args.record_type if self.args.record_type else ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

        self.threads = self.args.threads
        self.lock = Lock()

        self.quiet = self.args.quiet

        self.ports = self.args.ports if self.args.ports else [22, 80, 443]

        self.output_file_path = self.args.output

        self.styles = getSampleStyleSheet()

        self.pdf_file_path = self.args.pdf

    def cprint(self, string, state):
        if state == 'success':
            self.console.print('\n', end='')
            self.console.print('[bold green][+] {}[/bold green]'.format(string))
        elif state == 'failure':
            self.console.print('\n', end='')
            self.console.print('[bold red][-] {}[/bold red]'.format(string))
        elif state == 'info':
            self.console.print('\n', end='')
            self.console.print('[bold blue][*] {}[/bold blue]'.format(string))
        elif state == 'ack':
            self.console.print('\n', end='')
            self.console.print('[bold yellow][*] {}[/bold yellow]'.format(string))
        else:
            self.console.print('\n', end='')
            self.console.print('[bold {}][*] {}[/bold {}]'.format(state, string, state))

    def highlight_json(self, data):
        if isinstance(data, dict):
            return {k: self.highlight_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self.highlight_json(v) for v in data]
        else:
            return '[#FFF5E1 on #C80036]{}[/#FFF5E1 on #C80036]'.format(data)

    def cprint_json(self, data):
        highlighted_data = self.highlight_json(data)
        json_str = json.dumps(highlighted_data, indent=4)
        self.console.print('\n', end='')
        self.console.print(json_str)

    def initialize_argparse(self):
        parser = argparse.ArgumentParser(
            description='InfoDomain Seeker: A tool for gathering information about domains.',
            epilog='Coded by Mohamed Ahmed (ma4747gh).')

        parser.add_argument('-d', '--domain',
                            help='Single domain name to gather information about.',
                            default=None)

        parser.add_argument('-dfp', '--domains_file_path',
                            help='Path to a file containing multiple domain names, each on a new line.',
                            default=None)

        parser.add_argument('-dr', '--dns_resolver',
                            help='IP address of a DNS resolver to use for DNS queries.',
                            default=None)

        parser.add_argument('-drfp', '--dns_resolvers_file_path',
                            help='Path to a file containing multiple DNS resolver IP addresses, each on a new line.',
                            default=None)

        parser.add_argument('-rt', '--record_type',
                            help='Types of DNS records to query (e.g., A, AAAA, MX, NS).',
                            nargs='*', default=None)

        parser.add_argument('-t', '--threads',
                            help='Number of threads to use for concurrent processing.',
                            type=int, default=1)

        parser.add_argument('-q', '--quiet',
                            help='Suppress non-error messages during execution.',
                            action='store_true', default=False)

        parser.add_argument('-p', '--ports',
                            help='Ports to check for open status (e.g., 22, 80, 443).',
                            nargs='*', default=None)

        parser.add_argument('-o', '--output',
                            help='Path to save the output JSON file.',
                            default='output.json')

        parser.add_argument('--pdf',
                            help='Path to save the PDF report file.',
                            default=None)

        args = parser.parse_args()

        if not args.domain and not args.domains_file_path:
            self.cprint('You have at least to use --domain or --domains_file_path.', 'failure')
            exit()

        if args.domain and args.domains_file_path:
            self.cprint('You can not use both --domain and --domains_file_path together.', 'failure')
            exit()

        if args.dns_resolver and args.dns_resolvers_file_path:
            self.cprint('You can not use both --dns_resolver and --dns_resolvers_file_path together.', 'failure')
            exit()

        return args

    def print_banner(self):
        self.console.print('''[bold #604CC3]
 ___        __       ____                        _         ____            _             
|_ _|_ __  / _| ___ |  _ \  ___  _ __ ___   __ _(_)_ __   / ___|  ___  ___| | _____ _ __ 
 | || '_ \| |_ / _ \| | | |/ _ \| '_ ` _ \ / _` | | '_ \  \___ \ / _ \/ _ \ |/ / _ \ '__|
 | || | | |  _| (_) | |_| | (_) | | | | | | (_| | | | | |  ___) |  __/  __/   <  __/ |   
|___|_| |_|_|  \___/|____/ \___/|_| |_| |_|\__,_|_|_| |_| |____/ \___|\___|_|\_\___|_|[/bold #604CC3]''', )

    def read_domains_file_path(self):
        with open(self.domains_file_path) as file:
            for line in file.readlines():
                self.domains.append(line.strip())

    def read_dns_resolvers_file(self):
        with open(self.dns_resolvers_file_path) as file:
            for line in file.readlines():
                if self.is_valid_ipv4(line.strip()):
                    self.dns_resolvers.append(line.strip())

    @staticmethod
    def fetch_whois_info(domain):
        try:
            whois_info = whois(domain)
            return whois_info
        except Exception:
            return 'Exception'

    def get_whois_info(self):
        get_whois_info_result = {}
        self.cprint('Start gathering WHOIS info.', 'ack')

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.fetch_whois_info, domain): domain for domain in self.domains}
            for future in as_completed(futures):
                domain = futures[future]
                whois_info = future.result()
                if whois_info == 'Exception':
                    self.cprint('Failed to retrieve WHOIS information for \'{}\'.'.format(domain), 'failure')
                else:
                    get_whois_info_result[domain] = whois_info

        if not self.quiet:
            self.cprint_json(get_whois_info_result)

        return get_whois_info_result

    @staticmethod
    def is_valid_ipv4(ip):
        try:
            IPv4Address(ip)
            return True
        except AddressValueError:
            return False

    @staticmethod
    def resolve_domain(domain, dns_servers, record_type):

        resolver = dns.resolver.Resolver(configure=False)

        resolver.nameservers = dns_servers

        try:
            answer = resolver.resolve(domain, record_type)
            return answer
        except dns.resolver.NoAnswer:
            return 'NoAnswer'
        except dns.resolver.NXDOMAIN:
            return 'NXDOMAIN'
        except dns.resolver.Timeout:
            return 'Timeout'
        except Exception:
            return 'Exception'

    def get_dns_record_info(self, domain):
        dns_resolvers_data = {}
        for dns_resolver in self.dns_resolvers:
            dns_resolvers_data[dns_resolver] = {}
            for record in self.record_type:
                answer = self.resolve_domain(domain, [dns_resolver], record)
                if answer == 'NoAnswer' or answer == 'NXDOMAIN' or answer == 'Timeout' or answer == 'Exception':
                    self.lock.acquire()
                    self.cprint('\'{}\' raised \'{}\' for the domain \'{}\' and the record type \'{}\'.'.format(dns_resolver, answer, domain, record), 'failure')
                    self.lock.release()
                else:
                    for entry in answer:
                        if not self.quiet:
                            self.lock.acquire()
                            self.cprint('\'{}\' --> \'{}\' --> \'{}\' --> {}'.format(domain, dns_resolver, record, str(entry)), 'success')
                            self.lock.release()
                        dns_resolvers_data[dns_resolver][record] = str(entry)
        return dns_resolvers_data

    def get_dns_records_info(self):
        records = {}
        self.cprint('Start gathering DNS records from \'{}\'.'.format(', '.join(self.dns_resolvers)), 'ack')

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.get_dns_record_info, domain): domain for domain in self.domains}
            for future in as_completed(futures):
                domain = futures[future]
                dns_resolvers_data = future.result()
                records[domain] = dns_resolvers_data

        if not self.quiet:
            self.cprint_json(records)

        return records

    @staticmethod
    def fetch_ssl_tls_configuration(domain):
        domain_data = {}

        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        conn.connect((domain, 443))

        cipher = conn.cipher()
        cipher_suite, ssl_tls_version, key_size = cipher
        domain_data['cipher'] = {
            'cipher_suite': cipher_suite,
            'ssl_tls_version': ssl_tls_version,
            'key_size': key_size
        }

        domain_data['certificates'] = []
        pem_cert_chain = ssl.DER_cert_to_PEM_cert(conn.getpeercert(binary_form=True))
        certificates = pem_cert_chain.split('\n-----END CERTIFICATE-----\n')[:-1]
        for certificate in certificates:
            certificate += '\n-----END CERTIFICATE-----\n'
            cert = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
            cert_data = {
                'subject': cert.subject,
                'issuer': cert.issuer,
                'valid_from': cert.not_valid_before_utc,
                'valid_until': cert.not_valid_after_utc
            }
            domain_data['certificates'].append(cert_data)

        conn.close()

        return domain_data

    def get_ssl_tls_configuration(self):
        get_ssl_tls_configuration_result = {}
        self.cprint('Start gathering SSL/TLS info.', 'ack')

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.fetch_ssl_tls_configuration, domain): domain for domain in self.domains}
            for future in as_completed(futures):
                domain = futures[future]
                domain_data = future.result()
                get_ssl_tls_configuration_result[domain] = domain_data

        if not self.quiet:
            self.cprint_json(get_ssl_tls_configuration_result)

        return get_ssl_tls_configuration_result

    @staticmethod
    def check_if_port_is_open(domain, ports):
        open_ports = []
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((domain, int(port)))
                if result == 0:
                    open_ports.append(port)
        return open_ports

    def get_open_ports(self):
        domains_open_ports = {}
        self.cprint('Start gathering open ports.', 'ack')

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_if_port_is_open, domain, self.ports): domain for domain in self.domains}
            for future in as_completed(futures):
                domain = futures[future]
                open_ports = future.result()
                domains_open_ports[domain] = open_ports

        if not self.quiet:
            self.cprint_json(domains_open_ports)

        return domains_open_ports

    def output_json(self, aggregator):
        self.cprint('Saving results to \'{}\'.'.format(self.output_file_path), 'ack')
        final_data = {}
        for domain in self.domains:
            final_data[domain] = {}
            for key, value in aggregator.items():
                final_data[domain][key] = value[domain]

        def convert_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
        with open(self.output_file_path, 'w') as file:
            file.write(json.dumps(final_data, default=convert_datetime, indent=4))

        return final_data

    def format_value(self, key, value):
        if isinstance(value, list) and len(value) > 1:
            items = [Paragraph(f'<font color="blue">- {item}</font>', self.styles['Normal']) for item in value]
            return [Paragraph(f'{key}:', self.styles['Normal'])] + items
        return [Paragraph(f'{key}: <font color="blue">{value}</font>', self.styles['Normal'])]

    def create_pdf(self, data, filename):
        self.cprint('Saving PDF copy at \'{}\'.'.format(self.pdf_file_path), 'ack')
        doc = SimpleDocTemplate(filename, pagesize=letter)
        flowables = []

        for domain, domain_data in data.items():
            flowables.append(Paragraph(f'Domain: {domain}', self.styles['Title']))

            whois_info = domain_data.get('whois_info', {})
            dns_records_info = domain_data.get('dns_records_info', {})
            ssl_tls_configuration = domain_data.get('ssl_tls_configuration', {})
            open_ports = domain_data.get('open_ports', [])

            flowables.append(Paragraph('WHOIS Info', self.styles['Heading2']))
            for key, value in whois_info.items():
                formatted_values = self.format_value(key, value)
                flowables.extend(formatted_values)
            flowables.append(Spacer(1, 12))

            flowables.append(Paragraph('DNS Records Info', self.styles['Heading2']))
            for server, records in dns_records_info.items():
                flowables.append(Paragraph(f'Server: {server}', self.styles['Heading3']))
                for record_type, record_value in records.items():
                    formatted_values = self.format_value(record_type, record_value)
                    flowables.extend(formatted_values)
            flowables.append(Spacer(1, 12))

            flowables.append(Paragraph('SSL/TLS Configuration', self.styles['Heading2']))
            cipher = ssl_tls_configuration.get('cipher', {})
            for key, value in cipher.items():
                formatted_values = self.format_value(key, value)
                flowables.extend(formatted_values)

            certificates = ssl_tls_configuration.get('certificates', [])
            for cert in certificates:
                flowables.append(Paragraph('Certificate:', self.styles['Heading3']))
                for key, value in cert.items():
                    formatted_values = self.format_value(key, str(value).strip('<').strip('>'))
                    flowables.extend(formatted_values)
            flowables.append(Spacer(1, 12))

            flowables.append(Paragraph('Open Ports', self.styles['Heading2']))
            if open_ports:
                formatted_ports = self.format_value('Ports', open_ports)
                flowables.extend(formatted_ports)
            flowables.append(Spacer(1, 12))

        doc.build(flowables)

    def start(self):
        if self.args.domains_file_path:
            self.read_domains_file_path()

        if self.args.dns_resolvers_file_path:
            self.read_dns_resolvers_file()

        dict_1 = self.get_whois_info()
        dict_2 = self.get_dns_records_info()
        dict_3 = self.get_ssl_tls_configuration()
        dict_4 = self.get_open_ports()

        aggregator = {
            'whois_info': dict_1,
            'dns_records_info': dict_2,
            'ssl_tls_configuration': dict_3,
            'open_ports': dict_4
        }

        final_data = self.output_json(aggregator)
        if self.pdf_file_path:
            self.create_pdf(final_data, self.pdf_file_path)


info_domain_seeker = InfoDomainSeeker()
info_domain_seeker.start()
