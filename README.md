# InfoDomain Seeker

## Description

`InfoDomain Seeker` is a tool designed to gather information about domains. It fetches WHOIS data, DNS records, SSL/TLS configurations, and checks open ports for specified domains. This information can be saved to a JSON file or exported as a PDF report.

## Features

- Gather WHOIS information for domains.
- Fetch various DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA).
- Retrieve SSL/TLS configurations.
- Check open ports for domains.
- Save results in JSON format.
- Export results as a PDF report.

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/yourusername/InfoDomainSeeker.git
    cd InfoDomainSeeker
    ```

## Usage

### Command Line Arguments

- `-d`, `--domain`: Specify a single domain.
- `-dfp`, `--domains_file_path`: Path to a file containing a list of domains.
- `-dr`, `--dns_resolver`: Specify a DNS resolver.
- `-drfp`, `--dns_resolvers_file_path`: Path to a file containing a list of DNS resolvers.
- `-rt`, `--record_type`: Specify DNS record types (default: A, AAAA, MX, NS, TXT, CNAME, SOA).
- `-t`, `--threads`: Number of threads to use (default: 1).
- `-q`, `--quiet`: Suppress output to the console.
- `-p`, `--ports`: Specify ports to check (default: 22, 80, 443).
- `-o`, `--output`: Path to save the JSON output (default: `output.json).
- `--pdf`: Path to save the PDF report.

### Example Usage

Fetch information for a single domain:
```sh
python info_domain_seeker.py -d example.com
```

Fetch information for domains listed in a file:
```sh
python info_domain_seeker.py -dfp domains.txt
```

Fetch information using a specific DNS resolver:
```sh
python info_domain_seeker.py -d example.com -dr 8.8.8.8
```

Fetch information and save output to a specific file:
```sh
python info_domain_seeker.py -d example.com -o results.json
```

Fetch information and generate a PDF report:
```sh
python info_domain_seeker.py -d example.com --pdf report.pdf
```

## Requirements

- Python 3.6 or higher
- `rich`
- `argparse`
- `whois`
- `ipaddress`
- `dns.resolver`
- `json`
- `ssl`
- `cryptography`
- `concurrent.futures`
- `threading`
- `socket`
- `datetime`
- `reportlab`

## Acknowledgements

Coded by Mohamed Ahmed (ma4747gh).
