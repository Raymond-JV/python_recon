#!/usr/bin/env python3

import argparse
import csv
import logging
import re
import sys
import tldextract
from pathlib import Path

class Organization:
    def __init__(self, root_path, scope_path):
        self.name = re.search(r'scopes_for_(.*)_at_\d+', scope_path.name).group(1)
        self.org_path = root_path / Path(self.name)
        self.scope_path = scope_path
        self.domains = parse_scope_file(scope_path)
        self.domains_path = self.org_path / Path(f'{self.name}_domains.txt')
        self.subs_path = self.org_path / Path(f'{self.name}_subs.txt')
        self.create_files()

    def create_files(self):
        if not self.org_path.exists():
            self.org_path.mkdir()
        with self.domains_path.open('w') as f:
            for domain in self.domains:
                logging.debug(f'writing {domain} to {self.domains_path}')
                f.write(domain + '\n')
        self.subs_path.touch(exist_ok=True)

def parse_scope_file(scope_path):
    with scope_path.open('r') as f:
        csv_reader = csv.reader(f)
        header = next(csv_reader)  
        return extract_domains(csv_reader)

def extract_domains(data): 
    domains = set() 
    valid_asset_types = ['URL','WILDCARD']

    for row in data:
        if not isinstance(row, list):
            continue

        url = row[0]
        asset_type = row[1]
        eligible_for_submission = row[4]

        if asset_type not in valid_asset_types:
            continue
        if eligible_for_submission != 'true': 
            continue

        ext = tldextract.extract(url)
        host = f"{ext.subdomain}.{ext.domain}.{ext.suffix}" 
        if host: 
            host = host.replace('www.' , '')
            parts = host.split('.')
            if '*'in parts[0]:
                host = '.'.join(parts[1:])
            host = host.replace('*.', '')
            host = host.lstrip('.')
            domains.add(host)

    return domains

def parse_args():
    parser = argparse.ArgumentParser(description="Read domains from a HackerOne CSV scope file")
    parser.add_argument('--file', '-f', type=Path, help="Scope File", required=True)
    parser.add_argument('--output', '-o', type=Path, help="Scope File")
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    domains = parse_scope_file(args.file) 
    [print(d) for d in domains]

    if args.output:
        with output.open('w') as f:
            for d in domains:
                f.write(d)
