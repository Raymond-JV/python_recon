#!/usr/bin/env python3
import argparse
import logging
import os
import re
import sys
import time
from analyze_org import *
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from parse_scopes import parse_scope_file
from parse_scopes import Organization
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import List

class ChainContext:
    def __init__(self, chain : List[BasicCommand]):
        self.chain = chain
        self.chain_start = datetime.now()
        self.deactivate_task()
    
    def chain_duration(self):
        current_time = datetime.now()
        return f'{current_time - self.chain_start}'

    def task_duration(self):
        current_time = datetime.now()
        return f'{current_time - self.task_start}'

    def start(self):
        links = [task.cmd for task in self.chain]
        logging.debug(f'starting chain {links}')
        i = 0
        logging.debug(f'chain links: {len(links)} chain cycle {i}')
        for cmd in self.chain:
            self.set_running_task(cmd)
            try:
                cmd.process()
            except Exception as e:
                logging.debug(f"An unexpected error occurred: {e}", exc_info=True)
            i = i + 1
            logging.debug(f'chain cycle {i}')
            self.deactivate_task()

    def set_running_task(self, cmd : BasicCommand):
        self.running_task = cmd
        self.fmt_cmd = cmd.fmt_cmd
        self.display = cmd.name
        self.task_start = datetime.now()

    def deactivate_task(self):
        self.set_running_task(BasicCommand('Idle', {}, None))

def get_file_paths(dir_path):
    if not dir_path.is_dir():
        return []
    file_paths = [file for file in dir_path.rglob('*') if file.is_file()]
    return file_paths

def generate_args(org):
    args = {}
    config = Path('config')
    args['domains'] = org.domains_path
    args['subs'] = org.subs_path
    args['resolvers'] = config / Path('resolvers.txt')
    args['resolvers_csv'] = file_to_csv(args['resolvers'])
    args['amass_config'] = config / Path('amass_config.yaml')
    args['amass_scan'] = org.org_path / Path('amass_scan')
    args['subfinder_config'] = config / Path('subfinder_config.yaml') 
    args['takeovers'] = org.org_path / Path('found_sub_takeovers.txt')
    args['dns_wordlist'] = config / Path('best-dns-wordlist.txt')
    args['dns-qps'] = 1500
    return args

def create_exec_chain(org):
    args = generate_args(org)
    subs_output = args['subs']
    takeover_output = args['takeovers']
    cmds = {
            'amass-scan' : 'amass enum -brute -silent -active -df {domains} -config {amass_config} -rf {resolvers} -dns-qps {dns-qps} -nocolor -w {dns_wordlist} | tee -a {amass_scan}',
            'dnsReaper' : 'docker run -it --rm -v $(pwd):/etc/dnsreaper punksecurity/dnsreaper file --filename /etc/dnsreaper/{subs} ',
            'nuclei' : 'nuclei -l {subs}  -silent -r {resolvers} -t http/takeovers/', 
            'subfinder' : 'subfinder -all -silent -dL {domains} -rL {resolvers} -nc -config {subfinder_config}'
            }
    return [
        BasicCommand(cmds['subfinder'], args, subs_output, name='subfinder'),
        Amass(cmds['amass-scan'], args, subs_output, name='amass scan'),
        Nuclei(cmds['nuclei'], args, takeover_output, name='nuclei')
            ]
"""
        DnsReaper(cmds['dnsReaper'], args, takeover_output, timeout=1200, name='dnsReaper'),
        BasicCommand('subfinder -all -silent -dL {domains} -rL {resolvers} -nc -config {subfinder_config}', args, subs_output),
        Amass('amass enum -active -silent -df {domains} -config {amass_config} -rf {resolvers} -dns-qps {dns-qps} -nocolor', args, subs_output),
        Nuclei('nuclei -l {subs}  -silent -r {resolvers} -t http/takeovers/', args, takeover_output)
        """
def file_to_csv(file_path):
    values = []
    with open(file_path, 'r') as f:
            values = [line.strip() for line in f] 
    return ','.join(values)

def create_contexts(root, scope_paths):
    contexts = {}
    for path in scope_paths:
        org = Organization(root, path) 
        chain = create_exec_chain(org)
        contexts[org.name] = {'chain_context' : ChainContext(chain)}
        contexts[org.name]['org_context'] = org
    return contexts

@log_errors
def analyze_orgs(org_contexts, max_threads):
    max_threads == min(len(org_contexts), max_threads)
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for org_name, contexts in org_contexts.items():
            chain_context = contexts['chain_context']
            logging.debug(f'starting scan for {org_name}')
            future = executor.submit(chain_context.start)
            contexts['future'] = future
        continuous_scan(executor, org_contexts)

@log_errors
def continuous_scan(executor, org_contexts):
    display_buff = {}
    while True:
        for org_name, contexts in org_contexts.items():
            chain_context = contexts['chain_context']
            future = contexts['future']
            display_buff[org_name] = f'{org_name:15} {chain_context.display:15} {chain_context.task_duration():15}'
            if future.done():
                logging.debug(f'scan finished {org_name} {chain_context.fmt_cmd} {chain_context.task_duration()}')
                future = executor.submit(chain_context.start)
                contexts['future'] = future      
        os.system('clear')
        for buff in display_buff.values():
            print(buff)
        time.sleep(1)
"""
def split_file_into_tmp_files(file_path, n_lines):
    tmp_files = []
    curr_dir = Path().cwd()
    with open(file_path, 'r') as f:
        while True:
            lines = [f.readline() for _ in range(n_lines)]
            if not any(lines):
                break
            with NamedTemporaryFile(delete=False, dir=curr_dir, mode='w') as tmp_file:
                tmp_file.writelines(lines)
                tmp_files.append(tmp_file.name)
    return tmp_files
"""

def init_logger(logger_level):
    logging.basicConfig(
        filename='app.log',      
        filemode='a',            
        level=logger_level,     
    )

def parse_args():
    parser = argparse.ArgumentParser(description="Search for subdomains from HackerOne")
    parser.add_argument("dir", type=Path, help="The path to scope files from HackerOne")
    parser.add_argument("-t", "--max-threads", type=int, default=25, help="Max thread count")
    parser.add_argument(
    '-d', '--debug',
    help="Print lots of debugging statements",
    action="store_const", dest="loglevel", const=logging.DEBUG,
    default=logging.WARNING,
    )
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    init_logger(args.loglevel)
    root_path = Path('orgs')
    scope_paths = get_file_paths(args.dir)
    contexts = create_contexts(root_path, scope_paths)
    analyze_orgs(contexts, args.max_threads)
