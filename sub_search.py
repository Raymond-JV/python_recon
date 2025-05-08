#!/usr/bin/env python3
import argparse
import logging
import os
import re
import time
from analyze_org import *
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from parse_scopes import parse_scope_file
from parse_scopes import Organization
from pathlib import Path
from typing import List

class ChainContext:
    def __init__(self, chain : List[BasicCommand]):
        self.chain = chain
        self.chain_start = datetime.now()
        self.set_running_task(BasicCommand('', {}, None))
    
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
                print(f"An unexpected error occurred: {e}")
            i = i + 1
            logging.debug(f'chain cycle {i}')
        self.set_running_task('None') 

    def set_running_task(self, cmd : BasicCommand):
        self.running_task = cmd
        self.task_start = datetime.now()

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
    args['amass_config'] = config / Path('amass_config.yaml')
    args['subfinder_config'] = config / Path('subfinder_config.yaml') 
    args['takeovers'] = org.org_path / Path('found_sub_takeovers.txt')
    args['dns-qps'] = 1500
    return args

def create_exec_chain(org):
    args = generate_args(org)
    subs_output = args['subs']
    takeover_output = args['takeovers']
    return [
        BasicCommand('sleep 5', args, subs_output),
        BasicCommand('subfinder -all -silent -dL {domains} -rL {resolvers} -nc -config {subfinder_config}', args, subs_output),
        Amass('amass enum -active -silent -df {domains} -config {amass_config} -rf {resolvers} -dns-qps -nocolor  {dns-qps}', args, subs_output),
        Nuclei('nuclei -l {subs}  -silent -r {resolvers} -t http/takeovers/', args, takeover_output)
            ]

def create_contexts(root, scope_paths):
    contexts = {}
    for path in scope_paths:
        org = Organization(root, path) 
        chain = create_exec_chain(org)
        contexts[org.name] = {'chain_context' : ChainContext(chain)}
        contexts[org.name]['org_context'] = org
    return contexts

def analyze_orgs(org_contexts, max_threads):
    max_threads == min(len(org_contexts), max_threads)
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        for org_name, contexts in org_contexts.items():
            chain_context = contexts['chain_context']
            logging.debug(f'starting scan for {org_name}')
            future = executor.submit(chain_context.start)
            contexts['future'] = future
        continuous_scan(executor, org_contexts)

def continuous_scan(executor, org_contexts):
    while True:
        for org_name, contexts in org_contexts.items():
            future = contexts['future']
            chain_context = contexts['chain_context']
            logging.debug(f'continuous scan {org_name} {chain_context.running_task} {chain_context.task_duration()}')
            print(f'{org_name} {chain_context.running_task.fmt_cmd} {chain_context.task_duration()}')
            if future.done():
                logging.debug('task finished')
                future = executor.submit(chain_context.start)
                contexts['future'] = future      
        time.sleep(1)
        os.system('clear')

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
