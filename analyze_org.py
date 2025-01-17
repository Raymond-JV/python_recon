#!/usr/bin/env python3
import argparse
import logging
import functools
import json
import pty
import re
import subprocess
import tldextract
from tempfile import NamedTemporaryFile
from pathlib import Path

def log_errors(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f'Exception in {func.__name__}: {e}', exc_info=True)
            raise
    return wrapper

class BasicCommand:
    def __init__(self, cmd : str, args, output_file, timeout=None, name="Idle"):
        self.cmd = cmd
        self.args = args
        self.fmt_cmd = self.cmd.format(**args)
        self.output_file = output_file      
        self.timeout = timeout
        self.name = name
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

    @log_errors
    def process(self) -> None:
        with NamedTemporaryFile(mode='wt', prefix="tmp_", suffix=".txt") as tmp_file:
            self._execute(self.cmd, self.args, tmp_file)
            tmp_name = tmp_file.name
            logging.debug(f'Opening {tmp_name}')
            with open(tmp_name, 'rt',) as f:
                found_lines = self._read(f)
                logging.debug(f'Writing {len(found_lines)} lines to tmp_file {tmp_name}')
                self._write_unique_lines(found_lines, self.output_file)

    def _execute(self, cmd: str, args, output_file: str) -> int:
        logging.debug(f'Running CMD: {self.fmt_cmd}')
        result = subprocess.run(self.fmt_cmd ,stdout=output_file, stderr=subprocess.PIPE, timeout=self.timeout, shell=True, text=True)
        if result.stderr:
            logging.debug(f'Standard Error: {result.stderr}')
        return result
   
    def _read(self, input_file) -> None:
        lines = set([line.strip() for line in input_file])
        return lines
  
    def _write_unique_lines(self, found_lines, output_file):
        old_lines = set(self._read_unique_lines(output_file))
        unique_lines = [f'{line}\n' for line in found_lines if line not in old_lines]
        logging.debug(f'_write_unique_lines')
        with open(output_file, 'a') as f:
            f.writelines(unique_lines)  
            logging.debug(f'_write_unique_lines_open_f.writelines')

    def _find_unique_lines(self, old_lines, input_file):
        unique_lines = set([line.strip() for line in input_file if line not in old_lines])
        input_file.seek(0)
        return unique_lines

    def _read_unique_lines(self, input_file):
        if not Path(input_file).is_file():
            return []
        with open(input_file, 'r') as f:
            return [line.strip() for line in f]

class Amass(BasicCommand):
    def _read(self, input_file):
        subs = set()
        domains = self._get_domains()
        logging.debug(f'amass finding subdomains of {domains}')
        for line in input_file:
            line = line.strip().lower() 
            if 'cname' not in line.lower():
                continue
            url = line.split(' ')[0]
            logging.debug(f'amass found cname {url}')
            ext = tldextract.extract(url)
            cname_domain = f'{ext.domain}.{ext.suffix}'
            if cname_domain not in domains:
                logging.debug(f'amass {url} not in {domains}')
                continue
            logging.info(f'amass adding subdomain {url}')
            subs.add(url)
        return subs

    def _get_domains(self):
        domain_path = self.args['domains']
        domains = set()
        with open(domain_path, 'r') as f:
            for line in f:
                url = line.strip()
                ext = tldextract.extract(url)
                domains.add(f'{ext.domain}.{ext.suffix}')
        return domains

class Nuclei(BasicCommand):
    def _read(self, input_file):
        subs = set([line.split(' ')[3] for line in input_file])
        logging.debug(f'Nuclei found {len(subs)} takeovers')
        return subs

class DnsReaper(BasicCommand):
    def _read(self, input_file):
        subs = set()
        lines = set([line.strip().lower() for line in input_file])
        for line in lines:
            if 'confidence' in line:
                 matches = re.findall(r"'(.*?)'", line)
                 logging.debug(matches)
                 domain = find_domain(matches)
                 logging.debug(f'found {domain}')
                 if domain:
                     subs.add(domain)
        return subs

def find_domain(words):
    for w in words:
        ext = tldextract.extract(w)
        if ext.domain and ext.suffix:
            return w
        return None

def read_config(config_path: Path):
    if not config_path.exists():
        raise FileNotFoundError(f"Config file {config_path} not found.")

    with config_path.open('r') as file:
        config_data = json.load(file)
    return config_data

def execute_subfinder(domains : str, resolvers : str, config : Path, output : Path):
   cmd= f'subfinder -all -silent -dL {domains} -rL {resolvers} -config {config} -o {output}'
   silent_cmd(cmd)

def nuclei(subs: str, resolvers : str, output: str):
    cmd = f'nuclei -l {subs} -silent -r config/resolvers.txt -t http/takeovers/'
    silent_cmd(cmd)

def main():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    parser = argparse.ArgumentParser(description="Script to read a configuration file")
    parser.add_argument('--config', type=Path, required=True, help="Path to the configuration file")
    parser.add_argument('-rL', '--rlist', type=Path, required=True, help="Path to the file containing the list of resolvers")
    args = parser.parse_args()

if __name__ == "__main__":
    main()
