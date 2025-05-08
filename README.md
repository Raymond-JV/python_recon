# python_recon
This is a personal program that I wrote to automate continuous recon for bug bounty. It cycles through subfinder, amass and nuclei to find subdomains and takeovers.

![search2](resources/search2.png)

## Usage
```nroff
positional arguments:
  dir                   The path to scope files from HackerOne

options:
  -h, --help            show this help message and exit
  -t, --max-threads MAX_THREADS
                        Max thread count
  -d, --debug
```
The ```max-threads``` flag determines how many targets to scan at once. For example, setting ```-t 2``` will loop through all of the targets indefinitely two at a time.

## Setup

Add the CSV scope files of programs from HackerOne to the scopes dir.

![scopes](resources/scopes.png)

Add config files to the config dir.

![config](/resources/config.png)

Good luck :)

```
./sub_search.py scopes -t 5 -d
```
![search1](resources/search1.png)

## Results
An orgs dir is created for saving results.

![ls_cmd](resources/orgs.png)

![found_subs](resources/newegg_subs.png)

## TODO
* Implement a cleaner solution for reading config files.
* Utilize Luigi to create a Pipeline so failures are handled more reliably.
* Cleanup the BasicCommand class and include more tools.
* Add SMS Notifications.
* Use a package manager.
