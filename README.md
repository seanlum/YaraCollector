# YaraCollector
A tool for assembling large quantities of Yara rule files into a single scanner, and scanning a list of files 

```bash

$ python3 scan-files.py --help
usage: scan-files.py [-h] [--scan-list-stdin] [--scan-list SCAN_LIST] [--scan-single-file SCAN_SINGLE_FILE]
                     [--scan-directory SCAN_DIRECTORY] [--ignore-rule-list IGNORE_RULE_LIST] [--rules-list RULES_LIST]
                     [--rules-file RULES_FILE] [--export] [--export-path EXPORT_PATH] [--results-log RESULTS_LOG]
                     [--output-log OUTPUT_LOG] [--error-log ERROR_LOG] [--verbose] [--core-count CORE_COUNT]

options:
  -h, --help            show this help message and exit
  --scan-list-stdin     will default to stdin, no recursive directory traversal
  --scan-list SCAN_LIST
                        Scan list of paths to files, no recursive directory traversal
  --scan-single-file SCAN_SINGLE_FILE
                        Path to the single file to scan
  --scan-directory SCAN_DIRECTORY
                        Path of directory to scan
  --ignore-rule-list IGNORE_RULE_LIST
                        Ignore file for rule list file, optional, paths of rules
  --rules-list RULES_LIST
                        Rules list file, required
  --rules-file RULES_FILE
                        Multiple can be supplied, for loading
  --export              Export compiled rules to a file
  --export-path EXPORT_PATH
                        Will default to compiled-export.yara Plaintext will not be assembled in a file.
  --results-log RESULTS_LOG
                        will default to stdout, if not supplied
  --output-log OUTPUT_LOG
                        will default to stdout, if not supplied
  --error-log ERROR_LOG
                        will default to stderr, if not supplied
  --verbose             Verbose output
  --core-count CORE_COUNT
                        Number of cores to use

```

## Issues
You can report an issue if you find one. I was also thinking about adding a rule repair tool that someone else wrote to make the program more dependable. However I have yet to do so because I need to find out how the matching meta changes after a rule repair. For now I've been doing this by myself. But it would be nice to have help and refactor this to include people ☺

## Notes
- This program has not implemented the following features yet. If you would like to contribute, open a pull request.
  - Multi-threaded / Multi-core programming. Was thinking of using `concurrent.futures`
  - Implement using a single rule file switch. Should allow multiple switches of the same name to submit multiple single files.
  - De-duping scanned files. For now all paths are converted to absolute paths and filtered. However, it is still possible to scan the same file twice.
  - Test output files and validate data joining with the `tail` command to read all file outputs to one file and compare with stdout as default.
- Need to test on the following platforms
  - Windows Python3
  - WSL 1 Python3, WSL2 has been tested
  - Linux Virtual Machine
  - MacOS
  - Android, if possible
  - iOS, if possible
  
