import os
import sys
import re
import yara
import io
import argparse

yc_config = {
    'current_file': '',
    'scanner': None,
    'rules_list_path': '',
    'scan_list_path': '',
    'results_log_path': '',
    'results_log': None,
    'os': '',
    'verbose': ''
}

def parse_commandline():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scan-list', help='Path to the scan list file')
    parser.add_argument('--rules-list', help='Path to the rules list file')
    parser.add_argument('--results-log', help='Path to the results log file')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--os', choices=['Linux', 'Windows'], help='Operating system (Linux or Windows)')
    args = parser.parse_args()
    yc_config['scan_list_path'] = args.scan_list
    yc_config['rules_list_path'] = args.rules_list
    yc_config['results_log_path'] = args.results_log
    # update with file create function to ensure file exists
    yc_config['results_log'] = open(yc_config['results_log_path'], 'w')
    yc_config['verbose'] = args.verbose
    yc_config['os'] = args.os               

def yc_verbose_log(message=''):
    if (yc_config['verbose']):
        sys.stdout.write(message + '\n')

def yc_check_scanner():
    # Check scanner initialization
    if yc_config['scanner'] == None:
        sys.stderr.write('Scanner not initialized, exiting\n')
        quit()

def yc_write_results_log(message=''):
    if yc_config['results_log'] != None:
        yc_config['results_log'].write(message + '\n')
        yc_config['results_log'].flush()

def yc_match_result(result):
    # Check if result is empty
    if (result == None):
        return
    else:
        # Print match result
        yc_verbose_log('Match found in: ' + yc_config['current_file'])
        for key, value in result.items():
            yc_write_results_log(key + ': ' + str(value))

def yc_scan_file(file_path=''):
    # Check if file path is empty
    if (file_path == ''):
        return
    else:
        # Set current file path
        yc_config['current_file'] = file_path
    yc_verbose_log('Scanning: ' + yc_config['current_file'])
    try:
        with open(yc_config['current_file'], 'rb') as yc_scan_file:
            yc_scan_file_data = bytes(yc_scan_file.read())
            results = yc_config['scanner'].match(data=yc_scan_file_data, callback=yc_match_result, which_callbacks=yara.CALLBACK_MATCHES)
            yc_match_result(result=results)
    except:
        print('Could not open: ' + file_path)

def yc_scan_file_list():
    with open(yc_config['scan_list_path'], 'r+') as yc_scanlist_handle:
        yc_scanlist_data = yc_scanlist_handle.read()
        for yc_scan_file_path in yc_scanlist_data.split('\n'):
            if (yc_scan_file_path == ''):
                # skip empty lines
                pass
            yc_scan_file(filepath=yc_scan_file_path)
        
def build_scanner_list(file_paths):
    rule_names = set()
    output_data = []
    for file_path in file_paths:
        if file_path != '':
            print('Reading: ' + file_path)
            with open(file_path, 'r+', encoding='utf-8') as file:
                try:
                    data = file.read()
                    compiled_rules = yara.compile(source=data, includes=True)
                    output_data.append(data)
                except:
                    print('could not read ' + file_path)
    try:
        data_build = '\n'.join(output_data)
        print(str(len(data_build)) + ' chars long')
        print('=======================================================')
        ## print(data_build)
        print('=======================================================')
        output_rules = yara.compile(source=data_build)
        i = 0
        for n in output_rules:
            i = i+1
            print(n)
            print(n.identifier)
        print(str(i) + ' Rules found')
        save_rules('compilated', output_rules)
        # scan_files()
    except yara.SyntaxError as e:
        print('could not compile')
        print(e)
#    with open('main.yar', 'w', encoding='utf-8') as output_file:
#        output_file.writelines(output_lines)

if __name__ == "__main__":
    args = parse_commandline()
    
    # List of YARA files to process
    with open(rules_list_path, 'r') as yara_file:
        yara_files = yara_file.read().split('\n')
        build_scanner_list(yara_files)
