import os
import sys
import io
import yara
import re
import magic
import argparse
import concurrent.futures

yc_file_handles = {
    'rules_list': None,
    'scan_list': None,
    'results_log': None,
    'output_log': None,
    'error_log': None,
    'export': None,
    'current_file': None,
    'ignore_rule_list': None
}

yc_scanner_data = {
    'directories': [],
    'files': [],
    'paths_to_scan': [],
    'scanner' : None,
    'output_rules' : [],
    'scanned_rules' : {},
    'compiled_rules': [],
    'export_flag': False,
}

yc_config = {
    'core_count': 1,
    'current_file': '',
    'rules_list_path': '',
    'scan_list_path': '',
    'results_log_path': '',
    'output_log_path': '',
    'error_log_path': '',
    'export_path': '',
    'ignore_rule_list_path': '',
    'os': '',
    'verbose': ''
}

def yc_is_octet_stream(file_path=''):
    ms = magic.Magic(mime=True)
    file_type = ms.from_file(file_path)
    if file_type == 'application/octet-stream':
        return True
    else:
        return False

def yc_is_txt_file(file_path=''):
    ms = magic.Magic(mime=True)
    file_type = ms.from_file(file_path)
    if file_type == 'text/plain':
        return True
    else:
        return False

def yc_process_executor(task, *arguments):
    with concurrent.futures.ProcessPoolExecutor(max_workers=yc_config['core_count']) as executor:
         executor.map(task, arguments)

def yc_log_verbose(message=''):
    if (yc_config['verbose']):
        if yc_file_handles['output_log'] == None:
            yc_file_handles['output_log'].write(message + '\n')
        else:
            sys.stdout.write(message)

def yc_log_error(message=''):
    if yc_file_handles['output_log'] == None:
        yc_file_handles['output_log'].write(message + '\n')
    else:
        sys.stderr.write(message)

def yc_file_handle_close_all():
    for value in yc_file_handles.values():
        if (value != None):
            value.close()

def yc_file_handle_close(file_handle_key=''):
    if (file_handle_key not in yc_file_handles):
        sys.stderr.write('Invalid file handle key\n')
        quit()
    if (yc_file_handles[file_handle_key] != None):
        yc_file_handles[file_handle_key].close()
        yc_file_handles[file_handle_key] = None

def yc_file_handle_open(file_path='', mode=''):
    if file_path == '':
        sys.stderr.write('File path not provided\n')
        return None
    file_path = os.path.normpath(file_path)
    if os.path.exists(file_path) != True:
        sys.stderr.write('File not found: ' + file_path + '\n')
        return None
    if mode == '':
        sys.stderr.write('Mode not provided\n')
        quit()
    if mode not in ['r', 'rb', 'w', 'a']:
        sys.stderr.write('Invalid mode: ' + mode + '\n')
        quit()
    try:
        if mode == 'rb':
            yc_log_verbose('Opening: ' + file_path + ' in binary mode')
            yc_open_file_handle = open(file_path, mode)
        else:
            yc_log_verbose('Opening: ' + file_path + ' in text mode')
            yc_open_file_handle = open(file_path, mode, encoding='utf-8')
        return yc_open_file_handle
    except PermissionError as e:
        #sys.stderr.write('(PermissionError) Access was denied: ' + file_path + '\n')
        #sys.stderr.write(str(e) + '\n')
        yc_open_file_handle = None
    except IsADirectoryError as e:
        sys.stderr.write('(IsADirectoryError) Is a directory: ' + file_path + '\n')
        sys.stderr.write(str(e) + '\n')
        yc_open_file_handle = None
    except FileNotFoundError as e:
        sys.stderr.write('(FileNotFoundError) File not found: ' + file_path + '\n')
        sys.stderr.write(str(e) + '\n')
        yc_open_file_handle = None
    except OSError as e:
        sys.stderr.write('(OSError) Could not open file: ' + file_path + '\n')
        sys.stderr.write(str(e) + '\n')
        yc_open_file_handle = None
    except Exception as e:
        sys.stderr.write('Could not open file: ' + file_path + '\n')
        sys.stderr.write(str(e) + '\n')
        yc_open_file_handle = None
    return yc_open_file_handle

def yc_file_handle_init(method=None,  file_path='', file_mode='', file_handle_key=''):
    if (file_handle_key not in yc_file_handles):
        sys.stderr.write('Invalid file handle key\n')
        quit()
    if (yc_file_handles[file_handle_key] != None):
        sys.stderr.write('File handle already initialized\n')
        quit()
    if method == 'file':
        if file_mode in ['r', 'rb', 'w', 'a']:
            yc_file_handles[file_handle_key] = yc_file_handle_open(file_path=file_path, mode=file_mode)
        else:
            sys.stderr.write('Invalid file mode\n')
            quit()
    elif method == 'stdout':
        yc_file_handles[file_handle_key] = sys.stdout
    elif method == 'stderr':
        yc_file_handles[file_handle_key] = sys.stderr
    elif method == 'stdin':
        yc_file_handles[file_handle_key] = sys.stdin
    else:
        sys.stderr.write('Invalid log method\n')
        quit()

def yc_enumerate_file_entry(file_entry=''):
    file_entry = file_entry.strip()
    if file_entry == '':
        return
    if os.path.isfile(file_entry):
        if file_entry not in yc_scanner_data['files']:
            yc_scanner_data['files'].append(file_entry)
    elif os.path.isdir(file_entry):
        if file_entry not in yc_scanner_data['directories']:
            yc_scanner_data['directories'].append(file_entry)
    else:
        sys.stderr.write('Invalid path: ' + line + '\n')
# Scan stdin or the list file for files to scan
#   then go through entries in in files and directories
#   and add all found paths to paths_to_scan
def yc_enumerate_files():
    # Check if scan list is stdin
    if yc_file_handles['scan_list'] == sys.stdin:
        for line in sys.stdin:
            sys.stdout.write('Enumerating: ' + line)
            yc_enumerate_file_entry(file_entry=line)
    elif yc_file_handles['scan_list'] != None:
        temp_data = yc_file_handles['scan_list'].read()
        for line in temp_data.split('\n'):
            yc_enumerate_file_entry(file_entry=line)
    files_found_in_directories = 0
    for directory in yc_scanner_data['directories']:
        for dir_entry_name in os.listdir(directory):
            temp_path = os.path.join(directory, dir_entry_name).strip()
            if os.path.isfile(temp_path):
                if temp_path not in yc_scanner_data['files']:
                    files_found_in_directories += 1
                    yc_scanner_data['files'].append(temp_path)
    for file in yc_scanner_data['files']:
        file = os.path.abspath(file)
        yc_scanner_data['paths_to_scan'].append(file)
    if len(yc_scanner_data['paths_to_scan']) > 1:
        yc_scanner_data['paths_to_scan'] = list(yc_scanner_data['paths_to_scan'])
        yc_scanner_data['paths_to_scan'] = set(yc_scanner_data['paths_to_scan'])
        yc_scanner_data['paths_to_scan'] = list(yc_scanner_data['paths_to_scan'])
    print(str(len(yc_scanner_data['paths_to_scan'])) + ' files to scan')
    print(str(files_found_in_directories) + ' new files found in directories')

def yc_scanner_open_rule_list():
    with yc_file_handle_open(file_path=yc_config['rules_list_path'], mode='r') as yara_sig_file_db:
        sig_file_db_data = None
        try:
            sig_file_db_data = yara_sig_file_db.read()
            sig_file_db_out_data = []
            for line in sig_file_db_data.split('\n'):
                line.strip()
                if line == '':
                    continue
                if os.path.isfile(line):
                    sig_file_db_out_data.append(line)
            return sig_file_db_out_data
        except UnicodeDecodeError:
            yc_log_error(f"Error: Could not decode the contents of '{yc_config['rules_list_path']}'.")
            return None
        except OSError as e:
            yc_log_error(f"Error: An OS error occurred while reading the file: {e}")
            quit()
def yc_scanner_open_ignore_rule_list():
    if yc_file_handles['ignore_rule_list'] == None:
        return []
    else:
        ignore_rule_list = []
        ignore_paths = yc_file_handles['ignore_rule_list'].read().split('\n')
        for line in ignore_paths:
            line.strip()
            if line == '':
                continue
            if os.path.isfile(line):
                ignore_rule_list.append(line)
        return ignore_rule_list


def yc_scanner_open_signatures(file_path=''):
    output_rules = None
    if yc_is_octet_stream(file_path=file_path):
        try:
            sys.stdout.write('Reading: (compiled) ' + file_path + '\n')
            output_rules = yara.load(filepath=file_path)
            yc_scanner_data['compiled_rules'].append(output_rules)
            return None
        except:
            print('could not load ' + file_path)
    elif yc_is_txt_file(file_path=file_path):
        try:
            sys.stdout.write('Reading: (raw) ' + file_path + '\n')

            temp_handle = yc_file_handle_open(file_path=file_path, mode='r')
            temp_data = temp_handle.read()
            output_rules = yara.compile(source=temp_data, includes=True)
            for rule in output_rules:
                print('Rule: ' + rule.identifier)
                if rule.identifier is None:
                    print('Rule identifier is None, ignoring...')
                    return None
                if rule.identifier == '':
                    print('Rule identifier is empty, ignoring...')
                    return None
                if rule.identifier in yc_scanner_data['scanned_rules'].keys():
                    print('Duplicate rule found: ' + rule.identifier + ' ignoring...')
                    return None
                else:
                    yc_scanner_data['scanned_rules'][rule.identifier] = rule
            temp_handle.close()
            return temp_data
        except:
            print('could not compile ' + file_path)
    else:
        print('could not determine file type of ' + file_path)
        return None

def yc_scanner_build_list():
    yc_scanner_rules_file_list = yc_scanner_open_rule_list()
    yc_scanner_ignore_file_list = yc_scanner_open_ignore_rule_list()
    for file_path in yc_scanner_rules_file_list:
        if file_path in yc_scanner_ignore_file_list:
            print('Ignoring: ' + file_path)
        else:
            rule = yc_scanner_open_signatures(file_path=file_path)
            if rule != None and rule != '':
                yc_scanner_data['output_rules'].append(rule)
            else:
                pass
    print('Total raw rules: ' + str(len(yc_scanner_data['output_rules'])) + '\n')
    export_text = '\n'.join(yc_scanner_data['output_rules'])
    export_rules = None

    export_rules = yara.compile(source=export_text, includes=True)

    total_text_rules = 0
    for export_rule in export_rules:
        # sys.stdout.write('Rule: ' + export_rule.identifier)
        total_text_rules += 1
    yc_scanner_data['compiled_rules'].append(export_rules)
    if yc_scanner_data['export_flag'] == True:
        sys.stdout.write('Writing ' + str(int(total_text_rules)) + ' rules compiled from text to: ' + yc_config['export_path'] + '\n')
        export_rules.save(yc_config['export_path'])
    total_compiled_rules = 0
    total_compiled_scanners = 0
    for compiled_rule in yc_scanner_data['compiled_rules']:
        total_compiled_scanners += 1
        for sub_rule in compiled_rule:
            total_compiled_rules += 1
    sys.stdout.write('Total compiled rules: ' + str(int(total_compiled_rules)) + '\n')
    sys.stdout.write('Total compiled scanners: ' + str(int(total_compiled_scanners)) + '\n')

# remove???
def yc_check_scanner():
    # Check scanner initialization
    if yc_scanner_data['scanner'] == None:
        sys.stderr.write('Scanner not initialized, exiting\n')
        quit()

def yc_write_results_log(message=''):
    if yc_file_handles['results_log'] != None:
        yc_file_handles['results_log'].write(message + '\n')
        yc_file_handles['results_log'].flush()

def yc_match_result(result):
    # Check if result is empty
    if (result == None):
        return
    else:
        # Print match result
        sys.stdout.write('Match found in: ' + yc_config['current_file'] + '\n')
        for key, value in result.items():
            yc_write_results_log(key + ': ' + str(value))


def yc_enumerate_scan_files():
    for file_path in yc_scanner_data['paths_to_scan']:
        # Check if file path is empty
        if (file_path == ''):
            pass
        # Set current file path
        yc_config['current_file'] = file_path
        yc_scan_file = yc_file_handle_open(file_path=yc_config['current_file'], mode='rb')
        if yc_scan_file != None:
            print('=' * 96)
            sys.stdout.write('Scanning: ' + yc_config['current_file'] + '\n')
            print('=' * 96)
            try:
                yc_scan_file_data = bytes(yc_scan_file.read())
            except:
                print('Could not read: ' + file_path)
                quit()
            sys.stdout.write('Scanning: ' + file_path + '\n')
            for scanner in yc_scanner_data['compiled_rules']:
                results = scanner.match(data=yc_scan_file_data, callback=yc_match_result, which_callbacks=yara.CALLBACK_MATCHES)
                # yc_match_result(result=results)
        else:
            sys.stderr.write('Could not open file: ' + file_path + '\n')
def yc_command_args_parse():
    parser = argparse.ArgumentParser()
    # Ideas
    # 1. Add option to scan a single file
    # 2. Add option to scan a directory
    # 3. Add option to save compiled rules to a file
    # 4. Experimental, memory telemetry outside of stdin/stdout
    # scanning
    parser.add_argument('--scan-list-stdin', action='store_true', help='will default to stdin, no recursive directory traversal')
    parser.add_argument('--scan-list', help='Scan list of paths to files, no recursive directory traversal')
    parser.add_argument('--scan-single-file', type=str, action='append', help='Path to the single file to scan')
    parser.add_argument('--scan-directory', type=str, action='append', help='Path of directory to scan')
    # rules
    parser.add_argument('--ignore-rule-list', help='Ignore file for rule list file, optional, paths of rules')
    parser.add_argument('--rules-list', help='Rules list file, required')
    parser.add_argument('--rules-file', type=str, action='append', help='Multiple can be supplied, for loading')
    # exporting compiled rules
    parser.add_argument('--export', action='store_true', help='Export compiled rules to a file')
    parser.add_argument('--export-path', help='Will default to compiled-export.yara Plaintext will not be assembled in a file.')
    # logging
    parser.add_argument('--results-log', help='will default to stdout, if not supplied')
    parser.add_argument('--output-log', help='will default to stdout, if not supplied')
    parser.add_argument('--error-log', help='will default to stderr, if not supplied')
    # options
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--core-count', help='Number of cores to use')

    args = parser.parse_args()
    # Initialize configuration
    yc_config['scan_list_path'] = args.scan_list
    yc_config['rules_list_path'] = args.rules_list
    yc_config['results_log_path'] = args.results_log
    yc_config['output_log_path'] = args.output_log
    yc_config['error_log_path'] = args.error_log
    yc_config['ignore_rule_list_path'] = args.ignore_rule_list
    yc_config['export_path'] = 'compiled-export.yar' if args.export_path == None else args.export_path
    yc_config['verbose'] = args.verbose
    yc_scanner_data['export_flag'] = args.export
    # Check if help is requested
    if 'help' in args:
        parser.print_help()
        quit()
    # Initialize file handles
    # Initialize error log
    if yc_config['error_log_path'] == None:
        yc_log_verbose('Error log not provided, using stderr')
        yc_file_handle_init(method='stderr', file_handle_key='error_log')
    else:
        yc_file_handle_init(method='file', file_path=yc_config['error_log_path'], file_mode='w', file_handle_key='error_log')
    # Initialize results log
    if yc_config['results_log_path'] == None:
        yc_log_verbose('Results log not provided, using stdout')
        yc_file_handle_init(method='stdout', file_handle_key='results_log')
    else:
        yc_file_handle_init(method='file', file_path=yc_config['results_log_path'], file_mode='w', file_handle_key='results_log')
    # Initialize output log
    if yc_config['output_log_path'] == None:
        yc_log_verbose('Output log not provided, using stdout')
        yc_file_handle_init(method='stdout', file_handle_key='output_log')
    else:
        yc_file_handle_init(method='file', file_path=yc_config['output_log_path'], file_mode='w', file_handle_key='output_log')
    # Rule list is required
    if yc_config['rules_list_path'] != None:
        yc_file_handle_init(method='file', file_path=yc_config['rules_list_path'], file_mode='r', file_handle_key='rules_list')
    else:
        sys.stderr.write('Rules list not provided\n')
        quit()
    # Check if ignore rule list is provided
    if yc_config['ignore_rule_list_path'] != None:
        yc_file_handle_init(method='file', file_path=yc_config['ignore_rule_list_path'], file_mode='r', file_handle_key='ignore_rule_list')
    # Check if scan list is provided
    if (args.scan_list_stdin == False) and (args.scan_single_file == None) and (args.scan_directory == None) and (args.scan_list == None):
        sys.stderr.write('Scan list not provided\n')
        quit()
    # Check for scan list
    if args.scan_list_stdin == True:
        yc_file_handle_init(method='stdin', file_handle_key='scan_list')
    # Check if scan single file is provided
    if (args.scan_list_stdin == False) and (args.scan_single_file != None):
        for file in args.scan_single_file:
            file = os.path.normpath(file)
            if os.path.isfile(file):
                yc_scanner_data['files'].append(file)
    # Check if scan directory is provided
    if (args.scan_list_stdin == False) and (args.scan_directory != None):
        for directory in args.scan_directory:
            if os.path.isdir(directory):
                yc_scanner_data['directories'].append(directory)
    # Check if scan list is provided
    if (args.scan_list_stdin == False) and (args.scan_list != None):
        if os.path.isfile(args.scan_list):
            yc_file_handle_init(method='file', file_path=yc_config['scan_list_path'], file_mode='r', file_handle_key='scan_list')
    # Check if core count is provided
    if args.core_count != None:
        if (args.core_count.isdigit() == False):
            sys.stderr.write('Invalid core count\n')
            quit()
        if (args.core_count > os.cpu_count()):
            sys.stderr.write('Core count exceeds available cores\n')
            quit()
        yc_config['core_count'] = int(args.core_count)
    else:
        yc_config['core_count'] = (os.cpu_count() / 2)
    # Check if export path is provided
    if args.export_path != None and yc_scanner_data['export_flag'] != False:
         yc_file_handle_init(method='file', file_path=yc_config['export_path'], file_mode='w', file_handle_key='export')


if __name__ == "__main__":
    yc_command_args_parse()
    yc_scanner_build_list()
    # must be called to prep the file list for scanning
    yc_enumerate_files()
    yc_enumerate_scan_files()

