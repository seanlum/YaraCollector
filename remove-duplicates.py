import os
import re
import yara
import io

existing_rules = {}

# with open('main.yar', 'r+') as clear_file:
#	clear_file.truncate()

def parse_rules(compiled):
    # for rule in compiled:
    #     # print(rule.identifier)
    #     if (rule.identifier in existing_rules):
    #         print('Duplicate rule: ' + rule.identifier)
    #     else:
    #         found = False
    #         for existing_rule in existing_rules.keys():
    #             for item in existing_rules[existing_rule].meta.keys():
    #                 for item2 in rule.meta.keys():
    #                     if item.startswith('hash') and item2.startswith('hash'):
    #                         if existing_rules[existing_rule].meta[item] == rule.meta[item2]:
    #                             found = True
    #                             print('Duplicate hash: ')
    #                             print(rule.identifier + ' == ' + existing_rule)
    #                             print(item + ' : ' + existing_rules[existing_rule].meta[item])
    #                             print(item2 + ' : ' + rule.meta[item2])
    #             for string in existing_rules[existing_rule].strings.keys():
    #                 for string2 in rule.strings.keys():
    #                     if existing_rules[existing_rule].strings[string] == rule.strings[string2]:
    #                         print('Duplicate string')
    #                         print(rule.identifier + ' == ' + existing_rule)
    #                         print(existing_rules[existing_rule].strings[string])
            if found == False:
                existing_rules[rule.identifier] = rule

def remove_duplicate_rules(file_paths):
    rule_names = set()
    output_lines = []
    rule_name_pattern = re.compile(r'rule\s+(\w+)')
    for file_path in file_paths:
        if file_path != '':
            # print(file_path)
            with open(file_path, 'r+', encoding='utf-8') as file:
                try:
                    data = file.read()
                except:
                    print('could not read ' + file_path)
                try:
                    rules = yara.compile(source=data, includes=True)
                    parse_rules(rules)
                except yara.SyntaxError as e:
                    print('(skipping) could not compile ' + file_path)
                    # print(e)
#    with open('main.yar', 'w', encoding='utf-8') as output_file:
#        output_file.writelines(output_lines)

if __name__ == "__main__":
    # List of YARA files to process
     with open('main.list','r') as yara_file:
          yara_files = yara_file.read().split('\n')
          remove_duplicate_rules(yara_files)
          print(str(len(existing_rules.keys())) + ' rules detected')
