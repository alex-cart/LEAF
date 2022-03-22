#import yara
import os
#from plugins.errorhandling import *


def parse_yaradir(yara_rules, rec, files_list=[]):
    for item in yara_rules:
        item = os.path.abspath(item)
        if os.path.isdir(item):
            if rec:
                subfiles = os.listdir(item)
                for file in subfiles:
                    file = os.path.join(item, file)
                    parse_yaradir([file], files_list=files_list, rec=True)
            else:
                files_list.extend([os.path.join(item, f) for f in os.listdir(
                    item) if os.path.isfile(os.path.join(item, f))])
        elif os.path.isfile(item) and ".yar" in item[-5:].lower():
            files_list.append(item)
    return files_list

def run_yara(yara_files, v=False):
    # what is the target??
    # for file in yara_file, run yara [rule] [target] > output dir
    pass


def main(yara_dict, verbose=False):
    yara_unrec = yara_dict["non-recurse"]
    yara_rec = yara_dict["recurse"]
    yara_files = []
    yara_files.extend(parse_yaradir(yara_unrec, rec=False))
    yara_files.extend(parse_yaradir(yara_rec, rec=True))
    yara_files = list(set(yara_files))
    if verbose:
        print(f"Parsing files: {yara_files}")
    return yara_files

