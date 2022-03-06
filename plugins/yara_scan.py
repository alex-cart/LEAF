#import yara
import os
#from plugins.errorhandling import *

def parse_yaradir(rules_path, files_list=[], rec="y"):
    rules_items = rules_path.split(",")
    for item in rules_items:
        if os.path.isdir(item):
            if "n" in rec.lower():
                files_list.extend([os.path.join(item + f) for f in os.listdir(
                    item) if os.path.isfile(os.path.join(item, f))])
            else:
                subfiles = os.listdir(item)
                for file in subfiles:
                    parse_yaradir(os.path.join(item, file), files_list)
        elif os.path.isfile(item):
            files_list.append(item)
    return files_list

def main(rules_path, verbose=False):
    reenter = "n"
    while "n" in reenter.lower():
        recursive = input("Recursively get files from input directories? "
                          "[Y/n]: ")
        yara_items = parse_yaradir(rules_path, rec=recursive.lower())
        print(f"Using following Yara files:\n\t{yara_items}.\nIs this okay?")
        reenter = input("Use these files (Y), or re-enter yara input "
                        "locations (n): ")
        if "n" in reenter.lower():
            new_locations = input("Enter location(s) to pull yara files "
                                  "from: ")
            rules_path = new_locations
    #rules = yara.compile(filepaths=yara_dir)

#items=r'C:\Users\Anya\Downloads\hackeru,
# C:\Users\Anya\Downloads\AliHadi2020x300.jpg'

#files = main(items)
#for file in files:
#    print("FILE: " , file)