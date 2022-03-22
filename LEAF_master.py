from plugins.errorhandling import *
import os
from datetime import datetime
import argparse
from argparse import RawTextHelpFormatter
from plugins.logging import Log
import pandas as pd
from tqdm import tqdm
import subprocess
import hashlib
import shutil

class bcolors:
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    Black = "\033[30m"
    Red = "\033[31m"
    Green = "\033[32m"
    Yellow = "\033[33m"
    Blue = "\033[34m"
    Magenta = "\033[35m"
    Cyan = "\033[36m"
    LightGray = "\033[37m"
    DarkGray = "\033[90m"
    LightRed = "\033[91m"
    LightGreen = "\033[92m"
    LightYellow = "\033[93m"
    LightBlue = "\033[94m"
    LightMagenta = "\033[95m"
    LightCyan = "\033[96m"
    ENDC = '\033[0m'


class Log():
    def __init__(self, save_loc=str(os.getcwd() + "/LEAF_output/")):
        """
        Create a new log session for logging file cloning operations and
        command issues.
        :param save_loc: (str) location to save log in
        """
        self.save_loc = save_loc

        # Filename of the new log series ("logitem_YYYY-MM-DD_hhmmss")
        self.log_fname = "logitem_" + str(datetime.datetime.now().strftime(
            "%Y-%m-%d_%H%M%S"))

        # Create headers for file-clone log and command log
        self.full_log = pd.DataFrame(columns=["Source_File", "Dest_File",
                                              "Source_Hash", "Dest_Hash",
                                              "Integrity", "File_Size",
                                              "Time_UTC"])
        self.cmd_log = pd.DataFrame(columns=["Input_TargetFile",
                                             "Output_Location",
                                             "Users_List", "Categories",
                                             "Image_Name",
                                             "Verbose", "Save_RawData",
                                             "YaraScanning"])

    def new_log(self, src_name, dst_name, src_hash, dst_hash, size=0):
        """
        Add a new clone log to logging file
        :param src_name: (str)  name of original file
        :param dst_name: (str)  name of destination file
        :param src_hash: (str)  hash of original file
        :param dst_hash: (str)  hash of destination file
        :return:
        """
        current_time = str(datetime.datetime.utcnow()).replace(" ", "T")
        new_log = {
            "Source_File" : src_name,
            "Dest_File" : dst_name,
            "Source_Hash" : src_hash,
            "Dest_Hash" : dst_hash,
            "Integrity" : src_hash == dst_hash,
            "File_Size" : size,
            "Time_UTC" : current_time,
        }
        self.update_df(new_log)

    def new_commandlog(self, leaf_obj):
        new_cmdlog = {
            "Input_TargetFile" : leaf_obj.targets_file,
            "Output_Location" : leaf_obj.output_dir,
            "Users_List" : leaf_obj.users_list,
            "Categories" : leaf_obj.cats,
            "Image_Name" : leaf_obj.img_path,
            "Verbose" : leaf_obj.verbose,
            "Save_RawData" : leaf_obj.raw,
            "YaraScanning" : leaf_obj.yara
        }
        self.update_df(new_cmdlog, log_type="Cmd")
        self.write_to_file(log_type="Cmd")


    def update_df(self, new_log, log_type="File"):
        if log_type == "File":
            self.full_log = self.full_log.append(new_log, ignore_index=True)
        else:
            self.cmd_log = self.cmd_log.append(new_log, ignore_index=True)


    def write_to_file(self, fname="", log_type="File"):
        floc = self.save_loc
        if fname == "":
            fname = self.log_fname + ".csv"

        if log_type == "File":
            if fname == "":
                fname = self.log_fname + ".csv"
            write_log = self.full_log
        else:
            fname = self.log_fname + "_CommandData.csv"
            write_log = self.cmd_log

        write_path = str(floc + fname)
        try:
            write_log.to_csv(write_path, index=False)
        except FileNotFoundError as e:
            os.makedirs(floc)
            write_log.to_csv(write_path, index=False)

    def __str__(self):
        pd.set_option("display.max_rows", None, "display.max_columns", None)
        return str(self.full_log)


class LEAFInfo():
    def __init__(self, in_files="", t_file="", cats="", out="", img="", raw="",
                 script="", users="", evdc="", v="", yara="",
                 yara_f="", leaf="", abs_path=""):
        self.input_files = in_files
        self.targets_file = t_file
        self.cats = cats
        self.output_dir = out
        self.img_path = img
        self.raw = raw
        self.users_list = users
        self.evidence_dir = evdc
        self.verbose = v
        self.yara_all = yara
        self.yara_files = yara_f
        self.script_path = script
        self.abs_path = abs_path
        self.leaf_paths = []
        self.iso_hash = ""
        self.all_cats = ["APPLICATIONS", "EXECUTIONS", "LOGS", "MISC",
                         "NETWORK", "STARTUP", "SERVICES", "SYSTEM",
                         "TRASH", "USERS"]

    def get_params(self):
        """
            Main handler for interpreting user input information creating the forensic
            environment for output items.
            :return: user parameters:
                targets_file : Location of the compiled targets file
                cats : Categories to parse
                out_dir : Output directory for all evidence and LEAF-generated files
                img_name : Name and location of the ISO Image File
                sve : Whether or not to save the raw evidence clone directory
                script_path : Path to the LEAF scripts
                user_lis : List of users to parse
                evdc_dir : Evidence Directory (out_dir/evdc_dir)
            """

        # Gets the real path of the script. If the script is run from symlink,
        # this will output the source of the symlink
        self.script_path = "/".join(os.path.realpath(__file__).split('/')[
                                 :-2])+"/"

        self.abs_path = str("/".join(os.path.abspath(__file__).split("/")[
                                     :-1]))+"/"

        self.leaf_paths = [self.abs_path, self.script_path, self.output_dir]

        # Creates argparse parser
        parser = argparse.ArgumentParser(
            description=(bcolors.Green +
                         'LEAF (Linux Evidence Acquisition Framework) - '
                         'Cartware\n'
             '     ____        _________    ___________   __________ \n'
             '    /   /       /   _____/   /  ____    /  /   ______/\n'
             '   /   /       /   /____    /  /___/   /  /   /____  \n'
             '  /   /       /   _____/  /   ____    /  /   _____/\n'
             ' /   /_____  /   /_____  /   /   /   /  /   /      \n'
             '/_________/ /_________/ /___/   /___/  /___/          v1.2\n\n' +
                         bcolors.ENDC +
                         'Process Ubuntu 20.04/Debian file systems for forensic '
                         'artifacts, extract important data, \nand export '
                         'information to an ISO9660 file. Compatible with EXT4 '
                         'file system and common \nlocations on Ubuntu 20.04 '
                         'operating system.\nSee help page for more '
                         'information.\nSuggested usage: Do not run from LEAF/ '
                         'directory'
                         + bcolors.ENDC),
            epilog="Example Usages:\n\n"
                   "To use default arguments [this will use "
                   "default input file (./target_locations), users ("
                   "all users), categories (all categories), "
                   "and output location (./LEAF_output/). Cloned data will not "
                   "be stored in a local directory, verbose mode is off, "
                   "and yara scanning is disabled]:" +
                   bcolors.Green + "\n\tLEAF_main.py\n\n" + bcolors.ENDC +
                   "All arguments:\n\t" + bcolors.Green +
                   "LEAF_main.py -i /home/alice/Desktop/customfile1.txt -o "
                   "/home/alice/Desktop/ExampleOutput/ -c logs,startup,"
                   "services -x apache -u alice,bob,charlie -s -v -y -yr "
                   "/path/to/yara_rules/\n" + bcolors.ENDC +
                   "To specify usernames, categories, and yara files:\n\t" +
                   bcolors.Green +
                   "LEAF_main.py -u alice,bob,charlie -c applications,"
                   "executions,users -y /home/alice/Desktop/yara1.yar,"
                   "/home/alice/Desktop/yara2.yar" + bcolors.ENDC +
                   "\nTo include custom input file(s) and categories:\n\t" +
                   bcolors.Green +
                   "LEAF_main.py -i /home/alice/Desktop/customfile1.txt,"
                   "/home/alice/Desktop/customfile2.txt -x apache,xampp\n" +
                   bcolors.ENDC,
            formatter_class=RawTextHelpFormatter)

        # Add arguments to parser
        parser.add_argument('-i', "--input", nargs='+',
                            default=[str(self.script_path +
                                         "target_locations")],
                            help=str("Additional Input locations. Separate "
                                     "multiple input files with \",\"\nDefault: "
                                     "" + self.script_path +
                                     "target_locations"))

        parser.add_argument('-o', "--output", type=str,
                            default=str(os.getcwd() + "/LEAF_output/"),
                            help='Output directory location\nDefault: '
                                 './LEAF_output')
        try:
            parser.add_argument('-u', "--users", nargs='+',
                                default=os.listdir("/home"),
                                help='Users to include in output, separated by '
                                     '\",\" (i.e. alice,bob,charlie). \nMUST be '
                                     'in /home/ directory\nDefault: All users')
        except FileNotFoundError:
            parser.add_argument('-u', "--users", nargs='+',
                                default=[],
                                help='Users to include '
                                     'in output, separated by \",\" (i.e. alice,'
                                     'bob,charlie). \nMUST be in /home/ '
                                     'directory\nDefault: All users')

        parser.add_argument('-c', "--categories", nargs='*', type=str,
                            default=self.all_cats,
                            help='Explicit artifact categories to include  '
                                 'during acquisition. \nCategories must be separated '
                                 'by space, (i.e. -c network users apache). '
                                 '\nFull List of built-in categories '
                                 'includes: \n\t' + str(self.all_cats) +
                                 '\nCategories are compatible with '
                                 'user-inputted files as long as they follow '
                                 'the notation: \n\t# CATEGORY\n'
                                 '\t/location1\n\t/location2 \n'
                                 '\t.../location[n]\n\t# END CATEGORY '
                                 '\nDefault: "all"')

        parser.add_argument('-v', "--verbose", help='Output in verbose '
                                                    'mode, (may conflict with '
                                                    'progress bar)\nDefault: False',
                            action='store_true')

        parser.add_argument('-s', "--save", help='Save the raw evidence '
                                                 'directory\nDefault: False',
                            action='store_true')

        parser.add_argument('-y', "--yara", nargs='*',
                            default="do_not_include",
                            help='Configure Yara IOC scanning. Select -y alone '
                                 'to enable Yara scanning. Specify \'-y '
                                 '/path/to/yara/\' to specify custom input location.'
                                 '\nFor multiple inputs, use spaces between items, '
                                 'i.e. \'-y rule1 rule2 rule_dir/\'\nDefault: None')
        parser.add_argument('-yr', "--yara_recursive", nargs='*',
                            default="do_not_include", help='Configure '
                       'Recursive Yara IOC scanning. \nFor multiple inputs, '
                       'use spaces between items, i.e. \'-yr rule1,'
                       'rule2 rule_dir/\'. Directories in this list will '
                       'be scanned recursively.\nCan be used in conjunction '
                       'with the normal -y flag, but intersecting items '
                       'will take recursive priority.\nDefault: None')
        # Compile the arguments
        args = parser.parse_args()

        # Stores the arguments into static variables
        # output_dir : string of output location (single value)
        output_dir = args.output
        # save : boolean whether to save directory of copied files
        save = args.save
        self.raw = args.save
        # verbose : boolean whether to use verbose output
        verb = args.verbose
        self.verbose = args.verbose
        # input_file : list of input files (files that have targets)
        input_files = args.input
        self.set_input_files(input_files)

        self.input_files = input_files
        # yara : whether or not to use yara scanning; optional list
        # No "-y" --> "do_not_include"
        # -y with no arguments --> [] --> use default rules
        # -y a b c --> ["a", "b", "c"] --> use specific rules
        yara = args.yara
        # Same as -y flag but with recursive-available locations
        yara_rec = args.yara_recursive
        self.set_yara(yara, yara_rec)

        # Formats the "output_dir" variable to have a trailing "/"
        # If the output directory is not listed from root, create the full path
        if output_dir[0] != "/":
            output_dir = os.path.join(os.getcwd(), output_dir)
        if output_dir[-1] != "/":
            output_dir = output_dir + "/"

        self.output_dir = output_dir
        self.create_output_dir()

        self.set_users(args.users)

        user_cats = [x.upper() for x in args.categories]
        self.set_cats(user_cats)

        # Parses the inputted file(s) string to merge multiple files if
        # necessary.
        self.read_input_files()
        # Creates forensic data output environment, and gets the Evidence
        # Directory and the Image Name from the created evidence location
        self.create_evdc(output_dir)

        print("Arguments: ")
        print("\tInput File(s):\t\t", self.input_files)
        print("\tCompiled Targets File:\t", self.targets_file)
        print("\tOutput Directory:\t", self.output_dir)
        print("\tImage Name:\t\t", self.img_name)
        print("\tSave raw?\t\t", self.raw)
        print("\tScript Path:\t\t", self.script_path)
        print("\tUser(s):\t\t", self.users_list)
        print("\tCategories:\t\t", self.cats)
        print("\tYara Scanning Enabled:\t", self.yara_scan)
        print()

    def set_users(self, in_users):
        # Checks each user and remove users that do not exist
        for user in in_users:
            if user not in os.listdir("/home/"):
                print(f"Non-existent user, {user}. Removing...")
                in_users.remove(user)

        # If all the users included were invalid
        # and removed, use the default users
        try:
            if len(in_users) == 0:
                raise ArgumentEmpty("users")
        except ArgumentEmpty as e:
            print("Error:", e)
            in_users = os.listdir("/home")

        self.users_list = in_users

    def set_cats(self, user_cats):
        cats = []
        # If they did not enter "all" or use the default categories,
        # split categories into a list and remove non-existent categories
        if "ALL" in [x.upper() for x in user_cats]:
            cats.extend(self.all_cats)
            # Deprecated - removes non-existent categories
            additional = list(set(user_cats) - set(self.all_cats))
            cats.extend(additional)
            cats.remove("ALL")
        else:
            cats = list(set(user_cats))
        # If all the categories included were invalid
        # and removed, use the default categories
        try:
            if len(cats) == 0:
                raise ArgumentEmpty("categories")
        except ArgumentEmpty as e:
            print("Error:", e)
            cats = self.all_cats
        self.cats = cats

    def set_yara(self, yara, yara_rec):
        yara_inputs = {"non-recurse": [], "recurse": []}
        # Yara data [] means the flag was specified, but no paths
        # were inputted. "do_not_include" means that flag was not specified
        for input_save in [[yara, yara_inputs["non-recurse"]],
                           [yara_rec, yara_inputs["recurse"]]]:
            # If yara was specified (empty list)
            if len(input_save[0]) == 0:
                input_save[1].append(str(self.script_path) + "/yara_rules/")
            elif "do_not_include" not in input_save[0]:
                input_save[1].extend(input_save[0])
        # If non-recursive parsing and recursive parsing are the same targets,
        # use the recursive method only
        yara_inputs["non-recurse"] = [item for item in yara_inputs[
            "non-recurse"] if item not in yara_inputs["recurse"]]
        self.yara_all = yara_inputs

        # Scanning is enabled if either recursive or non-recursive is populated
        self.yara_scan_bool = (yara_inputs["non-recurse"] != [] or
                     yara_inputs["recurse"] != [])
        if self.yara_scan_bool:
            yara_unrec = yara_inputs["non-recurse"]
            yara_rec = yara_inputs["recurse"]
            yara_files = []
            yara_files.extend(self.parse_yaradir(yara_unrec, rec=False))
            yara_files.extend(self.parse_yaradir(yara_rec, rec=True))
            yara_files = list(set(yara_files))
            self.verbose_write(f"Parsing files: {yara_files}")
            self.yara_files = yara_files
        else:
            self.yara_files = []

    def set_input_files(self, in_files):
        input_files_paths = []
        for file in in_files:
            try:
                if not os.path.isfile(file):
                    self.verbose_write(f"Input file {file} does not exist. "
                                 f"Removing...")
                    raise DoesNotExistError(file)
                else:
                    input_files_paths.append(os.path.abspath(file))
            except DoesNotExistError as e:
                print("Error: ", e)
        if len(input_files_paths) == 0:
            # If all the items got removed from the input list due to not
            # existing, use default file
            input_files_paths = [os.path.join(self.script_path,
                                              "target_locations")]
        self.input_files = input_files_paths

    def create_output_dir(self):
        print("\nCreating", self.output_dir + "....")
        # If that directory does not exist, create it
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, mode=775)
        elif self.verbose:
            print("Path already exists. Continuing...\n")

    def create_evdc(self):
        # Gets the time of execution to assign to the image name
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.img_path = os.path.join(self.output_dir,
                                     str("LEAF_acquisition_" +
                                         str(current_time) + ".ISO"))

        evidence_dir = os.path.join(self.output_dir, "evidence")
        i = ""
        # If the evidence directory does not exist, create it
        if not os.path.exists(evidence_dir):
            os.makedirs(evidence_dir, mode=775)
        # Otherwise, if the evidence directory exists, parse all numbers in
        # range 1,255 to create a new directory, <evidence#> to prevent data
        # overwrite
        else:
            for i in range(1, 256):
                i = str(i)
                if not os.path.exists(evidence_dir + i):
                    os.makedirs(evidence_dir + i)
                    break
        self.evidence_dir = evidence_dir + i + "/"
        print("Creating evidence directory:", evidence_dir + "...")
        print()

    def read_input_files(self):
        #in_file = os.path.join(self.output_dir, "temp_file")
        # in_file, cats, output_dir, script_path, users
        #with open(in_file, "w+") as f:
        #    data = f.read()

        # Write every target location stored in input_files_paths to a
        # temporary file
        #targets = data.split("\n")
        targets = []
        for file in self.input_files:
            with open(file) as nextfile:
                data = data + nextfile.read()
                for line in nextfile:
                    targets.append(line)

        # Parse the list of files based on category to the target_locations list
        # in the output directory; remove the temp directory
        self.write_targets(targets)
        #os.remove(str(self.output_dir + "temp_file"))
        #return input_files_paths, targets_file

    def write_targets(self, targets):
        # Prepare the output file in the output directory
        self.targets_file = os.path.join(self.output_dir, "target_locations")

        if os.path.exists(self.targets_file):
            # If the file does exist, name it with the soonest number 1, 2,...
            for i in range(1, 256):
                i = str(i)
                if not os.path.exists(self.read_target_file + i):
                    # Rename the output targets file as necessary
                    self.read_target_file = self.read_target_file + i
                    break

        print("Creating target file,", self.targets_file + "...")
        # Begin to write to the target file
        f = open(self.targets_file, "w")
        # value to determine if files are in a sought category
        header_found = False
        # For each user, for each target line
        # (directory, file, header, trailer)
        for user in self.users:
            for target in targets:
                # If the line starts with "#", it is a header or a trailer
                if target[0] == "#":
                    # The current category is the last word in the header/trailer
                    ### current_cat = target.split(' ')[-1][:-1].upper()
                    current_cat = target.split(' ')[-1].strip().upper()
                    # If "END" is not in the line, this is the header of a category
                    if target.split(" ")[1].upper() != "END":
                        # If the header is in the category list, a header is found
                        if current_cat in self.cats:
                            header_found = True
                    else:
                        # Otherwise, if it is a trailer, the header is no longer
                        # found
                        header_found = False
                elif target != "":
                    # If the line is not a header/trailer nor empty...
                    if header_found:
                        # Write the line with replacing $USER with a user in a list
                        new_target = target.replace("$USER", user)
                        f.write(new_target)

        # Close the file after all writes and return the compiled target file
        f.close()

    def parse_yaradir(self, yara_rules, rec):
        for item in yara_rules:
            item = os.path.abspath(item)
            if os.path.isdir(item):
                if rec:
                    for root, dirs, files in os.walk(item):
                        for file in files:
                            if ".yar" in item[-5:].lower():
                                self.yara_files.append(os.path.join(root,
                                                                    file))
                else:
                    self.yara_files.extend(
                        [os.path.join(item, f) for f in os.listdir(
                            item) if os.path.isfile(os.path.join(item, f)) and
                         ".yar" in item[-5:].lower()])
            elif os.path.isfile(item) and ".yar" in item[-5:].lower():
                self.yara_files.append(item)

    def run_yara(self, yara_files):
        # what is the target??
        # for file in yara_file, run yara [rule] [target] > output dir
        pass

    def copy_files_main(self, New_LogFile):
            """
            Main handler for the copy file + metadata operations.
            :param target_file: (str)   file of listed targets
            :param evidence_dir: (str)  location of evidence directory
            :param v: (bool)      Verbose output on or off
            :param leaf_paths: (list)   list of protected locations used by LEAF
            :return:
            """
            # target_file, evidence_dir, v, leaf_paths,

            # Read all lines of the targets file and save to targets list
            with open(self.targets_file) as f:
                targets = f.readlines()
            # Parse each line/location; uses tqdm to generate a progress bar
            for i in tqdm(range(len(targets))):
                # Removes any trailing whitespaces or special characters
                line = targets[i].strip()

                # If the path does not exist, raise the DoesNotExist error
                try:
                    if not os.path.exists(line):
                        raise DoesNotExistError(line)

                    # If the line is in protected LEAF paths, raise LEAFinPath Error
                    elif any(l_path in line for l_path in self.leaf_paths):
                        raise LEAFInPath(line)
                    # Otherwise, if it is a valid path...
                    else:
                        # Get its partition location
                        part = subprocess.check_output(f"df -T '{line}'",
                                                       shell=True) \
                            .decode('utf-8').split("\n")[1].split(" ")[0]
                        # push the item to copy_item()
                        if not any(l_path in line for l_path in
                                   self.leaf_paths):
                            self.copy_item(line, part, New_LogFile)
                except DoesNotExistError as e:
                    print("Error:", e, "\nContinuing...")
                except LEAFInPath as e:
                    print("Error:", e, "\nContinuing...")

            print("\n\n")
            return New_LogFile

    def copy_item(self, src, part, logfile):
        """
        Copy each item from the source to the destination with incorporation
        of debugfs to ensure the secure copy of file (inode) metadata.
        :param src: (str)       file or directory that is being copied from
        :param evdc_dir: (str)  evidence directory
        :param part: (str)      partition that stores the files
        :return:
        """

        # The new item to be parsing; this will be the target location
        new_root = self.evidence_dir + src[1:]

        if any(l_path in src for l_path in self.leaf_paths):
            self.verbose_write(f"Skipping {src}: LEAF in Path")
            return

        self.verbose_write(f"CLONING {src}...")

        if os.path.isdir(src):
            # Otherwise, if the source is a directory, make sure it has a
            # trailing "/"...
            if src[-1] != "/":
                src = src + "/"

            # Copy the entire file structure to the target location. --parent
            # ensures that the entire hierarchy is copied, not just the final
            # directory
            copy = f"mkdir --parents '{new_root}'"
            os.system(copy)

            # Run debugfs to copy the inode data from the source to destination
            self.debugfs(src, new_root, part)

            ### TODO: Test this out
            files_list = []
            dirs_list = []
            for root, dirs, files in os.walk(src):
                for dir in dirs:
                    dirs_list.extend(os.path.join(root, dir))
                for file in files:
                    files_list.extend(os.path.join(root, file))

            for dir in dirs_list:
                if src[-1] != "/":
                    src = src + "/"
                copy = f"mkdir --parents '" \
                       f"{os.path.join(self.evidence_dir, dir)}'"
                os.system(copy)
                self.debugfs(src, new_root, part)
            for file in files_list:
                self.copy_item(file, part, logfile)


            """for filename in os.listdir(src):
                # Each item in the directory will be run through copy_item()
                # recursively with an updated source, as long as not in LEAF paths
                if not any(l_path in os.path.join(src, filename) for l_path in
                           self.leaf_paths):
                    # copy_item(os.path.join(src, filename), evdc_dir, part, v,
                    #          l_paths, logfile)
                    self.copy_item(os.path.join(src, filename), part, logfile)"""
        elif os.path.isfile(src):
            # If the source is a file, copy it to the latest target location
            copy = f"mkdir --parents " \
                   f"'{self.evidence_dir}{'/'.join(src.split('/')[:-1])}'"

            os.system(copy)

            copy = f"cp -p '{src}' '{new_root}'"
            os.system(copy)
            check_int = self.checkIntegrity(src, new_root)
            # Test if the source file and destination file have the same hash
            try:
                # If False, raise NonMatchingHashes error
                if not check_int[0]:
                    raise NonMatchingHashes(src, new_root)
            except NonMatchingHashes as e:
                print("Error:", e)

            # Use debugfs to copy each file's inode data over
            self.debugfs(src, new_root, part)

            try:
                file_size = os.path.getsize(new_root)
            except:
                file_size = "NA"
            # Log the action
            logfile.new_log(src, new_root, check_int[0], check_int[1],
                            file_size)
            # return to previous recursive statement
            return

        else:
            if os.path.islink(src):
                copy = f"mkdir --parents '{new_root}'"
                os.system(copy)
                copy = f"cp -P -p '{src}' '{new_root}'"
                os.system(copy)
            else:
                return

    def checkIntegrity(self, s_file, d_file):
        """
        Check Integrity of the copied file against the original file.
        :param s_file: (str)    source (original) file
        :param d_file: (str)    destination (copied) file
        :return: (bool) Whether or not the file hashes match
        """
        # List to store file hashes in
        hashes = []
        # Parse each file
        for file in (s_file, d_file):
            # Do not attempt to hash link files
            if os.path.islink(s_file):
                return True
            # Generating the hash for the file
            sha1 = hashlib.sha1()
            with open(file, 'rb') as f:
                buf = f.read()
                sha1.update(buf)
            # Add the hash to the file list
            hashes.append(sha1.hexdigest())
        # If the hashes do not match, return False
        if hashes[0] != hashes[1]:
            match = False
        else:
            # Otherwise, if hashes match, return true
            match = True
        return (match, hashes[0], hashes[1])

    def debugfs(self, src, tgt, part):
        """
        Transfer inode data from source item to destination item on single
        partition.
        :param src: (str)   source item being copied
        :param tgt: (str)   copied file
        :param part: (str)  partition name
        """

        """ ### TODO: Test WHY I use [:-1] ?????
        # Get the original item's inode identifier
        orig_inode = subprocess.check_output(f"stat -c %i '{src}'",
                                             shell=True).decode("utf-8")[:-1]
        # Get the copied item's inode identifier
        new_inode = subprocess.check_output(f"stat -c %i '{tgt}'",
                                            shell=True).decode("utf-8")[:-1]"""
        # Get the original item's inode identifier
        orig_inode = subprocess.check_output(f"stat -c %i '{src}'",
                                             shell=True).decode(
            "utf-8").strip()
        # Get the copied item's inode identifier
        new_inode = subprocess.check_output(f"stat -c %i '{tgt}'",
                                            shell=True).decode("utf-8").strip()
        # Copy the inode data associated with the source file to the copied file
        if self.verbose:
            debug_cmd = f"debugfs -wR \"copy_inode <{orig_inode}> <{new_inode}>\"" \
                        f" {part}"
        else:
            debug_cmd = f"debugfs -wR \"copy_inode <{orig_inode}> <{new_inode}>\"" \
                        f" {part} > /dev/null 2>&1"
        os.system(debug_cmd)

    def get_image(self):
        print(f"Acquiring '{self.evidence_dir}'...")
        os.system(f"tree -a '{self.evidence_dir}")
        print(f"Writing data to '{self.img_path}'")
        os.system(
            f"mkisofs -max-iso9660-filenames -U -o '{self.evidence_dir}' "
            f"'{self.output_dir}'")
        print("Done!")
        self.getHash()
        if not self.raw:
            shutil.rmtree(self.evidence_dir)

    def getHash(self):
        """
        Check Integrity of the copied file against the original file.
        :param s_file: (str)    source (original) file
        :param d_file: (str)    destination (copied) file
        :return: (bool) Whether or not the file hashes match
        """
        # Generating the hash for the file
        sha1 = hashlib.sha1()
        with open(self.img_path, 'rb') as f:
            buf = f.read()
            sha1.update(buf)
        self.iso_hash = sha1.hexdigest()

    def verbose_write(self, prnt):
        if self.verbose:
            print(prnt)

    def __str__(self):
        out = ""
        for i in self.all_args:
            out = out + str(i) + "\n"
        return out


def main():
    """
    Main handler for LEAF framework. LEAF_main.py is the file that will be
    executed and it will handle the rest of the calling of other files and
    dependencies accordingly
    """

    ### Instantiate the environment
    # Get the start time of execution
    start_time = datetime.now()

    # Gets the the argparse values
    LEAFObj = LEAFInfo()
    LEAFObj.get_params()

    # Ensure that the program is run in root
    try:
        if os.getuid() != 0:
            raise RootNotDetected
    except RootNotDetected as e:
        print("Error:", e)
        exit()

    # Initialize a Log File object
    LogFile = Log(save_loc=LEAFObj.script_path)

    # Create a command-run log
    LogFile.new_commandlog(LEAFObj)

    ### Start Clone/Copy Operations

    # Runs copy_files() to read the targeted locations file and copy
    # appropriate locations to the evidence directory
    ###copy_files(parameters["targets_file"], parameters[
    ###    "evidence_directory"], parameters["verbose"], leaf_paths, LogFile)
    LEAFObj.copy_files_main(LogFile)

    # Runs get_image() to create the image file for the evidence and hash
    # the image
    LEAFObj.get_image()
    LogFile.write_to_file()

    #if parameters["yara"]:
    #   scan_yara(str(parameters["script_path"] + "yara_rules/"))
    # Trailer
    print()
    print(f"Acquisition completed.\n\tFilename: {LEAFObj.img_path} "
          f"\n\tSHA1 Hash: {LEAFObj.iso_hash}")
    print()

    end_time = datetime.datetime.now()
    e = end_time - start_time
    # Create time elapsed
    print(f"Processing Time: {e}")


if __name__ == "__main__":
    main()

