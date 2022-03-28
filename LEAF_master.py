#!/usr/bin/python
import pandas as pd
from extensions.errorhandling import *
import os
from datetime import datetime
import argparse
from argparse import RawTextHelpFormatter
from tqdm import tqdm
import subprocess
import hashlib
import shutil

"""
May need to install packages like pandas using `sudo -H pip3 install pandas`
or `sudo -H pip3 install -r requirements.txt
"""


class bColors:
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


class Log:
    def __init__(self, save_loc=str(os.getcwd() + "/LEAF_output/")):
        """
        Create a new log session for logging file cloning operations and
        command issues.
        :param save_loc: (str) location to save log in
        """
        self.save_loc = save_loc

        # Filename of the new log series ("logitem_YYYY-MM-DD_hhmmss")
        self.log_fname = "logitem_" + str(datetime.now().strftime(
            "%Y-%m-%d_%H%M%S"))

        # Create headers for file-clone log, command log, and error log
        self.full_log = pd.DataFrame(columns=["Source_File", "Dest_File",
                                              "Source_Hash", "Dest_Hash",
                                              "Integrity", "File_Size",
                                              "Time_UTC"])
        self.cmd_log = pd.DataFrame(columns=["Input_TargetFile",
                                             "Output_Location",
                                             "Users_List", "Categories",
                                             "Image_Name",
                                             "Verbose", "Save_RawData",
                                             "Yara_Scanning", "Yara_Files"])

        self.err_log = pd.DataFrame(columns=["Time", "Error", "Function"])

    def new_log(self, src_name, dst_name, src_hash, dst_hash, size=0):
        """
        Add a new clone log to logging file
        :param src_name: (str)  name of original file
        :param dst_name: (str)  name of destination file
        :param src_hash: (str)  hash of original file
        :param dst_hash: (str)  hash of destination file
        :param size: (int)      size of file (B)
        :return:
        """
        current_time = str(datetime.utcnow()).replace(" ", "T")
        new_log = {
            "Source_File": src_name,
            "Dest_File": dst_name,
            "Source_Hash": src_hash,
            "Dest_Hash": dst_hash,
            "Integrity": src_hash == dst_hash,
            "File_Size": size,
            "Time_UTC": current_time,
        }
        self.update_df(new_log)

    def new_commandlog(self, leaf_obj):
        new_cmdlog = {
            "Input_TargetFile": leaf_obj.targets_file,
            "Output_Location": leaf_obj.output_dir,
            "Users_List": str(leaf_obj.users_list),
            "Categories": str(leaf_obj.cats),
            "Image_Name": leaf_obj.img_path,
            "Verbose": leaf_obj.verbose,
            "Save_RawData": leaf_obj.raw,
            "Yara_Scanning": leaf_obj.yara_scan_bool,
            "Yara_Files": str(leaf_obj.yara_files)
        }
        self.update_df(new_cmdlog, log_type="Cmd")
        self.write_to_file(log_type="Cmd")

    def new_errorlog(self, e, f):
        new_errlog = {
            "Time": datetime.now().strftime("%Y-%m-%d_%H-%M-%S"),
            "Error": e,
            "Function": f
        }
        self.update_df(new_errlog, log_type="Err")

    def update_df(self, new_log, log_type="File"):
        if log_type == "File":
            new_log = pd.DataFrame(new_log,
                                   columns=list(self.full_log.columns),
                                   index=[0])
            self.full_log = pd.concat([self.full_log, new_log],
                                      ignore_index=True)
        elif log_type == "Cmd":
            new_log = pd.DataFrame(new_log, columns=list(self.cmd_log.columns),
                                   index=[0])
            self.cmd_log = pd.concat([self.cmd_log, new_log],
                                     ignore_index=True)
        elif log_type == "Err":
            new_log = pd.DataFrame(new_log, columns=list(self.err_log.columns),
                                   index=[0])
            self.err_log = pd.concat([self.err_log, new_log],
                                     ignore_index=True)

    def write_to_file(self, fname="", log_type="File"):
        floc = self.save_loc
        if fname == "":
            fname = self.log_fname + ".csv"

        if log_type == "File":
            write_log = self.full_log
        elif log_type == "Cmd":
            fname = self.log_fname + "_CommandData.csv"
            write_log = self.cmd_log
        elif log_type == "Err":
            fname = self.log_fname + "_ErrorLog.csv"
            write_log = self.err_log

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
    def __init__(self):
        """
        Class Attributes:
            script_path (str)   : real path to script
            abs_path (str)      : absolute path to script
            input_files (list)  : files the user inputs for parsing
            targets_file (str)  : created file containing list of artifact
                                    locations
            all_cats (list)     : list of all default categories
            cats (list)         : list of categories user seeks to parse
            output_dir (str)    : location to output evidence, logs, and image
            img_path (str)      : file location + name of ISO image
            evidence_dir (str)  : location + name of evidence directory
            users_list (list)   : list of users to parse
            users_dict (dict)   : dictionary of user information for inputted
                                    users
            all_users (dict)    : dictionary of all user information on the host
            primary_users (dict): dictionary of all non-service user
                                    information
            groups (dict)       : group information present on the system
            yara_inputs (dict)  : dictionary of inputted yara file locations
                                    (non-recursive and recursive)
            yara_files (list)   : list of yara rule files
            yara_scan_bool (bool)   : whether or not yara is enabled
            raw (bool)          : whether or not to save file clones in
                                    directory (evidence_dir)
            get_ownership (list): list of locations to parse for user-owned
                                    files
            iter (str)          : iterable value to associate evidence_dir
                                    and targets_file
            leaf_paths (list)   : list of protected paths; not acquired
            iso_hash (str)      : hash of ISO file

        """
        self.script_path = "/".join(os.path.realpath(__file__).split('/')[
                                    :-1]) + "/"
        self.abs_path = "/".join(os.path.abspath(__file__).split("/")[
                                 :-1]) + "/"
        self.input_files = [os.path.join(self.abs_path, "target_locations")]
        self.targets_file = os.path.join(self.abs_path, "target_locations")
        self.all_cats = ["APPLICATIONS", "EXECUTIONS", "LOGS", "MISC",
                         "NETWORK", "STARTUP", "SERVICES", "SYSTEM",
                         "TRASH", "USERS"]
        self.cats = ["APPLICATIONS", "EXECUTIONS", "LOGS", "MISC", "USERS",
                     "NETWORK", "STARTUP", "SERVICES", "SYSTEM", "TRASH"]
        self.output_dir = os.path.join(os.getcwd(), "LEAF_output/")
        self.img_path = str("LEAF_acquisition_" + str(datetime.now()) + ".ISO")
        self.evidence_dir = os.path.join(self.output_dir, "evidence")
        self.users_dict = {}
        self.users_list = []
        self.all_users = {}
        self.primary_users = {}
        self.groups = {}
        self.yara_inputs = {"recurse": [], "non-recurse": []}
        self.yara_files = []
        self.yara_scan_bool = False
        self.verbose = False
        self.raw = False
        self.get_ownership = []
        self.iter = ""
        self.leaf_paths = [self.script_path, self.abs_path, self.output_dir]
        self.iso_hash = ""

    def get_params(self):
        """
            Main handler for interpreting user input information creating the
            forensic environment for output items.
            Assigns the following class attributes:
                input_files : list of "targets" files the user chooses to
                            include
                targets_file : Location of the compiled targets file
                cats : Categories to parse
                output_dir : Output directory for all evidence and
                            LEAF-generated files
                img_path : Name and location of the ISO Image File
                raw : Whether or not to save the raw evidence clone directory
                script_path : Path to the LEAF scripts
                users_list : List of users to parse
                users_dict : dictionary of user information for inputted users
                all_users : dictionary of all user information on the host
                primary_users : dictionary of all non-service user information
                groups : groups present on the system
                evidence_dir : Evidence Directory (out_dir/evdc_dir)
                yara_scan_bool : whether or not yara scanning is enabled
                get_ownership : list of locations to parse for user-owned files
                yara_files : list of yara files from which rules will be pulled
                leaf_paths : list of protected locations that must not be
                            acquired
            """

        # Creates argparse parser
        parser = argparse.ArgumentParser(
            description=(bColors.Green +
                         'LEAF (Linux Evidence Acquisition Framework) - '
                         'Cartware\n'
                         '     ____        _________    ___________   __________ \n'
                         '    /   /       /   _____/   /  ____    /  /   ______/\n'
                         '   /   /       /   /____    /  /___/   /  /   /____  \n'
                         '  /   /       /   _____/  /   ____    /  /   _____/\n'
                         ' /   /_____  /   /_____  /   /   /   /  /   /      \n'
                         '/_________/ /_________/ /___/   /___/  /___/          v1.9\n\n' +
                         bColors.ENDC +
                         'Process Ubuntu 20.04/Debian file systems for forensic '
                         'artifacts, extract important data, \nand export '
                         'information to an ISO9660 file. Compatible with EXT4 '
                         'file system and common \nlocations on Ubuntu 20.04 '
                         'operating system.\nSee help page for more '
                         'information.\nSuggested usage: Do not run from LEAF/ '
                         'directory'
                         + bColors.ENDC),
            epilog="Example Usages:\n\n"
                   "To use default arguments [this will use "
                   "default input file (./target_locations), users ("
                   "all users), categories (all categories), "
                   "and output location (./LEAF_output/). Cloned data will "
                   "not be stored in a local directory, verbose mode is off, "
                   "and yara scanning is disabled]:" +
                   bColors.Green + "\n\tLEAF_main.py\n\n" + bColors.ENDC +
                   "All arguments:\n\t" + bColors.Green +
                   "LEAF_main.py -i /home/alice/Desktop/customfile1.txt -o "
                   "/home/alice/Desktop/ExampleOutput/ -c logs startup "
                   "services apache -u alice bob charlie -s -v -y "
                   "/path/to/yara_rule1.yar -yr /path2/to/yara_rules/ -g /etc/"
                   "\n\n" + bColors.ENDC + "To specify usernames, categories, "
                   "and yara files:\n\t" + bColors.Green +
                   "LEAF_main.py -u alice bob charlie -c applications "
                   "executions users -y /home/alice/Desktop/yara1.yar "
                   "/home/alice/Desktop/yara2.yar\n\n" + bColors.ENDC +
                   "To include custom input file(s) and categories:\n\t" +
                   bColors.Green +
                   "LEAF_main.py -i /home/alice/Desktop/customfile1.txt "
                   "/home/alice/Desktop/customfile2.txt -c apache xampp\n" +
                   bColors.ENDC,
            formatter_class=RawTextHelpFormatter)

        # Add arguments to parser
        parser.add_argument('-i', "--input", nargs='+',
                            default=[os.path.join(self.abs_path,
                                                  "target_locations")],
                            help=str("Additional Input locations. Separate "
                                     "multiple input files with spaces\n"
                                     "Default: " + self.abs_path +
                                     "target_locations"))

        parser.add_argument('-o', "--output", type=str,
                            default=os.path.join(os.getcwd(), "LEAF_output/"),
                            help='Output directory location\nDefault: '
                                 './LEAF_output')

        parser.add_argument('-u', "--users", nargs='+',
                            default=[],
                            help='Users to include in output, separated '
                                 'by spaces (i.e. -u alice bob root). '
                                 '\nUsers not present in /etc/passwd will be '
                                 'removed\nDefault: All non-service users '
                                 'in /etc/passwd')

        parser.add_argument('-c', "--categories", nargs='+', type=str,
                            default=self.all_cats,
                            help='Explicit artifact categories to include '
                                 'during acquisition. \nCategories must be '
                                 'separated by space, (i.e. -c network users '
                                 'apache).\nFull List of built-in categories '
                                 'includes:' + list_to_str(self.all_cats,
                                                           "\t") +
                                 '\nCategories are compatible with '
                                 'user-inputted files as long as they follow '
                                 'the notation:' + bColors.Yellow +
                                 '\n\t# CATEGORY\n\t/location1\n\t/location2 '
                                 '\n\t.../location[n]\n\t# END CATEGORY '
                                 + bColors.ENDC + '\nDefault: "all"')

        parser.add_argument('-v', "--verbose", help='Output in verbose '
                                                    'mode, (may conflict with '
                                                    'progress bar)'
                                                    '\nDefault: False',
                            action='store_true')

        parser.add_argument('-s', "--save", help='Save the raw evidence '
                                                 'directory\nDefault: False',
                            action='store_true')

        parser.add_argument('-g', "--get_ownership", nargs='*',
                            help='Get files and directories owned by included '
                                 'users.\nEnabling this will '
                                 'increase parsing time.\nUse -g '
                                 'alone to parse from / root '
                                 'directory.\nInclude paths after '
                                 '-g to specify target locations ('
                                 'i.e. "-g /etc '
                                 '/home/user/Downloads/\nDefault: '
                                 'Disabled', default="disabled")

        parser.add_argument('-y', "--yara", nargs='*',
                            default="do_not_include",
                            help='Configure Yara IOC scanning. Select -y '
                                 'alone to enable Yara scanning.\nSpecify \'-y'
                                 ' /path/to/yara/\' to specify custom input '
                                 'location.\nFor multiple inputs, use spaces '
                                 'between items,\ni.e. \'-y rulefile1.yar '
                                 'rulefile2.yara rule_dir/\'\nAll yara files '
                                 'must have \".yar\" or \".yara\" extension.'
                                 '\nDefault: None')
        parser.add_argument('-yr', "--yara_recursive", nargs='*',
                            default="do_not_include",
                            help='Configure '
                                 'Recursive Yara IOC scanning.\nFor multiple '
                                 'inputs, use spaces between items,\ni.e. '
                                 '\'-yr rulefile1.yar rulefile2.yara '
                                 'rule_dir/\'.\nDirectories in this list will '
                                 'be scanned recursively.\nCan be used in '
                                 'conjunction with the normal -y flag,\nbut '
                                 'intersecting directories will take '
                                 'recursive priority.\nDefault: None')
        # Ensure that the program is run in root
        try:
            if os.getuid() != 0:
                raise RootNotDetected
        except RootNotDetected as e:
            print("Error:", e)
            exit()

        # Compile the arguments
        args = parser.parse_args()

        self.raw = args.save
        self.verbose = args.verbose
        self.set_input_files(args.input)

        # yara : whether or not to use yara scanning; optional list
        yara = args.yara
        # Same as -y flag but with recursive-available locations
        yara_rec = args.yara_recursive
        # parse the inputted yara file locations
        self.set_yara(yara, yara_rec)

        # Stores the arguments into static variables
        output_dir = args.output
        # Formats the "output_dir" variable to have a trailing "/"
        # If the output directory is not listed from root, create the full path
        if output_dir[0] != "/":
            higher_wd = os.path.abspath("/".join(output_dir.split("/")[:-1]))
            output_dir = os.path.join(higher_wd, output_dir.split("/")[-1])
        if output_dir[-1] != "/":
            output_dir = output_dir + "/"

        self.output_dir = output_dir
        self.leaf_paths = [self.abs_path, self.script_path, self.output_dir]

        self.create_output_dir()

        self.get_all_users()
        if len(self.users_list) == 0:
            in_users = list(self.primary_users.keys())
        else:
            in_users = args.users
        self.set_users(in_users)

        if args.get_ownership == []:
            self.get_ownership = ["/"]
        elif args.get_ownership == "disabled":
            self.get_ownership = []
        else:
            self.get_ownership = [os.path.abspath(loc) for loc in
                                  args.get_ownership]

        user_cats = [x.upper() for x in args.categories]
        self.set_cats(user_cats)

        # Parses the inputted file(s) string to merge multiple files if
        # necessary.
        self.read_input_files()
        # Creates forensic data output environment, and gets the Evidence
        # Directory and the Image Name from the created evidence location
        self.create_evdc()

        if self.yara_scan_bool:
            print("Note: Yara Scanning is still in development and will "
                  "not parse in this version.")
        print()

    def set_users(self, in_users):
        output_users = {}
        for user in in_users:
            for uname in self.all_users:
                if user.upper() == uname.upper():
                    output_users[uname] = all_list[uname]
        self.users_dict = output_users
        self.users_list = list(self.users_dict.keys())

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

        # Scanning is enabled if either recursive or non-recursive is populated
        self.yara_scan_bool = (self.yara_inputs["non-recurse"] != [] or
                               self.yara_inputs["recurse"] != [])
        if self.yara_scan_bool:
            yara_unrec = self.yara_inputs["non-recurse"]
            yara_rec = self.yara_inputs["recurse"]
            yara_files = []
            self.parse_yaradir(yara_rec, rec=True)
            self.parse_yaradir(yara_unrec, rec=False)
            self.yara_files = list(set(self.yara_files))
            self.verbose_write(f"Parsing files: {yara_files}")
        else:
            self.yara_files = []

    def set_input_files(self, in_files):
        input_files_paths = []
        for file in in_files:
            try:
                if not os.path.isfile(file):
                    if self.verbose: raise DoesNotExistError(file)
                    self.verbose_write(f"Removing...")
                else:
                    input_files_paths.append(os.path.abspath(file))
            except DoesNotExistError as e:
                self.verbose_write("Error: ", e)
        if len(input_files_paths) == 0:
            # If all the items got removed from the input list due to not
            # existing, use default file
            input_files_paths = [os.path.join(self.script_path,
                                              "target_locations")]
        self.input_files = input_files_paths

    def create_output_dir(self):
        self.verbose_write("\nCreating", self.output_dir + "....")
        # If that directory does not exist, create it
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, mode=775)
        elif self.verbose:
            self.verbose_write("Path already exists. Continuing...\n")

    def create_evdc(self):
        # Gets the time of execution to assign to the image name
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.img_path = os.path.join(self.output_dir,
                                     str("LEAF_acquisition_" +
                                         str(current_time) + ".ISO"))
        evidence_dir = os.path.join(self.output_dir, f"evidence{self.iter}")
        i = ""
        # If the evidence directory does not exist, create it
        if not os.path.exists(evidence_dir):
            os.makedirs(evidence_dir, mode=775)
        # Otherwise, if the evidence directory exists, parse all numbers in
        # range 1,255 to create a new directory, <evidence#> to prevent data
        # overwrite
        else:
            for i in range(1, 256):
                i = f"-{str(i)}"
                if not os.path.exists(evidence_dir + i):
                    os.makedirs(self.evidence_dir + i, mode=775)
                    break
        self.evidence_dir = evidence_dir + i + "/"
        self.verbose_write(f"Creating evidence directory: "
                           f"{self.evidence_dir}...")

    def get_all_users(self):
        passwd_file = "/etc/passwd"
        groups_file = "/etc/group"
        users_dict = {}
        primary_users_dict = {}
        groups_dict = {}

        with open(groups_file, "r") as file:
            group_lines = file.readlines()
            for line in group_lines:
                vals = line.split(":")
                groups_dict[vals[2].strip()] = {
                    "gid": int(vals[2].strip()),
                    "gname": vals[0].strip(),
                    "users": [u.strip() for u in vals[3].split(
                        ",") if u != "" and u != "\n"]
                }
        with open(passwd_file, "r") as file:
            passwd_lines = file.readlines()
            for line in passwd_lines:
                vals = line.split(":")
                try:
                    users_dict[vals[0].strip()] = {
                        "uname": vals[0].strip(),
                        "uid": int(vals[2].strip()),
                        "groups": [groups_dict[vals[3]]["gname"]],
                        "home": vals[5].strip()
                    }
                except KeyError:
                    users_dict[vals[0].strip()] = {
                        "uname": vals[0].strip(),
                        "uid": int(vals[2].strip()),
                        "groups": [vals[3].strip()],
                        "home": vals[5].strip()
                    }
        for group in groups_dict:
            gname = groups_dict[group]["gname"]
            users_in_group = groups_dict[group]["users"]
            if len(users_in_group) > 0:
                for user in users_in_group:
                    user = user.strip()
                    users_dict[user]["groups"].append(gname)

        for user in users_dict:
            uid = users_dict[user]["uid"]
            if (uid > 999 and uid <= 10000) or uid == 0:
                primary_users_dict[user] = users_dict[user]

        self.all_users = users_dict
        self.primary_users = primary_users_dict
        self.groups = groups_dict

    def get_file_ownership(self):
        for root_target in self.get_ownership:
            for user in self.users_list:
                os.system(f"find {root_target} -user {user} >> "
                          f"{self.targets_file}")

    def read_input_files(self):
        # Write every target location stored in input_files to a
        # temporary list
        targets = []
        for file in self.input_files:
            with open(file) as nextfile:
                for line in nextfile:
                    if len(line.strip()) > 0:
                        targets.append(line.strip())

        # Write targets to a new file
        self.write_targets(targets)

    def write_targets(self, targets):
        # Prepare the output file in the output directory
        self.targets_file = os.path.join(self.output_dir, f"target_locations")
        if os.path.exists(self.targets_file):
            # If the file does exist, name it with the soonest number 1, 2,...
            for i in range(1, 256):
                i = str(i)
                if not os.path.exists(self.targets_file + i):
                    # Rename the output targets file as necessary
                    self.iter = i
                    self.targets_file = self.targets_file + self.iter
                    break

        self.verbose_write(f"Creating target file, {self.targets_file} ...")
        # Begin to write to the target file
        f = open(self.targets_file, "w")
        # value to determine if files are in a sought category
        header_found = False
        # For each user, for each target line
        # (directory, file, header, trailer)
        for user in self.users_dict:
            for target in targets:
                # If the line starts with "#", it is a header or a trailer
                if target[0] == "#":
                    # The current category is in the header/trailer
                    current_cat = target.split(' ')[-1].strip().upper()
                    # If "END" is not in the line, this is the header of a
                    # category
                    if target.split(" ")[1].upper() != "END":
                        # If the header is in the category list, a header is
                        # found
                        if current_cat in self.cats:
                            header_found = True
                    else:
                        # Otherwise, if it is a trailer, the header is no
                        # longer found
                        header_found = False
                elif target != "":
                    # If the line is not a header/trailer nor empty...
                    if header_found:
                        # Write the line with replacing   with a user
                        new_target = target.replace("$USERHOME",
                                                    self.users_dict[user][
                                                        "home"])
                        f.write(new_target + "\n")

        # Close the file after all writes and return the compiled target file
        self.get_file_ownership()
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
                    if self.verbose: raise DoesNotExistError(line)

                # If the line is in protected LEAF paths, raise LEAFinPath
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
                        try:
                            self.copy_item(line, part, New_LogFile)
                        except FileNotFoundError as e:
                            self.verbose_write(
                                f"Cannot find file or directory,"
                                f" {line}. Continuing...")
                            New_LogFile.new_errorlog(e, "copy_files_main")
            except DoesNotExistError as e:
                if self.verbose: print("Error:", e, "\nContinuing...")
                New_LogFile.new_errorlog(e, "copy_files_main")
            except LEAFInPath as e:
                if self.verbose: print("Error:", e, "\nContinuing...")
                New_LogFile.new_errorlog(e, "copy_files_main")

        print("\n\n")
        return New_LogFile

    def copy_item(self, src, part, logfile):
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

            files_list = []
            dirs_list = []
            for root, dirs, files in os.walk(src):
                for dirx in dirs:
                    dirs_list.append(os.path.join(root, dirx))
                for file in files:
                    files_list.append(os.path.join(root, file))

            for file in files_list:
                try:
                    self.copy_item(file, part, logfile)
                except KeyboardInterrupt:
                    print(
                        "Exit triggered (^Z, ^C). Saving current progress...")
                except FileNotFoundError as e:
                    print(f"Cannot find file or directory, {file}. "
                          f"Continuing...")
                    logfile.new_errorlog(e, "copy_item")
        elif os.path.isfile(src):
            # If the source is a file, copy it to the latest target location
            copy = f"mkdir --parents " \
                   f"'{self.evidence_dir}{'/'.join(src.split('/')[:-1])}'"

            os.system(copy)

            copy = f"cp -p '{src}' '{new_root}'"
            os.system(copy)
            check_int = self.check_integrity(src, new_root)
            # Test if the source file and destination file have the same hash
            try:
                # If False, raise NonMatchingHashes error
                if not check_int[0]:
                    raise NonMatchingHashes(src, new_root)
            except NonMatchingHashes as e:
                self.verbose_write("Error:", e)
                logfile.new_errorlog(e, "copy_item")
            except TypeError as e:
                self.verbose_write("Error:", e)
                logfile.new_errorlog(e, "copy_item")

            # Use debugfs to copy each file's inode data over
            self.debugfs(src, new_root, part)

            try:
                file_size = os.path.getsize(new_root)
            except:
                file_size = "NA"
            # Log the action
            logfile.new_log(src, new_root, check_int[1], check_int[2],
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

    def check_integrity(self, s_file, d_file):
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
            if os.path.islink(s_file) and file == s_file:
                hashes.append("NA")
                continue
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
        return match, hashes[0], hashes[1]

    def debugfs(self, src, tgt, part):
        """
        Transfer inode data from source item to destination item on single
        partition.
        :param src: (str)   source item being copied
        :param tgt: (str)   copied file
        :param part: (str)  partition name
        """

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
        os.system(f"tree -a '{self.evidence_dir}'")
        print(f"Writing data to '{self.img_path}'")
        os.system(
            f"mkisofs -max-iso9660-filenames -iso-level 4 -U -o '{self.img_path}' "
            f"'{self.evidence_dir}'")
        """for line in mkiso_log.split("\n"):
            logfile.new_errorlog(line)"""
        print("Done!")
        self.getHash()
        if not self.raw:
            shutil.rmtree(self.evidence_dir)

    def getHash(self):
        # Generating the hash for the file
        sha1 = hashlib.sha1()
        with open(self.img_path, 'rb') as f:
            buf = f.read()
            sha1.update(buf)
        self.iso_hash = sha1.hexdigest()

    def verbose_write(self, *prnt):
        out = ""
        if self.verbose:
            for item in prnt:
                out = f"{out} {item}"
            print(out)

    def __str__(self):
        out = ""
        """for _, var in vars(self).items():
            out += str(var)"""

        out = out + f"\nArguments:\n\t" \
                    f"Input File(s):\t\t{self.input_files}\n\t" \
                    f"Output Directory:\t{self.output_dir}\n\t" \
                    f"Evidence Directory:\t{self.evidence_dir}\n\t" \
                    f"Compiled Targets File:\t{self.targets_file}\n\t" \
                    f"Image Name:\t\t{self.img_path}\n\t" \
                    f"Save raw?\t\t{self.raw}\n\t" \
                    f"User(s):\t\t{self.users_list}\n\t" \
                    f"Categories:\t\t{self.cats}\n\t" \
                    f"Yara Scanning Enabled:\t{self.yara_scan_bool}"
        if self.verbose:
            out = out + f"\n\t" \
                        f"Yara Files:\t\t{self.yara_files}\n\t" \
                        f"Verbose:\t\t{self.verbose}\n\t" \
                        f"Get files by ownership: {len(self.get_ownership) > 0}\n\t" \
                        f"'Ownership' Location(s): {self.get_ownership}\n\t" \
                        f"Protected Locations:\t{self.leaf_paths}\n\t" \
                        f"ISO Hash:\t\t{self.iso_hash}"

        return out


def list_to_str(value, pre=""):
    out = ""
    for item in value:
        out = f"{out}\n{pre}{item}"
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
    print(LEAFObj)

    # Initialize a Log File object
    LogFile = Log(save_loc=LEAFObj.output_dir)

    ### Start Clone/Copy Operations

    # Runs copy_files() to read the targeted locations file and copy
    # appropriate locations to the evidence directory
    LEAFObj.copy_files_main(LogFile)

    # Runs get_image() to create the image file for the evidence and hash
    # the image
    LEAFObj.get_image()

    # Create a command-run log
    LogFile.new_commandlog(LEAFObj)

    # Write the logging to file
    print("Saving acquisition log...")
    LogFile.write_to_file()
    print("Saving error log...")
    LogFile.write_to_file(log_type="Err")

    # Trailer
    print()
    print(f"Acquisition completed.\n\tFilename: {LEAFObj.img_path} "
          f"\n\tSHA1 Hash: {LEAFObj.iso_hash}")
    print()

    end_time = datetime.now()
    e = end_time - start_time
    # Create time elapsed
    print(f"Processing Time: {e}")


if __name__ == "__main__":
    main()

