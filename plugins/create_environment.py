import argparse
import os
from datetime import datetime
from plugins.errorhandling import *
from plugins.manipulate_targets import readInputFile
from argparse import RawTextHelpFormatter
from plugins.yara_scan import main as scan_yara


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


class LEAFInfo():
    def __init__(self, t_file="", cats="", out="", img="", raw="",
                 script="", users="", evdc="", v="", yara="",
                 yara_f=[], leaf=""):
        self.targets_file = t_file
        self.cats = cats
        self.output_dir = out
        self.img_path = img
        self.raw = raw
        self.script_path = script
        self.users_list = users
        self.evidence_dir = evdc
        self.verbose = v
        self.yara_all = yara
        self.yara_files = yara_f
        self.leaf_paths = leaf
        self.all_args = [self.targets_file, self.cats, self.output_dir,
                         self.img_path, self.raw, self.script_path,
                         self.users_list, self.evidence_dir, self.verbose,
                         self.yara_all, self.yara_files,
                         self.leaf_paths]

    def __str__(self):
        out = ""
        for i in self.all_args:
            out = out + str(i) + "\n"
        return out


def createOutputDir(output_dir):
    """
    Format the output location as a directory and creates it if necessary
    :param output_dir: (str) directory that the output will be saved to
    :return: updated directory output location
    """
    print("\nCreating", output_dir + "....")
    # If that directory does not exist, create it
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, mode=775)
    else:
        print("Path already exists. Continuing...")
        print()
    return output_dir


def createEvdc(output_dir):
    """
    Prepare the output files and environment based on user input
    :param output_dir: (str) Target location to save evidence to
    :return:
    """
    # Gets the time of execution to assign to the image name
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_filename = os.path.join(output_dir, str("LEAF_acquisition_" +
                          str(current_time) + ".ISO"))

    evidence_dir = os.path.join(output_dir, "evidence")
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
    evidence_dir = evidence_dir + i + "/"
    print("Creating evidence directory:", evidence_dir + "...")
    print()
    return evidence_dir, output_filename


# noinspection PyTypeChecker
def main(abs_path):
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
    # Define all categories
    all_cats = ["APPLICATIONS", "EXECUTIONS", "LOGS", "MISC", "NETWORK",
                "STARTUP", "SERVICES", "SYSTEM", "TRASH", "USERS"]
    LEAFObj = LEAFInfo()

    # Gets the real path of the script. If the script is run from a symlink,
    # this will output the source of the symlink
    script_path = "/".join(os.path.realpath(__file__).split('/')[:-2]) + "/"

    # Creates argparse parser
    parser = argparse.ArgumentParser(
        description=(bcolors.Green + 'LEAF (Linux Evidence Artifact '
        'Framework) - '
        'Cartware\n'
        '     ____        _________    ___________   __________  \n' 
        '    /   /       /   _____/   /  ____    /  /   ______/  \n'
        '   /   /       /   /____    /  /___/   /  /   /____    \n'
        '  /   /       /   _____/  /   ____    /  /   _____/  \n'
        ' /   /_____  /   /_____  /   /   /   /  /   /        \n'
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
                        default=[str(script_path + "target_locations")],
                        help=str("Additional Input locations. Separate "
                                 "multiple input files with \",\"\nDefault: "
                                 "" + script_path + "target_locations"))

    parser.add_argument('-o', "--output", type=str,
                        default=str(os.getcwd() + "/LEAF_output/"),
                        help='Output directory location\nDefault: '
                        './LEAF_output')
    # Deprecated
    """parser.add_argument('-t', "--type", default="ISO", nargs=1,
                        help='Output file type. '
                             'Options: '
                             'IMG, DD, ISO, VHD')"""
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
                        default=all_cats,
                        help='Explicit artifact categories to include  '
                        'during acquisition. \nCategories must be separated '
                        'by space, (i.e. -c network users apache). '
                        '\nFull List of built-in categories includes: \n\t' +
                        str(all_cats) + '\nCategories are compatible with '
                        'user-inputted files as long as they follow the '
                        'notation: \n\t# CATEGORY\n\t/location1\n\t/location2 '
                        '\n\t.../location[n]\n\t# END CATEGORY\nDefault: '
                                        '"all"')

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

    # Deprecated
    # img_type = args.type

    # Stores the arguments into static variables
    # input_file : list of input files (files that have targets)
    input_file = args.input
    # output_dir : string of output location (single value)
    output_dir = args.output
    # save : boolean whether to save directory of copied files
    save = args.save
    LEAFObj.raw = args.save
    # verbose : boolean whether to use verbose output
    verb = args.verbose
    LEAFObj.verbose = args.verbose
    # yara : whether or not to use yara scanning; optional list
    # No "-y" --> "do_not_include"
    # -y with no arguments --> [] --> use default rules
    # -y a b c --> ["a", "b", "c"] --> use specific rules
    yara = args.yara
    # Same as -y flag but with recursive-available locations
    yara_rec = args.yara_recursive
    yara_inputs = {"non-recurse": [], "recurse": []}

    # Yara data [] means the flag was specified, but no paths
    # were inputted. "do_not_include" means that flag was not specified
    for input_save in [[yara, yara_inputs["non-recurse"]],
                       [yara_rec, yara_inputs["recurse"]]]:
        # If yara was specified (empty list)
        if len(input_save[0]) == 0:
            input_save[1].append(str(script_path)+"/yara_rules/")
        elif "do_not_include" not in input_save[0]:
            input_save[1].extend(input_save[0])
    # If non-recursive parsing and recursive parsing are the same targets,
    # use the recursive method only
    yara_inputs["non-recurse"] = [item for item in yara_inputs[
            "non-recurse"] if item not in yara_inputs["recurse"]]

    # Scanning is enabled if either recursive or non-recursive is populated
    yara_scan = (yara_inputs["non-recurse"] != [] or
                 yara_inputs["recurse"] != [])
    if yara_scan:
        yara_files = scan_yara(yara_inputs, verb)
    else:
        yara_files = []

    # Formats the "output_dir" variable to have a trailing "/"
    # If the output directory is not listed from root, create the full path
    if output_dir[0] != "/":
        output_dir = os.path.join(os.getcwd(), output_dir)
    if output_dir[-1] != "/":
        output_dir = output_dir + "/"

    ###out_dir = createOutputDir(output_dir)
    out_dir = "test_out_dir"
    # Parses the inputted users into a list
    """if args.users != os.listdir("/home/"):
        user_list = args.users[0].split(",")
    else:
        user_list = args.users
    # Checks each user and remove users that do not exist
    for user in user_list:
        if user not in os.listdir("/home/"):
            print(f"Non-existent user, {user}. Removing...")
            user_list.remove(user)
    """
    user_list = ["test_user_list"]
    LEAFObj.users_list = user_list

    # If all the users included were invalid
    # and removed, use the default users
    try:
        if len(user_list) == 0:
            raise ArgumentEmpty("users")
    except ArgumentEmpty as e:
        print("Error:", e)
        user_list = os.listdir("/home")

    cats = []
    user_cats = [x.upper() for x in args.categories]
    # If they did not enter "all" or use the default categories,
    # split categories into a list and remove non-existent categories
    if "ALL" in [x.upper() for x in user_cats]:
        cats.extend(all_cats)
        # Deprecated - removes non-existent categories
        additional = list(set(user_cats) - set(all_cats))
        for item in additional:
            cats.append(item)
        cats.remove("ALL")
    else:
        # Default value is ["all"]
        cats = list(set(user_cats))
    # If all the categories included were invalid
    # and removed, use the default categories
    try:
        if len(cats) == 0:
            raise ArgumentEmpty("categories")
    except ArgumentEmpty as e:
        print("Error:", e)
        cats = all_cats
    LEAFObj.cats = cats

    # Parses the inputted file(s) string to merge multiple files if
    # necessary. Returns the lines that exist on the file system and are
    # listed under an intended category
    ###input_files, targets_file = readInputFile(input_file, cats,
    ###                                          out_dir, script_path,
    # user_list)
    input_files = ["test_input_files"]
    targets_file = "test_targets_file"
    # Creates forensic data output environment, and gets the Evidence
    # Directory and the Image Name from the created evidence location
    ###evdc_dir, img_name = createEvdc(output_dir)
    evdc_dir = "test_evdc_dir"
    img_name = "test_img_name"

    print("Arguments: ")
    print("\tInput File(s):\t\t", input_files)
    print("\tCompiled Targets File:\t", targets_file)
    print("\tOutput Directory:\t", out_dir)
    print("\tImage Name:\t\t", img_name)
    print("\tSave raw?\t\t", save)
    print("\tScript Path:\t\t", script_path)
    print("\tUser(s):\t\t", user_list)
    print("\tCategories:\t\t", cats)
    print("\tYara Scanning Enabled:\t", yara_scan)
    print()

    # Generate a LEAF Info Object
    """LEAFObj = LEAFInfo(t_file=targets_file,
                       cats=cats, #  
                       out=out_dir,
                       img=img_name,
                       raw=save, #
                       script=script_path,
                       users=user_list, #
                       evdc=evdc_dir,
                       v=verbose, #
                       yara=yara,
                       yara_f=yara_files,
                       leaf=(script_path, out_dir, abs_path + "/"))"""

    return LEAFObj

    # Returns generated data to main function
    """return {
        "targets_file": targets_file,
        "categories": cats,
        "output_directory": out_dir,
        "img_path": img_name,
        "raw": save,
        "script_path": script_path,
        "user_list": user_list,
        "evidence_directory": evdc_dir,
        "verbose": verb,
        "yara": yara_inputs,
        "yara_files": yara_files
    }"""