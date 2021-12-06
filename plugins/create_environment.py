import argparse
import os
from datetime import datetime
from plugins.errorhandling import *
from plugins.manipulate_targets import readInputFile
from argparse import RawTextHelpFormatter

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

def createOutputDir(output_dir):
    """
    Format the output location as a directory and creates it if necessary
    :param output_dir: (str) directory that the output will be saved to
    :return: updated directory output location
    """
    print("\nCreating" , output_dir + "....")
    # If that directory does not exist, create it
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, mode=775)
    else:
        print("Path already exists. Continuing...")
        print()
    return output_dir

def createEvdc(output_dir):
    """
    Create the outputted image file based on user input
    Note: during preliminary testing, the input will be a created directory.
    Once the tool is further developed, the input locations will be pulled
    from a list-like structure.
    :param output_dir: (str) Target location to save evidence to
    :param output_type: (str) Type/extension of output
    :return:
    """
    # Gets the time of execution to assign to the image name
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_filename = str(output_dir + "LEAF_acquisition_" +
                          str(current_time) + ".ISO")

    evidence_dir = str(output_dir + "evidence")

    # If the evidence directory does not exist, create it
    if not os.path.exists(evidence_dir):
        os.makedirs(evidence_dir, mode=775)
        i = ""
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


def main():
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
        '/_________/ /_________/ /___/   /___/  /___/          v1.2\n\n'+
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
               "To use default arguments (this will use "
               "default input file (./target_locations), users ("
               "all users), categories (all categories), "
               "and output location (./LEAF_output/):" +
               bcolors.Green + "\n\tLEAF_main.py\n\n" + bcolors.ENDC +
               "All arguments:\n\t" + bcolors.Green +
               "LEAF_main.py -i /home/alice/Desktop/customfile1.txt -o "
               "/home/alice/Desktop/ExampleOutput/ -c logs,startup,"
               "services -u alice,bob,charlie -s\n" + bcolors.ENDC +
               "To specify usernames and categories:\n\t" +
               bcolors.Green +
               "LEAF_main.py -u alice,bob,charlie -c applications,"
               "executions,users" + bcolors.ENDC +
               "\n\nTo include custom input file(s):\n\t" + bcolors.Green +
               "LEAF_main.py -i /home/alice/Desktop/customfile1.txt,"
               "/home/alice/Desktop/customfile2.txt\n" + bcolors.ENDC,
        formatter_class=RawTextHelpFormatter)

    # Gets the real path of the script. If the script is run from a symlink,
    # this will output the source of the symlink
    script_path = "/".join(os.path.realpath(__file__).split('/')[:-2]) + "/"

    # Add arguments to parser
    parser.add_argument('-i', "--input", nargs=1, type=str,
            default=str(script_path + "target_locations"),
            help=str("Additional Input locations. Separate " +
                "multiple input files with \",\"\n" +
                "Default: " + script_path + "target_locations"))

    parser.add_argument('-o', "--output", type=str,
            default=str(os.getcwd() + "/LEAF_output/"),
            help='Output directory location\nDefault: '
                    './LEAF_output')
    # Deprecated
    """parser.add_argument('-t', "--type", default="ISO", nargs=1,
                        help='Output file type. '
                             'Options: '
                             'IMG, DD, ISO, VHD')"""

    parser.add_argument('-u', "--users", nargs=1, type=str,
            default=os.listdir("/home"), help='Users to include '
                    'in output, separated by \",\" (i.e. alice,'
                    'bob,charlie). \nMUST be in /home/ '
                    'directory\nDefault: All users')

    parser.add_argument('-c', "--categories", nargs=1, type=str,
                        default="all",
                        help='Explicit artifact categories to include  '
                                 'during acquisition. \nCategories must be '
                                 'separated by comma, \",\" (i.e. network,'
                                 'users,application). \nFull List of '
                                 'categories includes: \n\t' + str(all_cats) +
                            ' or "all"\n Categories are '
                                 'compatible with user-inputted files as '
                                 'long as they follow the notation: \n\t# '
                                 'CATEGORY\n\t/location1\n\t/location2\n\t'
                                 '.../location[n]\n\t# END CATEGORY\nDefault: '
                                 '"all"')
    parser.add_argument('-v', "--verbose", help='Output in verbose '
                        'mode, (may conflict with '
                        'progress bar)\nDefault: False',
                        action='store_true')

    parser.add_argument('-s', "--save", help='Save the raw evidence '
                                             'directory\nDefault: False',
                        action='store_true')
    # Compile the arguments
    args = parser.parse_args()

    # Stores the arguments into static variables
    input_file = args.input
    output_dir = args.output
    sve = args.save
    verbose = args.verbose

    # Deprecated
    # img_type = args.type

    # Formats the "output_dir" variable to have a trailing "/"
    # If the output directory is not listed from root, create the full path
    if output_dir[0] != "/":
        output_dir = os.getcwd() + "/" + output_dir
    if output_dir[-1] != "/":
        output_dir = output_dir + "/"
    out_dir = createOutputDir(output_dir)

    # Parses the inputted users into a list
    if args.users != os.listdir("/home/"):
        user_list = args.users[0].split(",")
    else:
        user_list = args.users

    # Checks each user and remove users that do not exist
    for user in user_list:
        if user not in os.listdir("/home/"):
            print(f"Non-existent user, {user}. Removing...")
            user_list.remove(user)

    # If they did not enter "all" or use the default categories,
    # split categories into a list and remove non-existent categories
    if "ALL" not in str(args.categories).upper():
        cats = args.categories[0].upper().split(",")
        nonexist = list(set(cats) - set(all_cats))
        for item in nonexist:
            print(f"{item} is not a valid category. Removing...")
            cats.remove(item)
    else:
        # Default value is ["all"]
        cats = all_cats

    # If all the categories included were invalid
    # and removed, use the default categories
    try:
        if len(cats) == 0:
            raise CategoriesEmpty
    except CategoriesEmpty as e:
        print("Error:", e)
        cats = ["all"]

    # Parses the inputted file(s) string to merge multiple files if
    # neccesary. Returns the lines that exist on the file system and are
    # listed under an intended category
    input_files, targets_file = readInputFile(input_file, cats,
                                            out_dir, script_path, user_list)

    # Creates forensic data output environment, and gets the Evidence
    # Directory and the Image Name from the created evidence location
    evdc_dir, img_name = createEvdc(output_dir)

    print("Arguments: ")
    print("\tInput File(s):\t\t", input_files)
    print("\tCompiled Targets File:\t", targets_file)
    print("\tOutput Directory:\t", out_dir)
    print("\tImage Name:\t\t", img_name)
    print("\tSave raw?\t\t", sve)
    print("\tScript Path:\t\t", script_path)
    print("\tUser(s):\t\t", user_list)
    print("\tCategories:\t\t", cats)
    print()

    # Returns generated data to main function
    return (targets_file, cats, out_dir, img_name, sve, script_path, user_list,
            evdc_dir, verbose)
