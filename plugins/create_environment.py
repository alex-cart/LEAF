import argparse
import os
from datetime import datetime



# Get input location -- temporary (later changed to inputs from a list)
# Get output location
# Get output image type


def createOutputDir(output_dir):
    """
    Format the output location as a directory and creates it if necessary
    :param output_dir: (str) directory that the output will be saved to
    :return: updated directory output location
    """
    print("\nCreating" , output_dir + "....")
    # If that directory does not exist, create it
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    else:
        print("Path already exists. Continuing...")
        print()
    return output_dir

def createEvdc(output_dir): #, output_type):
    """
    Create the outputted image file based on user input
    Note: during preliminary testing, the input will be a created directory.
    Once the tool is further developed, the input locations will be pulled
    from a list-like structure.
    :param output_dir: (str) Target location to save evidence to
    :param output_type: (str) Type/extension of output
    :return:
    """
    current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_filename = str(output_dir + str(current_time) + ".ISO")
    # This will be modified during intermediary testing -- currently,
    # it will create an empty image file, however it will need a set size
    # once evidence is added to the mountpoint
    # print("Output Image Filename " + output_filename + " ...")

    evidence_dir = str(output_dir + "evidence")
    if not os.path.exists(evidence_dir):
        os.makedirs(evidence_dir)
        i = ""
    else:
        #print(evidence_dir + " already exists.")
        for i in range(1, 256):
            i = str(i)
            if not os.path.exists(evidence_dir + i):
                os.makedirs(evidence_dir + i)
                break
    evidence_dir = evidence_dir + i + "/"
    print("Creating evidence directory:", evidence_dir + "...")
    print()
    return evidence_dir, output_filename


        
def readInputFile(in_file, output_dir, script_path, users):
    with open(output_dir + "temp_file", "w+") as ftemp:
        data = ftemp.read()
    if in_file != str(script_path + "/target_locations"):
        input_files = in_file.split(",")

        for file in input_files:
            with open(file) as nextfile:
                data = data + nextfile.read()

        with open(str(output_dir + "temp_file"), "w") as f:
            f.write(data)

        in_file = str(output_dir + "temp_file")
    else:
        input_files = in_file

    f = open(in_file, "r")
    targets = []
    for line in f:
        targets.append(line)

    targets = writeTargets(output_dir, targets, users)
    os.remove(str(output_dir + "temp_file"))
    return targets, input_files


def writeTargets(output_dir, targets, users):
    temp_outfile = str(output_dir + "target_locations")
    if not os.path.exists(temp_outfile):
        i = ""
    else:
        for i in range(1, 256):
            i = str(i)
            if not os.path.exists(temp_outfile + i):
                break
    new_targetfile = (temp_outfile + i)
    print("Creating target file,", new_targetfile + "...")
    f = open(new_targetfile, "w")
    new_targets = []
    for user in users:
        for target in targets:
            if target[0] != "#" and target != "":
                if "$USER" in target:
                    new_targets.append(target.replace("$USER", user))
                    f.write(target.replace("$USER", user))
                elif target not in new_targets:
                    new_targets.append(target)
                    f.write(target)
    f.close()
    return new_targets, new_targetfile


def main():
    """
    Main handler for interpreting user input information creating the forensic
    environment for output items.
    :return: user parameters
    """
    # Creates argparse parser
    parser = argparse.ArgumentParser(
        description='Get input and output locations.')

    # Gets the real path of the script. If the script is run from a symlink,
    # this will output the source of the symlink
    script_path = "/".join(os.path.realpath(__file__).split('/')[:-2]) + "/"

    # Add arguments to parser
    parser.add_argument('-i', "--input", nargs='?', const=1, type=str,
                        default=str(script_path + "/target_locations"),
                        help=str("Additional Input locations. Separate " +
                                    "multiple input files with \",\". " +
                                    "Default: " + script_path +
                                   "target_locations."))

    parser.add_argument('-o', "--output", type=str,
                        default=str(os.getcwd() + "/LEAF_output/"),
                        help='Output directory location')
    # Deprecated
    """parser.add_argument('-t', "--type", default="ISO", nargs=1,
                        help='Output file type. '
                             'Options: '
                             'IMG, DD, ISO, VHD')"""

    parser.add_argument('-u', "--users", nargs=1, type=str,
                        default=os.listdir("/home"), help='Users to include '
                                'in output, separated by \",\" (i.e. alice,'
                                'bob,charlie). MUST be in /home/ directory')

    parser.add_argument('-s', "--save", help='Save the raw evidence directory',
                        action='store_true')
    # Compile the arguments
    args = parser.parse_args()

    # Stores the arguments into static variables
    input_file = args.input
    output_dir = args.output
    sve = args.save
    # Deprecated
    # img_type = args.type

    # Formats the "output_dir" variable to have a trailing "/"
    # If the output directory is not listed from root, create the full path
    if output_dir[0] != "/":
        output_dir = os.getcwd() + "/" + output_dir
    if output_dir[-1] != "/":
        output_dir = output_dir + "/"
    out_dir = createOutputDir(output_dir)

    if args.users != os.listdir("/home/"):
        user_list = args.users[0].split(",")
    else:
        user_list = args.users

    for user in user_list:
        if user not in os.listdir("/home/"):
            print(f"Unknown user, {user}. Removing...")
            user_list.remove(user)



    targets_params, input_files = readInputFile(input_file, out_dir,
                                          script_path, user_list)
    targets, targets_file = targets_params

    evdc_dir, img_name = createEvdc(output_dir) # , img_type)


    print("Arguments: ")
    print("\tInput File(s):\t\t" , input_files)
    print("\tOutput Directory:\t" , out_dir)
    print("\tImage Name:\t\t" , img_name)
    print("\tSave raw?\t\t" , sve)
    print("\tScript Path:\t\t",script_path)
    print("\tUser(s):\t\t",user_list)
    print()

    return (targets_file, out_dir, img_name, sve, script_path, user_list,
            evdc_dir)
