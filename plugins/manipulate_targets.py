import os
from plugins.errorhandling import *
import subprocess


def readInputFile(in_file, cats, output_dir, script_path, users):
    """
    Reads the input file(s) and compile all the data to a single file to
    interpret target locations.
    :param in_file: (str)   input file(s) to read from for target locations
    :param cats:    (str)   categories to parse
    :param output_dir: (str)    directory to output evidence to
    :param script_path: (str)   path to LEAF scripts
    :param users: (list)    list of users whose user directories are
                            targeted
    :return: targets (list ) list of target locations to parse
             input_files_paths (
    """
    with open(output_dir + "temp_file", "w+") as f:
        data = f.read()
    # If the inputted file location does not specify the default target
    # file, parse through each inputted file and add its full path to a single
    # list/file
    if in_file != str(script_path + "target_locations"):
        # Create a list out of the inputted target(s)
        input_files = in_file.split(",")
        input_files_paths = []
        # For each file including targets...
        for file in input_files:
            try:
                # If the file exists...
                if os.path.exists(file):
                    # ... and it is referenced relatively...
                    if file[0] != "/":
                        # Append the absolute path of that file to paths list
                        input_files_paths.append(f"{os.getcwd()}/{file}")
                    else:
                        # Otherwise, add the included file path to the paths
                        # list
                        input_files_paths.append(file)
                else:
                    # If the file does not exist, continue
                    raise DoesNotExistError(file)
            except DoesNotExistError as e:
                print("Error: ", e)
        # Write every target location stored in input_files_paths to a
        # temporary file
        for file in input_files_paths:
                with open(file) as nextfile:
                    data = data + nextfile.read()
        with open(str(output_dir + "temp_file"), "w") as f:
            f.write(data)
        in_file = str(output_dir + "temp_file")
    else:
        # If only one file is listed, export the single file
        input_files_paths = [in_file]
        in_file = str(script_path + "target_locations")
    if len(input_files_paths) == 0:
        # If all the items got removed from the input list due to not
        # existing, use default file
        input_files_paths = [str(script_path + "target_locations")]
        in_file = str(script_path + "target_locations")
    # Save list of all targeted items from the temp file
    f = open(in_file, "r")
    targets = []
    for line in f:
        targets.append(line)
    # Parse the list of files based on category to the target_locations list
    # in the output directory; remove the temp directory
    targets_file  = writeTargets(output_dir, cats, targets, users)
    os.remove(str(output_dir + "temp_file"))
    return input_files_paths, targets_file


def writeTargets(output_dir, cats, targets, users,):
    """
    Compile data from all the valid inputted files and parse them for the
    desired categories; then, write target locations to a single file.
    :param output_dir: (str)    output directory to save targets file
    :param cats: (str)      categories sought to extract
    :param targets: (list)  list of lines to parse
    :param users: (list)    users whose directories should be parsed
    :return: new_targetfile (str)  the new targets file with processed inputs
    """
    # Prepare the output file in the output directory
    new_targetfile = str(output_dir + "target_locations")

    if os.path.exists(new_targetfile):
        # If the file does exist, name it with the soonest number 1, 2,...
        for i in range(1, 256):
            i = str(i)
            if not os.path.exists(new_targetfile + i):
                # Rename the output targets file as necessary
                new_targetfile = (new_targetfile + i)
                break

    print("Creating target file,", new_targetfile + "...")
    # Begin to write to the target file
    f = open(new_targetfile, "w")
    # value to determine if files are in a sought category
    header_found = False
    # For each user, for each target line (directory, file, header, trailer)
    for user in users:
        for target in targets:
            # If the line starts with "#", it is a header or a trailer
            if target[0] == "#":
                # The current category is the last word in the header/trailer
                current_cat = target.split(' ')[-1][:-1]
                # If "END" is not in the line, this is the header of a category
                if target.split(" ")[1] != "END":
                    # If the header is in the category list, a header is found
                    if current_cat in cats:
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
    return new_targetfile
