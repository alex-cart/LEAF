#!/usr/bin/python3

from plugins.create_environment import main as create_env
from plugins.copy_files import main as copy_files
from plugins.get_image import main as get_image
from plugins.yara_scan import main as scan_yara
from plugins.errorhandling import *
import os
import datetime
from plugins.logging import Log

def main():
    """
    Main handler for LEAF framework. LEAF_main.py is the file that will be
    executed and it will handle the rest of the calling of other files and
    dependencies accordingly
    """
    # Get the start time of execution
    start_time = datetime.datetime.now()

    # Gets the the argparse values
    parameters = create_env()

    # Gets the absolute path of LEAF_main.py code
    abs_path = str("/".join(os.path.abspath(__file__).split("/")[:-1]))
    leaf_paths = (parameters["script_path"],
               parameters["output_directory"], abs_path + "/")

    print()
    # Initialize a Log File object
    LogFile = Log(save_loc=leaf_paths[1])

    # Ensure that the program is run in root
    try:
        if os.getuid() != 0:
            raise RootNotDetected
    except RootNotDetected as e:
        print("Error:", e)
        exit()

    # Create a command-run log
    LogFile.new_commandlog(parameters)
    """if parameters["yara"] != None:
        scan_yara(parameters["yara"], parameters["verbose"])"""

    # Runs copy_files() to read the targeted locations file and copy
    # appropriate locations to the evidence directory
    copy_files(parameters["targets_file"], parameters[
        "evidence_directory"], parameters["verbose"], leaf_paths, LogFile)

    # Runs get_image() to create the image file for the evidence and hash
    # the image
    iso_hash = get_image(parameters["evidence_directory"], parameters[
        "output_directory"], parameters["img_path"], parameters["raw"])

    LogFile.write_to_file()

    #if parameters["yara"]:
     #   scan_yara(str(parameters["script_path"] + "yara_rules/"))
    # Trailer
    print()
    print(f"Acquisition completed.\n\tFilename: {parameters['img_path']} "
          f"\n\tSHA1 Hash: {iso_hash}")
    print()

    end_time = datetime.datetime.now()
    e = end_time - start_time
    # Create time elapsed
    print(f"Processing Time: {e}")


if __name__ == "__main__":
    main()
