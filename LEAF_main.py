#!/usr/bin/python3

from plugins.create_environment import main as create_env
from plugins.copy_files import main as copy_files
from plugins.get_image import main as get_image
from plugins.errorhandling import *
import os
import datetime


if __name__ == "__main__":
    """
    Main handler for LEAF framework. LEAF_main.py is the file that will be 
    executed and it will handle the rest of the calling of other files and 
    dependencies accordingly
    """

    # Ensure that the program is run in root
    try:
        if os.getuid() != 0:
            raise RootNotDetected
    except RootNotDetected as e:
        print("Error:", e)
        exit()

    # Get the start time of execution
    start_time = datetime.datetime.now()

    # List of the parameter key names
    params_key = ["targets_file", "categories", "output_directory",
                  "img_path", "raw", "script_path", "user_list",
                  "evidence_directory", "verbose"]
    # Gets the values for each parameter from create_env()
    params_val = create_env()
    # Merge the keys and values into a single dictionary
    parameters = dict(zip(params_key, params_val))

    # Gets the absolute path of LEAF_main.py code
    abs_path = str("/".join(os.path.abspath(__file__).split("/")[:-1]))
    leaf_paths = (parameters["script_path"],
               parameters["output_directory"], abs_path + "/")
    print()
    # Runs copy_files() to read the targeted locations file and copy
    # appropriate locations to the evidence directory
    copy_files(parameters["targets_file"], parameters["evidence_directory"],
               parameters["verbose"], leaf_paths)
    # Runs get_image() to create the image file for the evidence and hash
    # the image
    iso_hash = get_image(parameters["evidence_directory"], parameters[
        "output_directory"], parameters["img_path"], parameters["raw"])

    # Trailer
    print()
    print(f"Acquisition completed.\n\tFilename: {parameters['img_path']} "
          f"\n\tSHA1 Hash: {iso_hash}")
    print()

    end_time = datetime.datetime.now()
    e = end_time - start_time
    # Create time elapsed
    print(f"Processing Time: {e}")
