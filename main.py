#!/usr/bin/python3

from plugins.create_environment import main as create_env
from plugins.copy_files import main as copy_files
from plugins.get_image import main as get_image
import os
import datetime

"""
Coming Soon.... all the files are admin-protected. Do I want this?

YARA scanning to find IOCS?
"""

if __name__ == "__main__":

    if os.getuid() != 0:
        print("Error: Root access not detected. Exiting...")
        exit()
    start_time = datetime.datetime.now()

    params_key = ["targets_file", "categories", "output_directory",
                  "img_path", "raw", "script_path", "user_list",
                  "evidence_directory"]
    params_val = create_env()
    parameters = dict(zip(params_key, params_val))

    abs_path = str("/".join(os.path.abspath(__file__).split("/")[:-1]))
    print()
    copy_files(parameters["targets_file"], parameters["evidence_directory"],
               (parameters["script_path"], parameters["output_directory"],
                abs_path + "/"))

    iso_hash = get_image(parameters["evidence_directory"], parameters[
        "output_directory"], parameters["img_path"], parameters["raw"])

    print()
    print(f"Acquisition completed.\n\tFilename: {parameters['img_path']} "
          f"\n\tSHA1 Hash: {iso_hash}")
    print()

    end_time = datetime.datetime.now()
    e = end_time - start_time
    print(f"Processing Time: {e}")


