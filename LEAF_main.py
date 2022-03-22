#!/usr/bin/python3

from plugins.create_environment import main as create_env
from plugins.copy_files import main as copy_files
from plugins.get_image import main as get_image
from plugins.yara_scan import main as scan_yara
from plugins.errorhandling import *
import os
import datetime
from plugins.logging import Log


class LEAFInfo():
    def __init__(self, t_file="", cats="", out="", img="", raw="",
                 script="", users="", evdc="", v="", yara="",
                 yara_f="", leaf=""):
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
        for _, var in vars(self).items():
            out += str(var)
        return out


def main():
    """
    Main handler for LEAF framework. LEAF_main.py is the file that will be
    executed and it will handle the rest of the calling of other files and
    dependencies accordingly
    """
    # Get the start time of execution
    start_time = datetime.datetime.now()

    # Gets the absolute path of LEAF_main.py code
    abs_path = str("/".join(os.path.abspath(__file__).split("/")[:-1]))

    # Gets the the argparse values
    ###parameters = create_env(abs_path)
    LEAFObj = create_env(abs_path)

    """leaf_paths = (parameters["script_path"],
               parameters["output_directory"], abs_path + "/")

    LEAFObj = LEAFInfo(t_file=parameters["targets_file"],
                       cats=parameters["categories"],
                       out=parameters["output_directory"],
                       img=parameters["img_path"],
                       raw=parameters["raw"],
                       script=parameters["script_path"],
                       users=parameters["user_list"],
                       evdc=parameters["evidence_directory"],
                       v=parameters["verbose"],
                       yara=parameters["yara"],
                       yara_f=parameters["yara_files"],
                       leaf=leaf_paths)"""
    print(LEAFObj)
    exit()

    # Initialize a Log File object
    LogFile = Log(save_loc=LEAFObj.script_path)

    # Ensure that the program is run in root
    try:
        if os.getuid() != 0:
            raise RootNotDetected
    except RootNotDetected as e:
        print("Error:", e)
        exit()

    # Create a command-run log
    LogFile.new_commandlog(LEAFObj)

    # Runs copy_files() to read the targeted locations file and copy
    # appropriate locations to the evidence directory
    ###copy_files(parameters["targets_file"], parameters[
    ###    "evidence_directory"], parameters["verbose"], leaf_paths, LogFile)
    copy_files(LEAFObj, LogFile)

    # Runs get_image() to create the image file for the evidence and hash
    # the image
    """iso_hash = get_image(parameters["evidence_directory"], parameters[
        "output_directory"], parameters["img_path"], parameters["raw"])"""
    iso_hash = get_image(LEAFObj)

    LogFile.write_to_file()

    #if parameters["yara"]:
     #   scan_yara(str(parameters["script_path"] + "yara_rules/"))
    # Trailer
    print()
    print(f"Acquisition completed.\n\tFilename: {LEAFObj.img_path} "
          f"\n\tSHA1 Hash: {iso_hash}")
    print()

    end_time = datetime.datetime.now()
    e = end_time - start_time
    # Create time elapsed
    print(f"Processing Time: {e}")


if __name__ == "__main__":
    main()

