#!/usr/bin/python3

from plugins.create_environment import main as create_env
from plugins.copy_files import main as copy_files
from plugins.get_image import main as get_image
import os


if __name__ == "__main__":
    if os.getuid() != 0:
        print("Error: Root access not detected. Exiting...")
        exit()

    params_key = ["targets_file", "output_directory", "img_path", "raw",
                  "script_path", "user_list", "evidence_directory"]
    params_val = create_env()
    parameters = dict(zip(params_key, params_val))


    #for param in parameters:
    #    print(param, ":", parameters[param])
    abs_path = str("/".join(os.path.abspath(__file__).split("/")[:-1]))
    print()
    copy_files(parameters["targets_file"], parameters["evidence_directory"],
               (parameters["script_path"], parameters["output_directory"],
                abs_path + "/"))

    get_image(parameters["evidence_directory"], parameters[
        "output_directory"], parameters["img_path"])
