from plugins.create_environment import main as create_env
from plugins.copy_files import main as copy_files
import os


if (os.getuid() != 0):
    print("Error: Root access not detected. Exiting...")
    exit()

params_key = ["targets_file", "output_directory", "IMG_name", "raw",
              "script_path", "user_list", "evidence_directory"]
params_val = create_env()
parameters = dict(zip(params_key, params_val))

for param in parameters:
    print(param, ":", parameters[param])

print()
copy_files(parameters["targets_file"], parameters["evidence_directory"])
