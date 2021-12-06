import os
import subprocess
import hashlib
from plugins.errorhandling import *
from tqdm import tqdm

"""

 - Software-specific logs (Apache, etc.)?

Example:
    ./LEAF/main.py -c network,users,logs,internet

Coming next... handling user-input files
 - If a user inputs a file, it will not undergo any categorization unless 
 specified (perhaps --ix for input-extreme)
 - If a user inputs his or her own files, additional categories will still 
 be a possibility to insert.

Examples:
    ./LEAF/main.py -i my_file.txt -c network,users,logs,internet
        # Will do LEAF built-in categories in addition to their file
    ./LEAF/main.py --ix my_file.txt --cx samba,apache,ssh
        # Will do the user's file's categories if it is categorized correctly
    ./LEAF/main.py --ix my_file.txt --cx network,users -c network,installation
    
"""


def checkIntegrity(s_file, d_file):
    """
    Check Integrity of the copied file against the original file.
    :param s_file: (str)    source (original) file
    :param d_file: (str)    destination (copied) file
    :return: (bool) Whether or not the file hashes match
    """
    # List to store file hashes in
    hashes = []
    # Parse each file
    for file in (s_file, d_file):
        # Do not attempt to hash link files
        if os.path.islink(s_file):
            return True
        # Generating the hash for the file
        sha1 = hashlib.sha1()
        with open(file, 'rb') as f:
            buf = f.read()
            sha1.update(buf)
        # Add the hash to the file list
        hashes.append(sha1.hexdigest())
    # If the hashes do not match, return False
    if hashes[0] != hashes[1]:
        return False
    # Otherwise, if hashes match, return true
    return True


def debugfs(src, tgt, part, v):
    """
    Transfer inode data from source item to destination item on single
    partition.
    :param src: (str)   source item being copied
    :param tgt: (str)   copied file
    :param part: (str)  partition name
    """

    # Get the original item's inode identifier
    orig_inode = subprocess.check_output(f"stat -c %i '{src}'",
                                         shell=True).decode("utf-8")[:-1]
    # Get the copied item's inode identifier
    new_inode = subprocess.check_output(f"stat -c %i '{tgt}'",
                                        shell=True).decode("utf-8")[:-1]
    # Copy the inode data associated with the source file to the copied file
    if v:
        debug_cmd = f"debugfs -wR \"copy_inode <{orig_inode}> <{new_inode}>\""\
                    f" {part}"
    else:
        debug_cmd = f"debugfs -wR \"copy_inode <{orig_inode}> <{new_inode}>\""\
                f" {part} > /dev/null 2>&1"
    os.system(debug_cmd)


def copy_item(src, evdc_dir, part, v, l_paths):
    """
    Copy each item from the source to the destination with incorporation
    of debugfs to ensure the secure copy of file (inode) metadata.
    :param src: (str)       file or directory that is being copied from
    :param evdc_dir: (str)  evidence directory
    :param part: (str)      partition that stores the files
    :return:
    """
    # The new item to be parsing; this will be the target location
    new_root = evdc_dir+src[1:]

    # Ensure that the evidence directory has a trailing "/"
    if evdc_dir[-1] != "/":
        evdc_dir = evdc_dir + "/"

    if any(l_path in src for l_path in l_paths):
        verbose(f"Skipping {src}: LEAF in Path", v)
        return

    verbose(f"CLONING {src}...", v)

    if os.path.isfile(src):
        # If the source is a file, copy it to the latest target location
        copy = f"mkdir --parents '{evdc_dir}{'/'.join(src.split('/')[:-1])}'"
        os.system(copy)

        copy = f"cp -p '{src}' '{new_root}'"
        os.system(copy)

        try:
            if not checkIntegrity(src, new_root):
                raise NonMatchingHashes(src, new_root)
        except NonMatchingHashes as e:
            print("Error:" , e)

        # Use debugfs to copy each file's inode data over
        debugfs(src, new_root, part, v)

        # return to previous recursive statement
        return

    elif os.path.isdir(src):
        # Otherwise, if the source is a directory, make sure it has a
        # trailing "/"...
        if src[-1] != "/":
            src = src + "/"

        # Copy the entire file structure to the target location. --parent
        # ensures that the entire hierarchy is copied, not just the final
        # directory
        copy = f"mkdir --parents '{new_root}'"
        os.system(copy)

        # Run debugfs to copy the inode data from the source to destination
        # item
        debugfs(src, new_root, part, v)
        for filename in os.listdir(src):
            # Each item in the directory will be run through copy_item()
            # recursively with an updated source, as long as not in LEAF paths
            if not any(l_path in str(src+filename) for l_path in l_paths):
                copy_item(src+filename, evdc_dir, part, v, l_paths)
    else:
        if os.path.islink(src):
            copy = f"cp -P '{src}' '{new_root}'"
            os.system(copy)
        else:
            return


def main(target_file, evidence_dir, v, leaf_paths):
    """
    Main handler for the copy file + metadata operations.
    :param target_file: (str)   file of listed targets
    :param evidence_dir: (str)  location of evidence directory
    :param v: (bool)      Verbose output on or off
    :param leaf_paths: (list)   list of protected locations used by LEAF
    :return:
    """
    # Read all lines of the targets file and save to targets list
    with open(target_file) as f:
        targets = f.readlines()
    # Parse each line/location; uses tqdm to generate a progress bar
    for i in tqdm(range(len(targets))):
        line = targets[i]
        # Removes any trailing whitespaces or special characters (i.e. "\n")
        if not line[-1].isalnum():
            line = line[:-1]

        # If the path does not exist, raise the DoesNotExist error
        try:
            if not os.path.exists(line):
                raise DoesNotExistError(line)

            # If the line is in protected LEAF paths, raise LEAFinPath Error
            elif any(l_path in line for l_path in leaf_paths):
                raise LEAFInPath(line)
            # Otherwise, if it is a valid path...
            else:
                # Get its partition location
                part = subprocess.check_output(f"df -T '{line}'", shell=True) \
                        .decode('utf-8').split("\n")[1].split(" ")[0]
                # push the item to copy_item()
                if not any(l_path in line for l_path in leaf_paths):
                    copy_item(line, evidence_dir, part, v, leaf_paths)
        except DoesNotExistError as e:
            print("Error:", e, "\nContinuing...")
        except LEAFInPath as e:
            print("Error:", e, "\nContinuing...")

    print("\n\n")
