import os
import subprocess
import hashlib

"""
Coming soon.... categories of targets listed with #'s. 
 - Lines that start with "#" will be handled as a category until the next # 
 or  end of file, and lines within that range will be interpreted as a category.
 - Add categories to create_environment.py
 - When categories are listed in create_environment, search the  
 target_locations for that category header. When found, run only the 
 acquisition on those files. 
 - Software-specific logs (Apache, etc.)

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
    ./LEAF/main.py --ix my_file.txt --cx network,users,logs,internet
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


def debugfs(src, tgt, part):
    """
    Transfer inode data from source item to destination item on single
    partition.
    :param src: (str)   source item being copied
    :param tgt: (str)   copied file
    :param part: (str)  partition name
    """
    # Get the original item's inode identifier
    orig_inode = subprocess.check_output(f"stat -c %i {src}",
                                         shell=True).decode("utf-8")[:-1]
    # Get the copied item's inode identifier
    new_inode = subprocess.check_output(f"stat -c %i {tgt}",
                                        shell=True).decode("utf-8")[:-1]
    # Copy the inode data associated with the source file to the copied file
    debug_cmd = f"debugfs -R \"copy_inode <{orig_inode}> <{new_inode}>\"" \
                f" {part}"
    os.system(debug_cmd)

def copy_item(src, evdc_dir, part):
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

    if os.path.isfile(src):
        # If the source is a file, copy it to the latest target location
        copy = f"mkdir --parents {evdc_dir}{'/'.join(src.split('/')[:-1])}"
        os.system(copy)
        copy = f"cp -p {src} {new_root}"
        os.system(copy)

        if not checkIntegrity(src, new_root):
            print(f"ERROR: Error copying {src}, wrong hash")

        # Use debugfs to copy each file's inode data over
        debugfs(src, new_root, part)

        # return to previous recursive statement
        return
    else:
        # Otherwise, if the source is a directory, make sure it has a
        # trailing "/"...
        if src[-1] != "/":
            src = src + "/"

        # Copy the entire file structure to the target location. --parent
        # ensures that the entire hierarchy is copied, not just the final
        # directory
        copy = f"mkdir --parents {new_root}"
        os.system(copy)

        # Run debugfs to copy the inode data from the source to destination
        # item
        debugfs(src, new_root, part)
        for filename in os.listdir(src):
            # Each item in the directory will be run through copy_item()
            # recursively with an updated source
            copy_item(src+filename, evdc_dir, part)


def main(target_file, evidence_dir, leaf_paths):
    """
    Main handler for the copy file + metadata operations.
    :param target_file: (str)   file of listed targets
    :param evidence_dir: (str)  location of evidence directory
    :param leaf_paths: (list)   list of protected locations used by LEAF
    :return:
    """
    # Read all lines of the targets file and save to targets list
    with open(target_file) as f:
        targets = f.readlines()
    # Parse each line/location
    for line in targets:
        # Removes any trailing whitespaces or special characters (i.e. "\n")
        if not line[-1].isalnum():
            line = line[:-1]

        # If the path does not exist, return that it does not exist and
        # continue
        if not os.path.exists(line):
            print(line, "does not exist.")
        # If the line is in the protected LEAF paths, do not copy and continue
        elif line in leaf_paths[0] or line in leaf_paths[1] or line in \
                leaf_paths[2]:
            print("Error: LEAF data path listed in target locations. "
                  "Continuing...")
        # Otherwise, if it is a valid path...
        else:
            # Get its partition location
            part = subprocess.check_output(f"df -T {line}",shell=True) \
                    .decode('utf-8').split("\n")[1].split(" ")[0]
            # push the item to copy_item()
            copy_item(line, evidence_dir, part)
    print("\n\n")





