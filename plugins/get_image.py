import os
import hashlib
import shutil
from plugins.errorhandling import *


def getHash(iso_file):
    """
    Check Integrity of the copied file against the original file.
    :param s_file: (str)    source (original) file
    :param d_file: (str)    destination (copied) file
    :return: (bool) Whether or not the file hashes match
    """

    # Generating the hash for the file
    sha1 = hashlib.sha1()
    with open(iso_file, 'rb') as f:
        buf = f.read()
        sha1.update(buf)
    return sha1.hexdigest()


def acquire(target_dir, out_dir, img_path):
    print(f"Acquiring '{target_dir}'...")
    os.system(f"tree -a '{target_dir}'")
    print(f"Writing data to '{img_path}'")
    os.system(f"mkisofs -max-iso9660-filenames -U -o '{target_dir}' '{out_dir}'")

def main(target_dir, out_dir, img_path, raw):
    acquire(target_dir, out_dir, img_path)
    print("Done!")
    iso_hash = getHash(img_path)
    if not raw:
        shutil.rmtree(target_dir)
    return iso_hash
