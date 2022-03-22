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


def acquire(e_dir, out_dir, img_path):
    print(f"Acquiring '{e_dir}'...")
    os.system(f"tree -a '{e_dir}'")
    print(f"Writing data to '{img_path}'")
    os.system(f"mkisofs -max-iso9660-filenames -U -o '{e_dir}' '{out_dir}'")
    #os.system(f"mkisofs -max-iso9660-filenames -U -o '{img_path}' '{
    # e_dir}'") #?


def main(leaf_obj):
    evdc_dir = leaf_obj.evidence_dir
    out_dir = leaf_obj.output_dir
    img_path = leaf_obj.img_path
    raw = leaf_obj.raw
    acquire(evdc_dir, out_dir, img_path)
    print("Done!")
    iso_hash = getHash(img_path)
    leaf_obj.iso_hash = iso_hash
    if not raw:
        shutil.rmtree(evdc_dir)
    return iso_hash
