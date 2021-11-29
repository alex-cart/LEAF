import os
import subprocess
import hashlib


def checkIntegrity(s_file, d_file):
    print(s_file, d_file)
    # hash each file, is the hash the same?
    hashes = []
    for file in (s_file, d_file):
        sha1 = hashlib.sha1()
        with open(file, 'rb') as f:
            buf = f.read()
            sha1.update(buf)
        hashes.append(sha1.hexdigest())
    if hashes[0] != hashes[1]:
        return False
    return True


def statAndCopy(in_item, out_dir, part):
    copyflag = "-p"
    if os.path.isdir(in_item):
        if in_item[-1] != "/":
            in_item = in_item + "/"
        copyflag = copyflag + "r"

    copy = f"cp {copyflag} --parents {in_item} {out_dir}"
    os.system(copy)

    orig_inode = subprocess.check_output(f"stat -c %i {in_item}",
                                         shell=True).decode("utf-8")[:-1]
    new_inode = subprocess.check_output(f"stat -c %i {out_dir}{in_item[1:]}",
                                        shell=True).decode("utf-8")[:-1]

    debug_cmd = f"debugfs -R \"copy_inode <{orig_inode}> <{new_inode}>\"" \
                f" {part}"
    os.system(debug_cmd)
    if os.path.isfile(in_item):
        if not checkIntegrity(in_item, f"{out_dir}{in_item[1:]}"):
            print(f"ERROR: Error copying {in_item}, wrong hash")
    print()


def main(target_file, evidence_dir, leaf_paths):
    #host_users = os.listdir("/home")
    with open(target_file) as f:
        targets = f.readlines()
    for line in targets:
        # find if it exists
        line = line[:-1]
        if not os.path.exists(line):
            print(line, "does not exist.")
        elif line in leaf_paths[0] or line in leaf_paths[1] or line in \
                leaf_paths[2]:
            print("Error: LEAF data path listed in target locations. "
                  "Continuing...")
        else:
            part = subprocess.check_output(f"df -T {line}",shell=True) \
                    .decode('utf-8').split("\n")[1].split(" ")[0]
            statAndCopy(line, evidence_dir, part)
    print("\n\n")





