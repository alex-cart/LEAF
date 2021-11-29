import os
# Think about doing pycdlib, see if there is a difference

def acquire(target_dir, out_dir, img_file):
    print(f"Acquiring {target_dir}...")
    os.system(f"tree {target_dir}")
    os.system(f"mkisofs -r -o {out_dir}{img_file} {target_dir}")


def main(target_dir, out_dir, img_file):
    acquire(target_dir, out_dir, img_file)
    print("Done!")

