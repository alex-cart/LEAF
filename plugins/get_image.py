import os

"""
Coming soon... testing the differences between pycdlib and mkisofs
"""

def acquire(target_dir, out_dir, img_path):
    print(f"Acquiring {target_dir}...")
    os.system(f"tree {target_dir}")
    os.system(f"mkisofs -r -o {img_path} {target_dir}")


def main(target_dir, out_dir, img_path):
    acquire(target_dir, out_dir, img_path)
    print("Done!")

