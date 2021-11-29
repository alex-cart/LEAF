import os
import shutil
import subprocess

print("Subprocess")
#x = os.system("ipconfig")
x = subprocess.check_output("debugfs -R 'copy_inode <1048700> <1048748>' "
                            "/dev/sda2", shell=True)
print("Subprocess2")
print(x)
print("System")
x = os.system("debugfs -R 'copy_inode <1048700> <1048748>' /dev/sda2")
print("System2")
print(x)


'''in_dir = "/home/user1/Desktop/aaa/two/"
in_file = "twotwo.txt"
out_dir2 = "/home/user1/Desktop/aaa/one/two/"
out_dir1 = "/home/user1/Desktop/aaa/mnpt/two/"


print()
print("================ORIGINAL DATA===============")
print()
os.system(f"stat {in_dir} {in_dir}{in_file}")

#shutil.copytree(in_dir, out_dir1)
#os.system(f"rsync -a {in_dir} {out_dir1}")
os.system(f"dd if={in_dir}{in_file} of={out_dir1} --conv=fsync,sync")
print()
print("================COPIED DATA===============")
print()
os.system(f"stat {out_dir1} {out_dir1}{in_file}")
print()
print("================FIXED DATA===============")
print()
os.system(f"touch -r {in_dir}{in_file} {out_dir1}{in_file}")

# Changes the Access Time
os.system(f"touch -a --date='$(stat -c %x {in_dir}{in_file}) "
          f"-m --date='$(stat -c %y {in_dir}{in_file}) {out_dir1}{in_file}")

"""## Changes the Modified Date
os.system("touch -m --date='$(stat -c %y aaa/two/twotwo.txt)' "
          "aaa/one/two/twotwo.txt")"""


os.system(f"stat {out_dir1} {out_dir1}{in_file}")


#touch -a --date="$(stat -c %x aaa/two/twotwo.txt)" -m --date="$(stat -c %y
# aaa/two/twotwo.txt)"  aaa/one/two/twotwo.txt
#dd if=aaa/two/twotwo.txt of=aaa/mnpt/twotwo.txt bs= --conv=fsync
'''
