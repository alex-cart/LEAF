# Linux Evidence Acquisition Framework (LEAF)
Author: Alexandra Cartwright

April, 2022
## Description
Linux Evidence Acquisition Framework (LEAF) acquires artifacts and evidence from Linux EXT4 systems, accepting user input to customize the functionality of the tool for easier scalability. Offering several modules and parameters as input, LEAF is able to use smart analysis to extract Linux artifacts and output to an ISO image file.

## Usage 
```
LEAF_master.py [-h] [-i INPUT [INPUT ...]] [-o OUTPUT] [-u USERS [USERS ...]] [-c CATEGORIES [CATEGORIES ...]] [-v]
                      [-s] [-g [GET_OWNERSHIP [GET_OWNERSHIP ...]]] [-y [YARA [YARA ...]]]
                      [-yr [YARA_RECURSIVE [YARA_RECURSIVE ...]]]

LEAF (Linux Evidence Acquisition Framework) - Cartware
     ____        _________    ___________   __________ 
    /   /       /   _____/   /  ____    /  /   ______/
   /   /       /   /____    /  /___/   /  /   /____  
  /   /       /   _____/  /   ____    /  /   _____/
 /   /_____  /   /_____  /   /   /   /  /   /      
/_________/ /_________/ /___/   /___/  /___/          v1.9
```

Process Ubuntu 20.04/Debian file systems for forensic artifacts, extract important data, 
and export information to an ISO9660 file. Compatible with EXT4 file system and common 
locations on Ubuntu 20.04 operating system.
See help page for more information.
Suggested usage: Do not run from LEAF/ directory

## Parameters
```
optional arguments:

  -h, --help            show this help message and exit

  -i INPUT [INPUT ...], --input INPUT [INPUT ...]
                        Additional Input locations. Separate multiple input files with spaces
                        Default: /home/user1/Desktop/LEAF-3/target_locations
			
  -o OUTPUT, --output OUTPUT
  
                        Output directory location
			
                        Default: ./LEAF_output
			
  -u USERS [USERS ...], --users USERS [USERS ...]
  
                        Users to include in output, separated by spaces (i.e. -u alice bob root). 
                        Users not present in /etc/passwd will be removed
                        Default: All non-service users in /etc/passwd
  -c CATEGORIES [CATEGORIES ...], --categories CATEGORIES [CATEGORIES ...]
                        Explicit artifact categories to include during acquisition. 
                        Categories must be separated by space, (i.e. -c network users apache).
                        Full List of built-in categories includes:
                        	APPLICATIONS, EXECUTIONS, LOGS, MISC, NETWORK, SHELL, STARTUP, SERVICES, SYSTEM, TRASH, USERS
                        Categories are compatible with user-inputted files as long as they follow the notation:
                        	# CATEGORY
                        	/location1
                        	/location2 
                        	.../location[n]
                        	# END CATEGORY 
                        Default: "all"
  -v, --verbose         Output in verbose mode, (may conflict with progress bar)
                        Default: False
  -s, --save            Save the raw evidence directory
                        Default: False
  -g [GET_OWNERSHIP [GET_OWNERSHIP ...]], --get_ownership [GET_OWNERSHIP [GET_OWNERSHIP ...]]
                        Get files and directories owned by included users.
                        Enabling this will increase parsing time.
                        Use -g alone to parse from / root directory.
                        Include paths after -g to specify target locations (i.e. "-g /etc /home/user/Downloads/
                        Default: Disabled
  -y [YARA [YARA ...]], --yara [YARA [YARA ...]]
                        Configure Yara IOC scanning. Select -y alone to enable Yara scanning.
                        Specify '-y /path/to/yara/' to specify custom input location.
                        For multiple inputs, use spaces between items,
                        i.e. '-y rulefile1.yar rulefile2.yara rule_dir/'
                        All yara files must have ".yar" or ".yara" extension.
                        Default: None
  -yr [YARA_RECURSIVE [YARA_RECURSIVE ...]], --yara_recursive [YARA_RECURSIVE [YARA_RECURSIVE ...]]
                        Configure Recursive Yara IOC scanning.
                        For multiple inputs, use spaces between items,
                        i.e. '-yr rulefile1.yar rulefile2.yara rule_dir/'.
                        Directories in this list will be scanned recursively.
                        Can be used in conjunction with the normal -y flag,
                        but intersecting directories will take recursive priority.
                        Default: None
```
## Example Usages:
```
To use default arguments [this will use default input file (./target_locations), users (all users), categories (all categories), and output location (./LEAF_output/). Cloned data will not be stored in a local directory, verbose mode is off, and yara scanning is disabled]:
	LEAF_main.py

All arguments:
	LEAF_main.py -i /home/alice/Desktop/customfile1.txt -o /home/alice/Desktop/ExampleOutput/ -c logs startup services apache -u alice bob charlie -s -v -y /path/to/yara_rule1.yar -yr /path2/to/yara_rules/ -g /etc/

To specify usernames, categories, and yara files:
	LEAF_main.py -u alice bob charlie -c applications executions users -y /home/alice/Desktop/yara1.yar /home/alice/Desktop/yara2.yar

To include custom input file(s) and categories:
	LEAF_main.py -i /home/alice/Desktop/customfile1.txt /home/alice/Desktop/customfile2.txt -c apache xampp
```
# How to Use
- Install Python requirements:
  - Python 3 (preferably 3.8 or higher) (`apt install python3`)
  - pip 3 (`apt install pip3`)
- Download required modules
  - Install modules from requirements.txt (`pip3 install -r requirements.txt`)
  - If you get an installation error, try `sudo -H pip3 install -r requirements.txt`
- Run the script
  - `sudo python3 LEAF_master.py` with optional arguments  