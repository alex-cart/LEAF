import os
import socket
import platform

try:
    import pwd, grp
except ModuleNotFoundError:
    print("This host is not Linux-based! Exiting...")
    exit()


class OSInfo():
    def __init__(self, os_type, os_v, b_num, vol_info):
        self.os_type = os_type
        self.os_vsn = os_v
        self.build_num = b_num


class UserInfo():
    def __init__(self):
        self.user_dict = self.getUnames()
        self.group_dict = self.getGroups()

    def getUnames(self):
        udict = {}
        for p in pwd.getpwall():
            udict[p[0]] = (grp.getgrgid(p[3])[0])
        return udict


    def getGroups(self):
        pass



class NetInfo():
    def __init__(self, ips, dhcp, networks):
        self.ip_list = ips
        self.dhcp = dhcp
        self.networks = networks



# BasicInfo has OSInfo, UserInfo, NetInfo
class BasicInfo(object):
    """def __init__(self, hname, ostype, osr, osv, hware, processor, users,
                 groups):
        self.hostname = hname

        self.os_type = ostype
        self.os_release = osr
        self.os_version = osv
        self.hardware = hware
        self.processor = processor

        self.user_dict = users
        self.groups_dict = groups"""

    def __init__(self, users, groups):
        self.os_type, self.hostname, self.os_release, self.os_version, \
            self.hardware, self.processor = platform.uname()

        self.user_dict = UserInfo.getUnames(self)
        self.groups_dict = groups

    """def getSystemInfo(self):
        return self.hostname, self.os_version, self.build_num"""

    def __str__(self):
        out = f"Hostname: {self.hostname}\nOS Type: {self.os_type}\n" \
               f"OS Release: {self.os_release}\nOS Version: " \
               f"{self.os_version}\nMachine Hardware (64b vs 32b): " \
               f"{self.hardware}\nProcessor: {self.processor}\nUsers:\n"
        for u_item in self.user_dict:
            out = out + "\t" + u_item + "\t --> \t" + self.user_dict[u_item] + "\n"
        return out


thisPC = BasicInfo("","")

print(thisPC)

#print(socket.gethostname())
#print(pwd.getpwall())
print("---------------------------------")
#print(grp.getgrgid())

