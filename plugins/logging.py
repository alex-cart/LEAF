import pandas as pd
import datetime
import os
from plugins.errorhandling import *


class Log():
    def __init__(self, save_loc=str(os.getcwd() + "/LEAF_output/")):
        """
        Create a new log session for logging file cloning operations and
        command issues.
        :param save_loc: (str) location to save log in
        """
        self.save_loc = save_loc

        # Filename of the new log series ("logitem_YYYY-MM-DD_hhmmss")
        self.log_fname = "logitem_" + str(datetime.datetime.now().strftime(
            "%Y-%m-%d_%H%M%S"))

        # Create headers for file-clone log and command log
        self.full_log = pd.DataFrame(columns=["Source_File", "Dest_File",
                                              "Source_Hash", "Dest_Hash",
                                              "Integrity", "File_Size",
                                              "Time_UTC"])
        self.cmd_log = pd.DataFrame(columns=["Input_TargetFile",
                                             "Output_Location",
                                             "Users_List", "Categories",
                                             "Image_Name",
                                             "Verbose", "Save_RawData",
                                             "YaraScanning"])

    def new_log(self, src_name, dst_name, src_hash, dst_hash, size=0):
        """
        Add a new clone log to logging file
        :param src_name: (str)  name of original file
        :param dst_name: (str)  name of destination file
        :param src_hash: (str)  hash of original file
        :param dst_hash: (str)  hash of destination file
        :return:
        """
        current_time = str(datetime.datetime.utcnow()).replace(" ", "T")
        new_log = {
            "Source_File" : src_name,
            "Dest_File" : dst_name,
            "Source_Hash" : src_hash,
            "Dest_Hash" : dst_hash,
            "Integrity" : src_hash == dst_hash,
            "File_Size" : size,
            "Time_UTC" : current_time,
        }
        self.update_df(new_log)

    def new_commandlog(self, leaf_obj):
        new_cmdlog = {
            "Input_TargetFile" : leaf_obj.targets_file,
            "Output_Location" : leaf_obj.output_dir,
            "Users_List" : leaf_obj.users_list,
            "Categories" : leaf_obj.cats,
            "Image_Name" : leaf_obj.img_path,
            "Verbose" : leaf_obj.verbose,
            "Save_RawData" : leaf_obj.raw,
            "YaraScanning" : leaf_obj.yara
        }
        self.update_df(new_cmdlog, log_type="Cmd")
        self.write_to_file(log_type="Cmd")


    def update_df(self, new_log, log_type="File"):
        if log_type == "File":
            self.full_log = self.full_log.append(new_log, ignore_index=True)
        else:
            self.cmd_log = self.cmd_log.append(new_log, ignore_index=True)


    def write_to_file(self, fname="", log_type="File"):
        floc = self.save_loc
        if fname == "":
            fname = self.log_fname + ".csv"

        if log_type == "File":
            if fname == "":
                fname = self.log_fname + ".csv"
            write_log = self.full_log
        else:
            fname = self.log_fname + "_CommandData.csv"
            write_log = self.cmd_log

        write_path = str(floc + fname)
        try:
            write_log.to_csv(write_path, index=False)
        except FileNotFoundError as e:
            os.makedirs(floc)
            write_log.to_csv(write_path, index=False)

    def __str__(self):
        pd.set_option("display.max_rows", None, "display.max_columns", None)
        return str(self.full_log)