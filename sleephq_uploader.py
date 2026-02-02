'''
sleephq_uploader.py
author: BChap, SleepHQ Forums
Latest Revision Date: 20260131

sleephq_uploader.py simplifies the process of uploading the data from an SD Card to the Sleep HQ website of
a pro member. 

usage: edit config.yaml to set the configuration that will be used to successfully upload the data, then call
'python sleephq_uploader.py'
'''

import sd_copy
import os
import shq_upload
from pathlib import Path
from yaml import safe_load


def load_config() -> dict:
    """
    Loads config.yaml from the current working directory

    :param:
    No parameters

    :return: 
    A dictionary of configuration parameters
    """
    
    # Open config.yaml and load in data
    with open("config.yaml", "r") as f:
        config = safe_load(f)
    return config

def main()-> None:
    """Main program when used standalone"""
    config = load_config()
    sd_params = config["sd_options"]
    upload_params = config["upload_options"]

    import_data(sd_params)
    upload_data(upload_params)


def import_data(parameters:dict)->None:
    """Helper function to call the importer with the config.yaml contents

    :param (dict) parameters: a dictionary of imported parameters from config.yaml

    :return:
    Returns nothing
    """
    sdp = os.path.normpath(parameters["sd_path"])
    ver = parameters["verbose"]
    n = parameters["number_of_days"]
    path = os.getcwd()+os.sep+parameters["save_to_path"]
    test = parameters["test_only"]
    
    sd_copy.run_backup(
        Path(sdp),
        Path(path),
        "DATALOG",
        "Settings",
        days_to_import=n,
        dry_run=test,
        verify=False,
        verify_created=False,
        verify_hash=False,
        slack=float(3.0)
    )

def upload_data(parameters:dict)->None:
    """
    Helper function to call the data uploader module

    :param parameters (dict): a dictionary of imported parameters from config.yaml
    
    :return:
    Returns nothing
    """
    cpap_data_path = os.getcwd()+os.sep+parameters["data_path"]
    cpap_subpath = cpap_data_path+os.sep
    shq_upload.run_upload(parameters["client_id"],parameters["client_secret"],cpap_data_path,cpap_subpath,False)

if __name__ == "__main__":
    main()