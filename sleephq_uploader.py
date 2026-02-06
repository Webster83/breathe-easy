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
import cleanup_files
import time
from pathlib import Path
from yaml import safe_load
from generate_config_yaml import gather_user_input, generate_config_yaml
from pprint import pprint as pprint

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
    """Main program to run the SD Card data import and SleepHQ upload based on config.yaml"""

    # Check if config.yaml exists, and if so, load it. If not, call the template generator with the configuration template dict
    if not os.path.exists("config.yaml"):
        # define the template, with the default values
        shq_upload_template = {
            'sd_options': {
                'copy': True,
                'sd_path': 'E:/',  # What location/partition/volume is your CPAP Card?
                'save_to_path': 'LatestCPAP',  # This is a subfolder of the location where the python files exist
                'number_of_days': 1,  # newest number of days to copy
                'verbose': False,  # show extra logging
                'test_only': False,  # set to true to only simulate the copy without actually copying files
            },
            'upload_options': {
                'upload': True,
                'client_id': 'Put Client ID value here',  # get this value from Sleep HQ API keys. See Readme.MD
                'client_secret': 'Put Client Secret here',  # get this value from Sleep HQ API keys. See Readme.MD
                'data_path': 'LatestCPAP',  # This is  a subfolder of the location where the python files exist.
                'verbose': False,  # show extra logging
            },
            'cleanup_options': {
                'cleanup': True,
                'files': [
                    # List specific files to clean up here
                ],
                'folders': [
                    # List specific folders to clean up here
                ],
            }
        }
        
        print("config.yaml not found in current working directory. Let's create one now")
        generate_config_yaml('config.yaml', gather_user_input(template=shq_upload_template))
        print("config.yaml created. Proceeding to load configuration and run the program.")
    else:
        print("config.yaml found. Proceeding to load configuration.")

    # now that we have a yalid config yaml for this application, lets load it and parse the parameters for the desired function calls
    config = load_config()
    sd_params = config["sd_options"]
    upload_params = config["upload_options"]
    cleanup_params = config["cleanup_options"]

    if sd_params["copy"]:
        print("Running SD Card data import...")
        import_data(sd_params)

    if upload_params["upload"]:
        print("Running SleepHQ data upload...")
        upload_data(upload_params)

    # Run the cleanup routines if specifified in config.yaml
    if cleanup_params["cleanup"]:
        print("Running cleanup of generated files and folders...")
        if len(cleanup_params["files"]) > 0:
            for file in cleanup_params["files"]:
                cleanup_files.cleanup_files([file])
        if len(cleanup_params["folders"]) > 0:
            for folder in cleanup_params["folders"]:
                cleanup_files.cleanup_folder(folder)

    print("All operations completed.")
    time.sleep(15)  # Pause to allow user to see final messages before terminal closes    


def import_data(parameters:dict)->None:
    """Helper function to call the importer with the config.yaml contents

    :param  dict parameters: a dictionary of imported parameters from config.yaml

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

    :param dict parameters: a dictionary of imported parameters from config.yaml
    
    :return:
    Returns nothing
    """
    cpap_data_path = os.getcwd()+os.sep+parameters["data_path"]
    cpap_subpath = cpap_data_path+os.sep
    shq_upload.run_upload(parameters["client_id"],parameters["client_secret"],cpap_data_path,cpap_subpath,False)

if __name__ == "__main__":
    main()