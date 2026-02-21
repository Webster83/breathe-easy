'''
sleephq_uploader.py
author: BChap, SleepHQ Forums
Latest Revision Date: 20260219

sleephq_uploader.py simplifies the process of uploading the data from an SD Card to the Sleep HQ 
website. This API access is available only to pro members. 

usage: edit config.yaml to set the configuration that will be used to successfully upload the data
, then call 'python sleephq_uploader.py'
'''

# 3rd party imports
import os
import time
from yaml import safe_load

# 1st party imports
import cleanup_files
import ezshare_getter
import sd_copy
import shq_upload
from generate_config_yaml import gather_user_input, generate_config_yaml

def load_config() -> dict:
    """
    Loads config.yaml from the current working directory

    :param:
    No parameters

    :return: 
    A dictionary of configuration parameters
    """

    # Open config.yaml and load in data
    with open("config.yaml", "r", encoding="utf-8") as f:
        config = safe_load(f)
    return config

def main()-> None:
    """Main program to run the SD Card data import via Wifi SD or local SD card 
    to SleepHQ upload, and optional cleanup based on a config.yaml file"""
    # Check if config.yaml exists, and if so, load it. If not, call the template generator with
    # the configuration template dict
    if not os.path.exists("config.yaml"):
        # define the template, with the default values
        shq_upload_template = {
            'global_options': {
                'save_to_path': 'LatestCPAP', # Which subfolder of the script directory will be 
                                              # used to store the CPAP data from the card
                'upload_from_ezshare': True, # if False, then we will do a local copy, need
                                             # sd_options set
                'upload_from_local_sd_card': False, # Still want this value, I may not 
                                                    # want to copy any data if the
                                                    # failure was upload related
                'number_of_days': 1,    # number of days data to copy, from most-recent backward
                                        # (1: last night, 2: last night and night before, etc)
                'upload': True,         # upload the data to SleepHQ
                'cleanup_after_upload': True,   # Delete the subfolder used to store the CPAP data
                                                # from the card after upload to SleepHQ
                'verbose': False    # verbose output. Lots of text output about the 
                                    # 'behind the scenes' operations
            },
            'cleanup_options': {
                'files': [
                    # list of files to remove as part of the cleanup
                ],
                'folders': [
                    # list of folders to clean up (eg LatestCPAP / subfolder where CPAP data from
                    # card is downloaded to)
                ]
            },
            'sd_options':{
                'sd_path': 'f:/', # What location/partition/volume/mountpoint is your CPAP card?
                'test_only': False, # a "dry run" where copy operation is simulated, but no data
                                    # is actually copied
            },
            'upload_options':{
                'sleephq_client_id': 'your SleepHQ Client ID goes here', # see README.md for info
                                                                         # on this key
                'sleephq_client_secret': 'your SleepHQ Client Secret goes here', # see README.md for
                                                                                 # info on this key
            },
            'ezshare': {
                'ip_address': '192.168.4.1',    # IP address of your EZSh@re card, typically
                                                # 192.168.4.1
                'dir': 'dir=A:',                # The string used by EZSh@re's web UI dir? parameter
                                                # to show the root level contents
                'card_ssid': 'ez share',        # The EZSh@re Wifi network name
                'card_wpa2': '88888888',        # The EZSh@re WiFi password - 
                                                # not currently used, as only Windows wifi
                                                # switching via profiles is supported currently
                'home_ssid': 'OurHouse',         # Your home WiFi network name 
                                                 # (what you use when you connect to the internet
                                                 # normally)
                'home_wpa2': 'InTheMiddleOfOurStreet', # Your home WiFi network password - not 
                                                       # currently used, as only Windows WiFi
                                                       # switching via profiles is
                                                       #  supported currently
                'overwrite': True,               # Overwrites folder names if they exist. 
            }
        }

        print("config.yaml not found in current working directory. Let's create one now")
        generate_config_yaml('config.yaml', gather_user_input(template=shq_upload_template))
        print("config.yaml created. Proceeding to load configuration and run the program.")
    else:
        print("config.yaml found. Proceeding to load configuration.")

    # now that we have a yalid config yaml for this application, lets load it and parse the
    # parameters for the desired function calls
    config = load_config()
    global_params = config['global_options']
    sd_params = config["sd_options"]
    upload_params = config["upload_options"]
    cleanup_params = config["cleanup_options"]
    ezshare_params = config["ezshare"]


    # Decide what initializations are needed
    if global_params['upload_from_ezshare']:
        # We want to get files from Wifi SD card
        # get the data from the EZShare
        ezshare_getter.run_ezshare(ezshare_params['card_ssid'],
                                   ezshare_params['home_ssid'],
                                   ezshare_params['ip_address'],
                                   ezshare_params['dir'],
                                   global_params['save_to_path'],
                                   ezshare_params['overwrite'],
                                   global_params['number_of_days'],
                                   global_params['verbose'])
    if global_params['upload_from_local_sd_card']:
        # We want to get files from local
        print("Running SD Card data import...")
        sd_copy.run_backup(sd_params['sd_path'],
                           global_params['save_to_path'],
                           'DATALOG',
                           'SETTINGS',
                           global_params['number_of_days'],
                           sd_params['test_only'],False,False,False,2.0)

    if global_params['upload']:
        # We want to upload to Sleep HQ
        upload_data(global_params,upload_params)

    # Run the cleanup routines if specifified in config.yaml
    if global_params['cleanup_after_upload']:
        print("Running cleanup of generated files and folders...")
        if len(cleanup_params["files"]) > 0:
            for file in cleanup_params["files"]:
                cleanup_files.cleanup_files([file])
        if len(cleanup_params["folders"]) > 0:
            for folder in cleanup_params["folders"]:
                cleanup_files.cleanup_folder(folder)

    print("All operations completed.")
    time.sleep(5)  # Pause to allow user to see final messages before terminal closes.
                           # 15 seconds was too long.

def upload_data(global_dict:dict,upload_dict:dict)->None:
    """
    Helper function to call the data uploader module

    :param dict globals: a dictionary of imported global_options from config.yaml
    :param dict uploads: a dictionary of imported upload_options from config.yaml
    
    :return:
    :rtype: None
    """
    cpap_data_path = os.getcwd()+os.sep+global_dict["save_to_path"]
    cpap_subpath = cpap_data_path+os.sep
    shq_upload.run_upload(upload_dict['sleephq_client_id'],
                          upload_dict['sleephq_client_secret'],
                          cpap_data_path,
                          cpap_subpath,
                          global_dict['verbose'])

if __name__ == "__main__":
    main()
