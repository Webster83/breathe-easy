'''breathe_easy.py - ResMed xPAP uploader client for SleepHQ
Written by: BChap - SleepHQ Community Forum Member
Last Modified Date: 20260613
'''


import os
import time
import logging
import sys
import argparse
import ctypes

from datetime import datetime

from yaml import safe_load

import breathe_easy.call_robocopy as call_robocopy
import breathe_easy.cleanup_files as cleanup_files
import breathe_easy.sd_copy as sd_copy
import breathe_easy.sleephq_upload as sleephq_upload
from breathe_easy.generate_config_yaml import make_config, prune_keys
from breathe_easy.ezshare_getter import run_ezshare
from breathe_easy.sleephq_upload import sleephq_upload


MYAPPID = "BRITS.BREATHE_EASY"
ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(MYAPPID)

def get_base_dir():

    ''' gets base directory depending on execution type'''

    if getattr(sys,'frozen',False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def get_resource_path(filename):

    '''returns resource path for PyInstaller'''

    base_path = getattr(sys, '_MEIPASS', os.path.abspath("."))
    return os.path.join(base_path, filename)


BASEDIR = get_base_dir()
CONFIGPATH = os.path.join(BASEDIR,'config.yaml')
LOGDIR = os.path.join(BASEDIR,'logs')
TEMPLATEDEST= os.path.join(BASEDIR,'template.yaml')
TEMPLATEBUND = get_resource_path("template.yaml")

if not os.path.exists(TEMPLATEDEST):
    print("Creating template.yaml from bundled copy...")

    with open(TEMPLATEBUND,"r", encoding="utf-8") as src:
        with open(TEMPLATEDEST, "w", encoding="utf-8") as dst:
            dst.write(src.read())


log_file = os.path.join(LOGDIR,"Breathe_Easy_v2_"
    +datetime.now().strftime("%Y%m%d%H%M%S")
    +".log")
os.makedirs(LOGDIR,exist_ok=True)

# Set up logging

logger = logging.getLogger("breathe_easy")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    filename=log_file,
    force=True
)
logger.info("<---- Starting Run ---->")

def parse_args():

    '''cli argument parser'''

    parser = argparse.ArgumentParser(
        description="Breathe Easy - A SleepHQ Uploader for Resmed Air11 devices"
    )

    parser.add_argument(
         "-rup", "--reset_user",
        action="store_true",
        help="Remove user profile settings"
    )

    parser.add_argument(
        "-ra","--reset_all", 
        action="store_true",
        help="Reset everything (removes config.yaml)"
    )

    parser.add_argument(
        "-nr", "--no_run",
        action="store_true",
        help="Do not run the program after completing the action. "\
            "Only valid with --reset_all (-ra) or --reset_user (-rup)."
        )

    return parser.parse_args()

def load_config() -> dict:

    '''
    Loads config.yaml from the current working directory

    :params: No parameters 

    :returns: A dictionary of configuration parameters
    :rtype: dict
    '''

    # Open config.yaml and load in data
    with open(CONFIGPATH, "r", encoding="utf-8") as f:
        config = safe_load(f)
    return config

def main()-> None:
    ''' Entry point, but handles args only before calling breathe_easy for
    processing logic beyond arg handling
    '''
    # check if --rup or -- ra are args:
    args = parse_args()

    if args.reset_user and args.reset_all:
        logger.error("Invalid reset. Cannot use both flags")
        print("Cannot use both --reset_user and --reset_all")
        time.sleep(5)
        sys.exit(1)
    if args.no_run and not (args.reset_user or args.reset_all):
        logger.error("Invalid use of --no_run")
        print("--no_run can only be used with --reset_user (-ru) or --reset_all")
        time.sleep(5)
        sys.exit(1)

    if args.reset_user:
        try:
            prune_shq_keys = [
                ['shq_options', 'name'],
                ['shq_options', 'team_id'],
                ['shq_options', 'default_mask_id'],
                ['shq_options', 'bearer']
            ]

            logger.info("calling prune_keys with (config.yaml,%s)", prune_shq_keys)
            success = prune_keys('config.yaml',prune_shq_keys)

            if not args.no_run and success:
                logger.info("SleepHQ options reset. Continuing Execution")
            elif args.no_run and success:
                logger.info("--no_run used. Exiting")
                print("SleepHQ user info reset. Exiting")
                time.sleep(5)
                sys.exit()
            else:
                print("No user profile settings found to delete. ",end="")
                if args.no_run:
                    logger.info("No SleepHQ user options. no_run used, so exiting")
                    print("No SleepHQ options found to reset. Goodbye")
                    time.sleep(5)
                    sys.exit()
                else:
                    logger.info("No SleepHQ user options. Continuing")
                    print("No SleepHQ options found to reset. Continuing")

        except FileNotFoundError:
            print("Config file not found, see log")
            logger.error("Config file not found when trying to use -ru")
            time.sleep(5)
            sys.exit(1)

    elif args.reset_all:
        try:
            os.remove('config.yaml')
            print("config.yaml removed")
            if args.no_run:
                logger.info("config.yaml deleted and no_run set")
                print("Goodbye!")
                time.sleep(5)
                sys.exit()
            else:
                logger.info("config.yaml file removed. Continuing to run")
                print("config.yaml file removed. Running breathe_easy at 'first run' state")
        except FileNotFoundError:
            print("No config.yaml file found to erase")
            if args.no_run:
                logger.info("config.yaml file not found. --no_run so exiting")
                print("Goodbye")
                time.sleep(5)
                sys.exit()
            else:
                logger.info("config.yaml file not found. Continuing to run")
                print("Continuing to run breathe_easy in a 'first run' state")

    breathe_easy()

def breathe_easy():

    """ Main program to run the SD Card data import via Wifi SD or local SD card 
    to SleepHQ upload, and optional cleanup based on a config.yaml file"""
    # Check if config.yaml exists, and if so, load it. If not, call the template generator with
    # the configuration template dict

    if not os.path.exists(CONFIGPATH):
        logger.info("config.yaml not found. Creating...")
        print("config.yaml not found in current working directory. Let's create one now")
        make_config(TEMPLATEDEST)
        print("config.yaml created. Proceeding to load configuration and run the program.")
    else:
        logger.info("config.yaml found")
        print("config.yaml found. Proceeding to load configuration.")

    # now that we have a yalid config yaml for this application, lets load it and parse the
    # parameters for the desired function calls

    config = load_config()
    logger.info("Successfully loaded config.yaml")
    global_params = config['global_options']
    logger.debug("Parsed [global_options]: %s", global_params)
    sd_params = config["sd_options"]
    logger.debug("Parsed [sd_options]: %s", sd_params)
    upload_params = config["shq_options"]
    logger.debug("Parsed [shq_options]: %s", upload_params)
    cleanup_params = config["cleanup_options"]
    logger.debug("Parsed [cleanup_options]: %s", cleanup_params)
    ezshare_params = config["ezshare"]
    logger.debug("Parsed [ezshare]: %s", ezshare_params)

    robo_rc1 = 16 # set up robo_copy return values so cleanup cannot be called without robocoppy
    robo_rc2 = 16 # running successfully. If 'run robo' was set to false and cleanup true, the
                   # script would crash due to accessing undefined variables. So set to fail
                   # value as default

    # Decide what initializations are needed

    # ----- debug logging statements -----

    if global_params.get("debug"):
        # we want to turn on debugging for all modules
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled for breathe_easy")
        logging.getLogger("connect_wifi_windows")
        logger.debug("Debug logging enabled for connect_wifi_windows")
        logging.getLogger("ezshare_getter").setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled for ezshare_getter")
        logging.getLogger("sd_copy").setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled for sd_copy")
        logging.getLogger("sleephq_upload").setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled for sleephq_upload")
        logging.getLogger("sleephq").setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled for sleephq.client")
        logging.getLogger("call_robocopy").setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled for call_robocopy")
        logging.getLogger("cleanup_files")
        logger.debug("Debug logging enabled for cleanup_files")

    # ----- Download files from Ez-Sh@re Wifi-SD card -----

    if global_params['download_from_ezshare']:
        # We want to get files from Wifi SD card
        # get the data from the EZShare

        logger.info("Connecting to Wifi SD card to get requested data...")
        print("🛜 Connecting to Wifi SD card to get requested data...")

        # define dicts for profiles, directories and options
        profiles={
            'sd':ezshare_params['card_ssid'],
            'home':ezshare_params['home_ssid'],
        }

        directories={
            'root':ezshare_params['dir'],
            'save':os.path.join(BASEDIR,global_params['save_to_path']),
        }

        options={
            'overwrite':ezshare_params['overwrite'],
            'verbose':global_params['debug'],
            'n_days':global_params['number_of_days'],
        }

        run_ezshare(ezshare_params['ip_address'],
                                   profiles,
                                   directories,
                                   options)

    # ------ Copy files from locally-connected SD Card ------

    if global_params['copy_from_local_sd_card']:
        # We want to get files from local
        logger.info("Running SD Card data import...")
        print("📂Running SD Card data import...")

        sd_copy.run_backup(sd_params['sd_path'],
                           os.path.join(BASEDIR,global_params['save_to_path']),
                           'DATALOG',
                           'SETTINGS',
                           global_params['number_of_days'],
                           sd_params['test_only'],False,False,False,2.0)

    # ------ Upload files to Sleep HQ -----

    if not global_params.get('no_shq_upload'):  # key can be None or set to false
                                                # and the upload will run
        global_params['save_to_path'] = os.path.join(BASEDIR,global_params['save_to_path'])
        sleephq_upload(global_params,upload_params)

    # ----- Robo-copy files to SD card (local backup of EZ-Sh@re)

    if global_params['run_robo']:
        logger.info("Running Robocopy... ")
        print("🤖 Running Robocopy... ")

        options= "/E /XO /DCOPY:T /COPY:DAT /R:1 /W:1 /MT:12 /XD 'Settings'"
        robo_rc1 = call_robocopy.run_robocopy(global_params['save_to_path'],
                                   sd_params['sd_path'],
                                   options)

        options = '/E /DCOPY:T /COPY:DAT /R:1 /W:1'
        robo_rc2 = call_robocopy.run_robocopy(f"{global_params['save_to_path']}"+r"\\Settings",
                                   sd_params['sd_path']+r'\\Settings',
                                   options)

    # Should only run this robocopy executes successfully...
    # Run the cleanup routines if specifified in config.yaml

    if global_params['cleanup_after_upload']:
        if robo_rc1 < 8 and robo_rc2 < 8:
            logger.info("Cleaning up after copy and upload...")
            print("🧹Cleaning up after copy and upload...")
            if len(cleanup_params["files"]) > 0:
                for file in cleanup_params["files"]:
                    logger.info("Cleaning up %s",file)
                    cleanup_files.cleanup_files([file])
            if len(cleanup_params["folders"]) > 0:
                for folder in cleanup_params["folders"]:
                    logger.info("Cleaning up %s",folder)
                    cleanup_files.cleanup_folder(folder)
        else:
            print("Cleanup not run as robocopy failed to run successfully\n"\
              "Manually delete files if desired")
            logger.error("Cleanup would have run without robocopy completing\n"\
                      "Not cleaning up for safety. Manually delete files")

    logger.info("All operations completed")
    print("🏁 All operations completed.")
    logger.info("<---- Ending Run ---->")
    logging.shutdown()

    time.sleep(5)  # Pause to allow user to see final messages before terminal closes.
                           # 15 seconds was too long.python
