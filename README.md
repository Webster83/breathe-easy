# sleephq_uploader Readme

## Purpose

To streamline import of ResMed Air 11 device data to SleepHQ and keep the import file sizes as small as possible to reduce load on SHQ servers

## Pre-use configuration

0. Optionally, but encouraged, create your own Virtual Environment (Venv) for Python. This helps avoid conflicts if you run multiple Python applications and want to ensure that this works as intended by the author. Run `python -m venv .venv` to create a virtual environment

1. Add modules required for this code by running `pip install -r requirements.txt`
2. Edit template_config.yaml and set any preferences, and add your client API keys. Save this as config.yaml

## Running the program

`python sleephq_uploader.py`

There is one main file to be concerned with:

* sleephq_uploader.py - wrapper to make the correct calls to the modules with required and optional arguments, parsed from config.yaml. Config.yaml is automatically created upon first launch of sleep_uploader. If you wish to make changes to the config.yaml, either edit the
file directly, if comfortable, or delete and recreate. Please note if you should choose to delete the config.yaml file, make a note of both the client_id and client_secret values, as you will need these again. Forgot to get them? Read "API Keys? How do I get them?" below.

There are several supporting python files, all are necessary, can be called separately and are documented with docstrings for some assistance in parsing the code and working to extend it.

These are:

* sd_copy.py - copies and maintains timestamp data of the SD Card files for the newest 'n' days
* shq_upload.py - uploads the CPAP data to SleepHQ using your Pro Account API keys
* cleanup_files.py - cleans up files from the import and upload
* generate_config_yaml.py - creates the config.yaml file, this is genericized to work with multiple scripts and can be passed a template dictionary to both capture user input for the config, and then to finalize the creation of a config.yaml (name can be passed as an argument if you wish to make it something else)

### Parameters for each module

#### sd_copy

--sd-root SD_ROOT     SD root (e.g., "E:\")
  --dest-root DEST_ROOT
                        Destination root (e.g., "C:\Users\...\LatestCPAP")
  --datalog-name DATALOG_NAME
                        DATALOG folder name (default: DATALOG)
  --settings-name SETTINGS_NAME
                        SETTINGS folder name (default: SETTINGS)
  --dry-run             Print actions without copying anything
  --verbose             Verbose logging
  --no-verify           Disable post-copy verification
  --verify-hash         Verify SHA-256 hash (slow, strongest)
  --verify-created      Verify Date created too (Windows-only)
  --time-slack TIME_SLACK
                        Allowed timestamp delta in seconds (default 3.0)

#### shq_upload

--client-id CLIENT_ID
                        Client ID API Key
  --client-secret CLIENT_SECRET
                        Client Secret API Key
  --data-path DATA_PATH
                        CPAP Data Directory
  --verbose VERBOSE     Display step-by-step processing

#### generate_config_yaml

Does not accept argparse arguments at this time

#### cleanup_files.py

Does not accept argparse arguments at this time

### API keys? Where do I get them

From [https://sleephq.com](https://sleephq.com), in the left sidebar, locate 'Account Settings' and click. Scroll the main pane to the section 'API keys' and, if none present, click the [+] button create them. You'll need both the Client UID and Client Secret. Clicking the clipboard icon will copy that particular value, so you can imediately paste it into the config.yaml file
![Screenshot of API key portion](image-1.png)

### config.yaml information

config.yaml is a file that streamlines the process of copying from SD card, uploading to SleepHQ and cleaning up runtime files. As this file is dynamically created, it is simpler to put documentation here on the parameters. It helps to be familiar with the structure of a YAML file, but that is beyond the scope of this readme.

Each option group (no indent), is for a specific module, and is self explanatory based on the name (sd_options for SD card import, upload_otpions for the SleepHQ upload module, and cleanup_options for cleanup module).

#### sd_options

copy - a Boolean (true/false) value for whether to copy the data from the card or not, default value is True
sd_path - what drive/partition/path can the SD card be located on (example: /Volumes/CPAP_Card, E:\)?
save_to_path - what path would you like to save the data under? This is a subfolder of the current working directory of the scripts. So 'LatestCPAP' when your files are located in C:\Users\Bob\Python\BreateEasy\ would save the files to C:\Users\Bob\Python\BreathEasy\LatestCPAP\
number_of_days - a number (int) of days to import, default value of 1, but can be overridden if you wish to do multiple days at once (return from vacation, forgot a few days, etc.)
verbose - a Boolean value - shows extra log messages as to what the program is doing at any given time. This can slow the execution of the application as printing to the command line, especially structured data, can add significant overhead
test_only - a Boolean value - shows the copy routines without actually copying data

#### upload_options

upload - a Boolean value - upload the data to SleepHQ
client_id - a string - Your individual SleepHQ API Client (s)ID key
client_secret - a string - Your individual SleepHQ API Client Secrety key
data_path - a string - the location where your data files reside, typically the same place you would have copied the data to (but doesn't have to be)
verbose - Boolean value - shows extra logging messages; caveats as with the above value in sd_options

#### cleanup_options

cleanup - a Boolean value - cleanup lists of files and folders related to the copy and upload processes
files - a list - list of file names to delete in the root (current working directory) folder
folders - a list - list of folder names to delete that are child folders of the current working directory

## I think I've found a bug

Very probably. Don't scream, shout or wave it about, or the REST will be GETting one too. This is a rudimentary helper to make my life easier. I replace repetitive tasks with scripts. If you care enough to fix it, please let me know

## Credits, kudos, acknowledgements

* To Bruce Elgort - whose Tweeting, Facebooking about CS50 and Python got me interested in learning more about it. This would literally not have existed without him as I always believed "I cannot write programs"
* To Uncle Nicko - for creating Sleep HQ, and providing us "hoseheads" a wonderful resource and a community to help and support each other
* To the SleepHQ:
  * Devs - for all your tireless work on the SleepHQ web app, iOS app, API documentation and just being really awesome
  * Members - for engaging in the community, and sharing knowledge and encouragement
* To anyone who reads this - It means you have found the link on the SHQ forum, and cared enough to at least check it out
