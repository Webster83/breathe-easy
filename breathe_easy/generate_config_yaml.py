"""
generate_config_yaml.py

Provides a user-interaction driven method of creating a config.yaml file, obfuscating
the need for the user to understand the markup language, while affording the 
developer the flexibility of a more rich configuration document than a straight
config.ini type file.

Usage: pass a template dictionary to the gather_user_input function, which will iterate through
the template, prompting for the various values. A completed dictionary can then be passed to 
generate_config_yaml along with an output path to create the desired config.yaml

Author: BChap
Last Updated: 20260222
"""

import sys
import time
import logging

from pathlib import Path
from ruamel.yaml import YAML

# ----- initalize logging -----
logger = logging.getLogger(name=__name__)

def gather_user_input(config,path=""):

    '''
    Walks through the config (loaded from YAML) and updates values in-place.
    Preserves comments when used with ruamel.yaml.
    '''

    true_values = {'true', '1', 'yes', 'y'}
    false_values = {'false', '0', 'no', 'n'}

    if path == "":
        print(
            "This utility will help you generate a config.yaml file.\n"
            "Please view the readme.md for details on each option."
        )

    for key, value in config.items():
        current_path = f"{path}.{key}" if path else key

        if isinstance(value, dict):
            print(f"\n--- {current_path} ---")
            gather_user_input(value, current_path)

        elif isinstance(value, list):
            user_input = input(
                f"Enter comma-separated values for '{current_path}' (default: {value}): "
            ).strip()

            if user_input:
                config[key] = [item.strip() for item in user_input.split(",")]

        else:
            user_input = input(
                f"Enter value for '{current_path}' (default: '{value}'): "
            ).strip()

            if user_input == "":
                continue  # keep existing value

            # Type handling
            if isinstance(value, bool):
                s = user_input.lower()
                if s in true_values:
                    config[key] = True
                elif s in false_values:
                    config[key] = False
                else:
                    print(f"Invalid boolean, keeping default {value}")

            elif isinstance(value, int):
                try:
                    config[key] = int(user_input)
                except ValueError:
                    print(f"Invalid int, keeping default {value}")

            elif isinstance(value, float):
                try:
                    config[key] = float(user_input)
                except ValueError:
                    print(f"Invalid float, keeping default {value}")

            else:
                config[key] = user_input

    return config

def make_config(template='template.yaml'):
    '''makes the config from the specified template yaml file'''
    yaml = YAML()
    with open(template, encoding='utf-8') as t:
        config = yaml.load(t)
        config = gather_user_input(config)
        generate_config_yaml('config.yaml',config)

def generate_config_yaml(file_path: str, config) -> None:
    '''generates the config.yaml'''
    yaml = YAML()

    with open(file_path, "w", encoding='utf-8') as cfg:
        yaml.dump(config, cfg)

    print(f"config.yaml has been created at {file_path}.")

def prune_keys(file_path: str = "config.yaml", key_paths: list | None = None) -> bool:

    '''
    Removes keys from a YAML config using path-based targeting.


    :param file_path: Path to config.yaml
    :param key_paths: List of key paths to remove
                      Example:
                      [
                            ["options", "key"],
                            ["options", "program_options", "key"]
                      ]
    :return bool: True / False on changes made
    '''

    yaml = YAML()
    config_file = Path(file_path)
    change_made = False

    # Load config or initialize empty

    try:
        with open(config_file, "r", encoding="utf-8") as f:
            config = yaml.load(f) or {}
    except FileNotFoundError:
        logger.error("Config file was not found: %s", file_path)
        raise FileNotFoundError

    if not key_paths:
        print("No key paths provided, nothing to prune.")
        return change_made #No change made

    for path in key_paths:
        current = config

        # Traverse to parent of target key
        for key in path[:-1]:
            if key not in current or not isinstance(current[key], dict):
                current = None
                break
            current = current[key]

        # Delete the key if reachable
        if current and path[-1] in current:
            logger.info("Deleting %s",".".join(path) )
            del current[path[-1]]
            print(f"Removed: {'.'.join(path)}")
            change_made = True

    # Write back
    if change_made: # Return True
        logger.info("Writing changes to %s",file_path)
        with open(config_file, "w", encoding="utf-8") as f:
            yaml.dump(config, f)
        return True
    else:
        logger.info("No changes made as keys to prune were not found")
        return change_made # value False (no changes made)

def update_config(file_path:str, key_path: list, value):

    '''
    Updates or creates a key in an existing YAML config file

    :param file_path: Path to config.yaml
    :param key_path: List of nested keys (eg ['shq', 'bearer_token'])
    :param value: value to set
    '''

    yaml = YAML()
    config_file = Path(file_path)

    # Load existing config
    if config_file.exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.load(f) or {}
    else:
        config = {}

    current = config
    for key in key_path[:-1]:
        if key not in current or not isinstance(current[key],dict):
            current[key] ={}
        current = current[key]

    current[key_path[-1]] = value
    with open(config_file,'w',encoding='utf-8') as f:
        yaml.dump(config,f)
    print(f"Updated: {'.'.join(key_path)} = {value}")

# ----- LEGACY CODE BLOCK -----
# documented for historical "how I did something"
# pylint: disable= all
# PyYAML-based, but moved to ruamel for commented YAML templates
if False: # type: ignore
    def old_generate_config_yaml(file_path: str, options: dict) -> None: # type: ignore
        '''
        Generates a template config.yaml file for the user to customize.

        :param str file_path: The path where the config.yaml file will be created

        :return: None
        '''


        with open(file_path, 'w', encoding="utf-8") as file:
            yaml.dump(options, file)

        print(f"config.yaml has been created at {file_path}. You may change values in the file "\
            "directly if you wish, or re-run this script to generate a new config file.")

    def old_main() -> None: # type: ignore
        '''Main function to generate a template config.yaml file.

        :param: No parameters

        :return: None
        '''
        template = {
            'sd_options': {
                'copy': True,
                'sd_path': 'E:/',  # What location/partition/volume is your CPAP Card?
                'save_to_path': 'LatestCPAP',  # This is a subfolder of the location 
                                               # where the script exists
                'number_of_days': 1,  # newest number of days to copy
                'verbose': False,  # show extra logging
                'test_only': False,  # set to true to only simulate the copy without doing so
            },
            'upload_options': {
                'upload': True,
                'client_id': 'Put Client ID value here',  # get this value from Sleep HQ API keys.
                                                        # See Readme.MD
                'client_secret': 'Put Client Secret here',  # get this value from Sleep HQ API keys. 
                                                            # See Readme.MD
                'data_path': 'LatestCPAP',  # This is  a subfolder of the location where the python
                                            # files exist.
                'verbose': False,  # show extra logging
            },
            'cleanup_options': {
                'cleanup': False,  # Set to true to enable cleanup of generated files and folders
                'files': [],  # List of specific files to clean up
                'folders': [],  # List of specific folders to clean up
            }
        }

        # Make it one line, as we will likely be calling this as an embedded module now rather
        # than standalone
        generate_config_yaml('config.yaml', gather_user_input(template=template))

    def old_gather_user_input(template:dict) -> dict: # type: ignore

        '''
        gather_user_input ingests a dict (or dict of dicts) of a template for a desired YAML output
        then iterates through the template, gathering user values or allowing selection of identified 
        defaults. It returns a dict of the same with the user-selected values applied. 
        This dict can then be passed to generate_config_yaml to create the YAML file.

        :param template: template dictionary to gather user input against
        :type template: dict
        :return: User-customized dictionary based on the template
        :rtype: dict{}
        '''

        # define true/false value sets for boolean conversion from user input
        # (because we don't know how they will type it)

        true_values = {'true', '1',  'yes', 'y'}
        false_values = {'false', '0', 'no', 'n'}

        # Get user preferences based on prompts for each value with a default option given from
        # the corresponding template value

        user_prefs = {}
        print('''This utility will help you generate a config.yaml file. " \
            "Please view the readme.md for details on each option.'''
            )

        for section, params in template.items():
            user_prefs[section] = {}
            print(f"\nThe following values are for configuring options for {section}:\n")
            for key, default_value in params.items():
                user_input = input(f"Enter value for '{key}' (default: '{default_value}'): ").strip()
                if user_input == '':
                    user_prefs[section][key] = default_value
                else:
                    # Convert to appropriate type based on the type of the default value
                    if isinstance(default_value, bool):
                        s = user_input.strip().lower()
                        if s in true_values:
                            user_prefs[section][key] = True
                        elif s in false_values:
                            user_prefs[section][key] = False
                        else:
                            # if they typed something not expected, fall back to default,
                            # as default value will generally do what is desirable

                            print(f"Unrecognized value type for '{key}'."\
                                 "Using default '{default_value}'."
                                )
                            user_prefs[section][key] = default_value

                    elif isinstance(default_value, int):
                        user_prefs[section][key] = int(user_input)
                    elif isinstance(default_value, list):
                        user_prefs[section][key] = [item.strip() for item in user_input.split(',')]
                    else:
                        user_prefs[section][key] = user_input
        return user_prefs

# ----- no main catcher

if __name__ == "__main__":
    print("This script is not intended to run directly. See README.md")
    logger.error("Script executed directy. Not supported. See README.md")
    time.sleep(5)
    sys.exit(1)
