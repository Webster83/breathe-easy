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

import yaml

def gather_user_input(template:dict) -> dict:

    """
    gather_user_input ingests a dict (or dict of dicts) of a template for a desired YAML output
    then iterates through the template, gathering user values or allowing selection of identified 
    defaults. It returns a dict of the same with the user-selected values applied. 
    This dict can then be passed to generate_config_yaml to create the YAML file.
    
    :param template: template dictionary to gather user input against
    :type template: dict
    :return: User-customized dictionary based on the template
    :rtype: dict{}
    """

    # define true/false value sets for boolean conversion from user input
    # (because we don't know how they will type it)

    true_values = {'true', '1',  'yes', 'y'}
    false_values = {'false', '0', 'no', 'n'}

    # Get user preferences based on prompts for each value with a default option given from
    # the corresponding template value

    user_prefs = {}
    print("""This utility will help you generate a config.yaml file. " \
        "Please view the readme.md for details on each option."""
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

                        print(f"""Unrecognized value type for '{key}'.
                              Using default '{default_value}'."""
                              )
                        user_prefs[section][key] = default_value

                elif isinstance(default_value, int):
                    user_prefs[section][key] = int(user_input)
                elif isinstance(default_value, list):
                    user_prefs[section][key] = [item.strip() for item in user_input.split(',')]
                else:
                    user_prefs[section][key] = user_input
    return user_prefs

def generate_config_yaml(file_path: str, options: dict) -> None:
    """
    Generates a template config.yaml file for the user to customize.

    :param str file_path: The path where the config.yaml file will be created

    :return: None
    """


    with open(file_path, 'w', encoding="utf-8") as file:
        yaml.dump(options, file)

    print(f"""config.yaml has been created at {file_path}. You may change values in the file
          directly if you wish, or re-run this script to generate a new config file.""")

def main() -> None:
    """Main function to generate a template config.yaml file.

    :param: No parameters

    :return: None
    """
    template = {
        'sd_options': {
            'copy': True,
            'sd_path': 'E:/',  # What location/partition/volume is your CPAP Card?
            'save_to_path': 'LatestCPAP',  # This is a subfolder of the location where the script 
                                           # exists
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

if __name__ == "__main__":
    main()
