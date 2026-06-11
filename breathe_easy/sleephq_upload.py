'''sleephq_upload.py
handles the upload of data to sleephq, and sets user preferences for import
'''

import logging
import sys
import time

from breathe_easy.generate_config_yaml import update_config
from breathe_easy.models import SleepHQAPIAuthCredentials
from breathe_easy.sleephq import SleepHQ as shq

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

def sleephq_upload(global_params:dict,upload_params:dict):

    '''
    sleephq_upload uploads the files in a specified folder (given in global_params)
    using credential information passed via upload_params

    :param dict global_params: a dictionary of global paramters
    :param dict upload_params: a dictionary of upload parameters
    '''

    if global_params == {}:
        logging.warning("run_breathe_easy(): global_params is empty. This shouldn't be the case\n" \
        "continuing execution may cause unintended consequences")
    if upload_params == {}:
        logging.warning("run_breathe_easy(): upload_params is empty. This shouldn't be the case\n" \
        "continuing execution may cause unintended consequences")

    creds = SleepHQAPIAuthCredentials(upload_params['client_id'], upload_params['client_secret'])
    client = shq('https://sleephq.com/api',credentials=creds,debug = global_params['debug'])
    bearer = upload_params.get('bearer')

    #----- load bearer or authenticate -----
    if bearer:
        print("Using stored bearer %s",bearer)
        creds.bearer_token = bearer
        client.session.headers.update(
            {"Authorization": f"Bearer {bearer}"
            }
        )

    else:
        client.authenticate()
        print("Bearer Token not found in config.yaml\n"\
              "performing authentication with SleepHQ")

        bearer = getattr(creds,'bearer_token')

        if not bearer:
            print('Error authenticating. See log for details')
            logger.error("Authentication failed, client.bearer token is: %s",bearer)
            sys.exit(1)

    #----- load user profile or call to retreive -----

    team_id = upload_params.get('team_id')
    default_mask = upload_params.get('default_mask_id')
    name = upload_params.get('name')
    logger.info("User info found in config:\n %s\nteam id:%s\n,default_mask_id:%s"
                 ,name,team_id,default_mask)

    profile = None # init profile to avoid "possibly unbound"
                   # Logically either both team_id and mask_id
                   # exist or either one or both do not exist

    if team_id and default_mask and name:
        logger.info("All SHQ data in config, setting profile...")
        profile = client.set_profile(
            name=name,
            team_id = team_id,
            mask_id = default_mask
            )
    else:
        logger.info("Incomplete user info, retrieving from SleepHQ...")
        # we need to get the profile because either:
        # any combination of these is missing:
        # name, team id and mask id
        profile = client.get_profile()

        if profile is None:
            print("Failed to get a valid profile. See log for details")
            logger.error("Profile fetch failed. Profile is %s",profile)
            raise RuntimeError('Failed to fetch profile from SleepHQ')

        name = getattr(profile, "user_name")
        if name:
            print(f"Storing {name} for persistent usage")
            update_config('config.yaml',['shq_options','name'],name)

        team_id = getattr(profile,"current_team_id")
        if team_id:
            print(f'Storing {team_id} for persistent usage')
            update_config('config.yaml',['shq_options','team_id'],team_id)
        else:
            print(f"Cannot store {team_id}")

    set_mask_in_config = False

    if default_mask: # gotta check to make sure the mask is still a
                     # valid mask (did you delete it?):
        if not client.is_valid_mask(default_mask,profile=profile): # caught a bad mask
            set_mask_in_config = client.set_mask(profile)

    if not default_mask: # default mask is set to None or key does not exist
        client.get_masks(profile)
        set_mask_in_config = client.set_mask(profile=profile)

    if set_mask_in_config: # So a mask has been assigned
                           # with user response 'Y' to set as default

        default_mask = getattr(profile,"user_default_mask_id", None)
        if isinstance(default_mask,int): #sanity check
            print(f"Setting {default_mask} as default for future uploads")
            update_config('config.yaml',['shq_options','default_mask_id'],default_mask)
        else:
            print("Default mask ID not set. See log for details.\n" \
                "Continuing without saving preference")
            logger.error("Could not set default mask ID. mask_id: %s",
                          default_mask
                        )

    print("Creating import ID")
    shq_import = client.create_import(profile)
    shq_import.import_id = client.get_import_id(shq_import)
    print("Import ID created")

    print("Creating list of files to upload...")
    client.create_file_queue(
       global_params['save_to_path'],
       import_id=shq_import.import_id
    )
    logger.debug("Contents of file_queue:")
    for file in client.config.file_queue:
        logger.debug("%s",file.name)

    client.upload_files(shq_import)
    print("Proccessing import...")
    client.process_import(shq_import)
    print("Validating import...")
    client.validate_import(shq_import)
    print("Storing Bearer in config.yaml for use until expiration")
    update_config('config.yaml',['shq_options','bearer'],creds.bearer_token)
    print("All SleepHQ operations completed. " \
    "Updated data should be available soon at https://sleephq.com")

if __name__ == "__main__":
    print("This file is designed to run as an import only. See"\
          " README.md")
    time.sleep(5)
    sys.exit(1)
