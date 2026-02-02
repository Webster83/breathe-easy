# sleephq_uploader Readme

## Purpose

To streamline import of ResMed Air 11 device data to SleepHQ and keep the import file sizes as small as possible to reduce load on SHQ servers

## Usage

Optionally, create your own Virtual Environment (Venv) for Python. This helps avoid conflicts if you run multiple Python applications and want to ensure that this works as intended by the author

Add modules required for this code by running `pip install -r requirements.txt`
Edit config.yaml and set any preferences, and add your client API keys
Run sleephq_uploader.py with Python

There are 3 main files to be concerned with:

* sleephq_uploader.py - wrapper to make the correct calls to the modules with required and optional arguments, parsed from config.yaml
* sd_copy.py - copies and maintains timestamp data of the SD Card files for the newest 'n' days
* shq_upload.py - uploads the CPAP data to SleepHQ using your Pro Account API keys
* template_config.yaml - Sets options for both the above files, and save as "config.yaml"

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

### API keys? Where do I get them

From [https://sleephq.com](https://sleephq.com), in the left sidebar, locate 'Account Settings' and click. Scroll the main pane to the section 'API keys' and, if none present, click the [+] button create them. You'll need both the Client UID and Client Secret. Clicking the clipboard icon will copy that particular value, so you can imediately paste it into the config.yaml file
![Screenshot of API key portion](image-1.png)

## I think I've found a bug

Very probably. Don't scream, shout or wave it about, or the REST will be GETting one too. This is a rudimentary helper to make my life easier. I replace repetitive tasks with scripts. If you care enough to fix it, please let me know

## Credits, kudos, acknowledgements

* To Bruce Elgort - whose Tweeting, Facebooking about CS50 and Python got me interested in learning more about it. This would literally not have existed without him as I always believed "I cannot write programs"
* To Uncle Nicko - for creating Sleep HQ, and providing us "hoseheads" a wonderful resource and a community to help and support each other
* To the SleepHQ: 
    * Devs - for all your tireless work on the SleepHQ web app, iOS app, API documentation and just being really awesome
    * Members - for engaging in the community, and sharing knowledge and encouragement
* To anyone who reads this - It means you have found the link on the SHQ forum, and cared enough to at least check it out
