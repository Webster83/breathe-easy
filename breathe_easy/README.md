# Readme

<!-- markdownlint-disable MD033 -->

<p align="center">
  <img src="https://via.placeholder.com/900x200?text=Breathe+Easy" alt="Breathe_Easy Banner" />
</p>

<h1 align="center">Breathe_Easy</h1>

<p align="center">
  Streamlined PAP data extraction and SleepHQ upload for ResMed Air11
</p>

<p align="center">
  <img src="https://img.shields.io/pypi/v/breathe-easy?label=PyPI" alt = "PyPi badge"/>
  <img src="https://img.shields.io/pypi/pyversions/breathe-easy" alt = "version badge"/>
  <img src="https://img.shields.io/github/license/Webster83/breathe-easy" alt = "license badge"/>
  <img src="https://img.shields.io/github/issues/Webster83/breathe-easy" alt = "issues badge"/>
  <img src="https://img.shields.io/github/stars/Webster83/breathe-easy?style=social" alt = "stars badge"/>

</p>

<!-- markdownlint-enable MD033 -->

## Purpose

breathe_easy streamlines extracting data from a ResMed AirSense 11 (xPAP) SD card—either via EZ-Sh@re WiFi SD or a local card reader—and uploading it to SleepHQ.

## Quick Start (TL;DR)

1. Install:
`pip install breathe_easy`

2. Run:
`breathe_easy`

3. Enter your SleepHQ API credentials when prompted, and complete the rest of the guided setup

4. Make sure your SD card (reader) is connected or EZ-Sh@re Wifi SD wireless network is in range

5. For first run, you'll be prompted to set a mask, and optionally set it as default (so next time it's a "start and walk away" experience)

6. That's it! Your latest data will upload automagically (automatically)

## Pre-Use configuration

0. Optional, but highly recommended, set up a virtual environment (venv) for Python on your own computer. This helps avoid conflicts if you run multiple Python applications and want to ensure that this works as intended by the author. Run `python -m venv .venv` to create a virtual environment
1. Have your API keys to hand from SleepHQ. In order to have these keys you must be a Pro member, or under a Pro trial. See SleepHQ.com for more information
2. In a command-line terminal instance (cmd.exe, powershell, windows Terminal app), run `pip install breathe_easy` to download and install breathe_easy. Being in an active venv is once again, encouraged, as the developer has tested against specific versions of python libraries, and cannot verify that older or newer versions of these won't break something

## Running breathe_easy

1. breathe_easy can be run straight from your command-line via `breathe_easy`  
The following args are supported:

   | Option | Description |
   | ------ | ----------- |
   | `-ru`, `--reset_user` | Reset SleepHQ User Configuration |
   | `-ra`, `--reset_all` | Delete config.yaml (resets everything) |
   | `no_run` (optional argument) | Skip execution after reset |

   Since breathe_easy leverages argparse, you can also use `breathe_easy -h` to launch the help dialog.

1. On first run, breathe_easy will detect that config.yaml does not exist and will generate it using your inputs before executing the main program.

1. Stay nearby, as you will be prompted to choose a mask used for the night. **PROTIP:** Set this as default to enable a "start and walk away" workflow for future uploads.

1. That's it—the rest is self-explanatory. By default, 1 day's data is retrieved from the SD card. That value can be changed to any valid integer.

1. Profit? Remember the first rule of acquisition!

> WARNING:  
> Setting `number_of_days` too high may cause failures if the data does not exist on the SD card.

### config.yaml

The following is the template for config.yaml. The inline '#' comments provide information on what each item and value does

#### global_options

  ```yaml
  save_to_path: Latest_xPAP_Data  # Which subfolder stores CPAP data  
  download_from_ezshare: true     # If false, use local SD copy instead  
  copy_from_local_sd_card: false  # Useful if failure was upload-related  
  number_of_days: 1               # Number of nights of data to copy  
  cleanup_after_upload: false     # Delete temp folder after upload?
  ```  

#### cleanup_options

  ```yaml
  files: []     # Files to remove during cleanup  
  folders: []   # Folders to remove during cleanup
  ```

#### sd_options

  ```yaml
  sd_path: "f:/"     # CPAP card mount point  
  test_only: false   # Dry run (no actual copying)
  ```

#### shq_options

  ```yaml
  client_id: "your SleepHQ Client ID goes here"  
  client_secret: "your SleepHQ Client Secret goes here"
  ```

#### ezshare

  ```yaml
  ip_address: 192.168.4.1   # EZShare card IP address  
  dir: "dir=A:"              # Directory query string  
  card_ssid: "ez share"      # WiFi name  
  card_wpa2: "88888888"      # WiFi password currently not used by the program due to windows wifi "oddities"  
  home_ssid: "OurHouse"  
  home_wpa2: "InTheMiddleOfOurStreet"  # currently not used by the program due to windows wifi "oddities"  
  overwrite: true            # Overwrite existing folders?
  ```

#### Options not in the template (advanced or programmatic)

\- under 'shq_options': no_shq_upload (does not do the upload to SleepHQ). This is a boolean value and can be entered as `no_shq_upload: true` (or false). 'false' is the assumed/absent state. Note that in YAML, boolean values are lower case, and Python works with 'True' and 'False'. Take special care to follow the correct casing.  
\- also under 'shq_options':  
values that will populate once run with an upload. The author STRONGLY recommends against editting these values beyond an erase. Limited error checking takes place and unexpected values may break execution.
\- under 'global_options': debug. A boolean value that controls logging statements for (LOTS OF) debug messages (Logging.setLevel(DEBUG)). A lot of "under the hood" process info and variable state data is there. This flag should generally not be set unless you're experiencing issues and want to get more specific information to log an 'Issue' on the Git.

## Platform Notes

- WiFi functionality has only been tested on Windows
- Support for Linux and macOS is not currently implemented
- Managing multiple WiFi adapters on Windows (e.g., simultaneous EZ-Sh@re + home network connections) can be unreliable due to OS limitations

## Thanks, Credits, etc

- To Bruce Elgort - whose Tweeting, Facebooking about CS50 and Python got me interested in learning more about it. This would literally not have existed without him as I always believed "I cannot write computer programs"
- To Uncle Nicko - for creating Sleep HQ, and providing us "hoseheads" a wonderful resource and a community to help and support each other
- To the SleepHQ:
  - Devs - for all your tireless work on the SleepHQ web app, iOS app, API documentation and just being really awesome. A special 'shout out' to Addsy for fixing a mask api issue and adding functionality that really improves the default mask experience (newest used masks first, based on 'last used date')
  - Members - for engaging in the community, and sharing knowledge and encouragement
- To anyone who reads this - It means you have found the link on the SHQ forum, and cared enough to at least check it out

## Troubleshooting

### Upload fails

- Verify SleepHQ API keys
- Check internet connection
- visit sleephq.com to check the site is up

### SD card not detected

- Confirm correct `sd_path`
- Ensure the card is mounted

### EZ-Sh@re not working

- Verify you can connect to the EZ-Sh@re WiFi network
- Confirm access to the device IP address
- Test: [http://192.168.4.1/dir?dir=A:](http://192.168.4.1/dir?dir=A:)

### Debug mode

Set:  
`debug: true`  
in the global_options section of config.yaml

## Changelog

v1->v2: A complete overhaul of code. wifi helper remains static, as does the copy routine, but entirely new library with dataclasses, generic functions and numerous performance/efficiency/optimization to improve the user (and backend) experience. The config_yaml generator also gained new functionality and a revamped template process, now leveraging ruamel to maintain inline comments. Not to be entirely negative of v1, it was was a great start and I learned a lot from "eating my own cooking" with all the "ugh, this sucks" when I'd run into a transport issue, or was in the middle of an upload and didn't know where something had failed (and tracebacks were not specific enough to drill into the exactitude of the error/issue).

From now on change log will be in newest order with greater alignment to the standard x.y.z structure. This truly qualifies as a main release as the complete logic change in the underpinnings broke a "heckuvalot" so trying to do any code reuse for something leveraging the library would be impossible (sorry, not sorry)
