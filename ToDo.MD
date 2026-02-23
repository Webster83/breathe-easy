# To Do

An unsorted list of what may be down the line

## sd_copy.py

Add a card backup parameter that creates a full/delta backup of the card data.

## New modules / offshoot ideas

* Look into possible "scriptability" of OSCAR importing, as some may wish to use both (or may not be SHQ pro members---though they should be!)
* RYO "magic uploader" with dual WIFI adapters. I could have built-in wifi be EzSh@re connected and the add-on wifi card be perma-connected to home wifi. Would love to work with SHQ devs on this idea, it would add extra cost to MU (MU ProPlus?), but open MU platform to be a host/server for other things

## To Done..s

Knocked these of the list:

### All modules

Finish docstrings for each function definition

### Build a configuration generator support script

This allows for the main application script to call for config.yaml creation if it does not exist rather than force the user out
of context to create one, or revert to argparse (which is just mean when there are lots of necessary parameters)

### Get EZSh@re SD card import working with automated wifi switching

Yeah, this one was a doozy. Making sure that all the casing was correct and the STR.edf file was cased exactly that, even though
the file is created as STR.EDF by the machine but the web importer doesn't like that :\ Turns out windows timestamps in copy operations
are a PAIN... In... The... Ass to deal with

### Get everything linter'd (PEP8)

We're cooking with Pylint!
