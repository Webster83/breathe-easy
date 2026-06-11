'''runs robocopy on Windows to back up given folder(s) or (files) from (source)
to (destination):'''

import subprocess
import logging

logger = logging.getLogger(__name__)


def run_robocopy(source, destination, options):
    '''
    Runs a robocopy command with the given source, destination, and options.
    '''

    cmd = f'robocopy "{source}" "{destination}" {options}'
    logger.debug("Running: %s", cmd)

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )

    except (subprocess.SubprocessError, OSError) as e:
        logger.exception("Error running robocopy")
        print(f"Error running robocopy: {e}")
        return 16  # treat as failure

    rc = result.returncode

    logger.debug("Robocopy stdout:\n%s", result.stdout)
    if result.stderr:
        logger.debug("Robocopy stderr:\n%s", result.stderr)

    if rc >= 8:
        logger.error("Robocopy FAILED with code %s", rc)
    else:
        logger.info("Robocopy completed with code %s", rc)

    return rc

if __name__ == "__main__":
    # Paths
    SOURCE_FOLDER = r"LatestBiPap"
    DESTINATION_DRIVE = r"D:/"

    # 1️⃣ Copy everything except Settings without overwriting existing files
    # /E = copy subdirectories (including empty)
    # /XO = exclude older files (prevents overwriting)
    # /DCOPY:T = preserve directory timestamps
    # /COPY:DAT = copy data, attributes, timestamps
    # /R:1 /W:1 = retry once, wait 1 sec
    # /MT:12 = multithread 12
    # /XD = exclude directory
    run_robocopy(
        SOURCE_FOLDER,
        DESTINATION_DRIVE,
        '/E /XO /DCOPY:T /COPY:DAT /R:1 /W:1 /MT:12 /XD "Settings"'
    )

    # 2️⃣ Copy Settings folder with overwriting allowed
    run_robocopy(
        fr"{SOURCE_FOLDER}\Settings",
        fr"{DESTINATION_DRIVE}\Settings",
        '/E /DCOPY:T /COPY:DAT /R:1 /W:1'
    )
