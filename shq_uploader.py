import argparse
import os
from sleephq import SleepHQ

def parse_args() -> argparse.Namespace:

    '''
    parse_args uses argparse to parse command line arguments for the SleepHQ CPAP
    data upload script.
    
    :return Namespace: An argparse.Namespace object containing the parsed command line
    arguments
    '''

    p = argparse.ArgumentParser(
        description="Upload CPAP data to SleepHQ."
    )
    p.add_argument("--client-id", required=True,
                   help='SleepHQ Client ID API Key')
    p.add_argument("--client-secret", required=True,
                   help='SleepHQ Client Secret API Key')
    p.add_argument("--data-path", required=True, default="latestcpap",
                   help='CPAP Data Directory')
    p.add_argument("--verbose", required=False, default = False,
                   help='Display step-by-step processing')
    return p.parse_args()

def run_upload(client_id,client_secret,data_dir_path,verbose):
    # create SleepHQ connection
    shq = SleepHQ(client_id,client_secret,verbose)

    # create a new import
    print("Creating Import ID")
    import_id = shq.create_upload()

    # add data_dir_path to the files to import
    files = shq.SHQImports.get_files(data_dir_path)
    shq.add_files(files)

    #process the upload
    shq.process_upload()

    #finally, validate it
    shq.validate_upload()

def main():

    '''
    This function serves as the main entry point for the SleepHQ CPAP data upload script. 
    It parses command line arguments, sets up necessary paths, and orchestrates the upload
    process by calling the run_upload function
    While it exists, the script is designed to be run from the command line with the appropriate
    arguments, or called from another Python script as a wrapper function where the
    arguments can be passed directly to run_upload.
    '''

    # Parse the Arguments from the CLI or wrapper call
    args = parse_args()
    client_id = args.client_id
    client_secret = args.client_secret
    verbose = bool(args.verbose)

    # Get the current working directory. We are expecting the user CPAP data to
    # be a subfolder of this directory

    exec_dir = os.getcwd()
    data_dir_path = exec_dir + os.sep + os.path.normpath(args.data_path)

    # Run the upload logic routine
    run_upload(client_id,client_secret,data_dir_path,verbose)

if __name__ == "__main__":
    main()
