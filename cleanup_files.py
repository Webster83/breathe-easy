'''
Docstring for cleanup_files
Module to clean up generated files and folders from previous runs of a program that generates temporary data.
This is not intended to be run as a standalone script, but can be if desired by providing the lists of files
and folders to be cleaned up in the main() function.

shutil module is used to remove directories (as we want to be able to delete non-empty directories and trees), 
and os module is used to remove files.

Author: BChap
Last Revision: 20260203
'''

import os
import shutil

def cleanup_folder(folder_path:str)-> None:
    """Cleans up generated files from previous runs.
    
    :param str folder_path: The path to the folder to be removed
    
    :return: None
    """
    if os.path.exists(folder_path) and os.path.isdir(folder_path):
        shutil.rmtree(folder_path)
        print(f"Removed folder {folder_path}")
    else:
        print(f"Folder {folder_path} does not exist, skipping.")

def cleanup_files(file_list)-> None:
    """Cleans up generated files from previous runs.

    :param list file_list: A list of file paths to be removed

    :return: None
    """
    for file in file_list:
        if os.path.exists(file):
            os.remove(file)
            print(f"Removed {file}")
        else:
            print(f"{file} does not exist, skipping.")

def main()-> None:
    """Main function to clean up generated files and folders.

    :param: No parameters
    
    :return: None
    """
    # Define the folders to clean up
    folders_to_cleanup = [
        "Folder_Name",
    ]
    
    for folder in folders_to_cleanup:
        cleanup_folder(folder)
    
    # Define specific files to clean up
    files_to_cleanup = [
        "item.ext",
    ]

    for file in files_to_cleanup:
        cleanup_files([file])

if __name__ == "__main__":
    main()