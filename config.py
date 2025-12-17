"""
This File is used to setup the needed Configurations which the user has to perform

RELATIVE_FILE_PATH: Provide the relative File Path which you want to use to for the Output File
E.g: resources/output/ or you can also use the absolute filepath C:/Users/[USERNAME]/PycharmProjects/ESDAR-Checker/resources/output/

@author Merlin von der Weide
@version 2.0.0
@date 2025
"""
import os

RELATIVE_FILE_PATH = "resources/output/"
# Using Google DNS and Cloudflare DNS as defaults
NAMESERVER_LIST = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]


def update_path(path: str) -> bool:
    """
    Update the output path for CSV files.
    
    Args:
        path: Path to set as output directory
        
    Returns:
        True if path was successfully updated, False otherwise
    """
    global RELATIVE_FILE_PATH
    try:
        # Normalize path separators
        normalized_path = path.replace("\\", "/")
        # Ensure path ends with /
        if not normalized_path.endswith("/"):
            normalized_path += "/"
        
        # Create directory if it doesn't exist
        os.makedirs(normalized_path, exist_ok=True)
        
        # Update global path
        RELATIVE_FILE_PATH = normalized_path
        return True
    except Exception:
        return False


def get_nameserver_list():
    """Get the list of nameservers to use for DNS lookups."""
    return NAMESERVER_LIST
