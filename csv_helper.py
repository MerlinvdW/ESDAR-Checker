"""
CSV Helper Module for ESDAR-Checker
Handles CSV file operations for reading and writing DNS check results

@author Merlin von der Weide
@date 2025
@version 2.0.0
"""
import csv
import os
from typing import List, Dict, Any

import config
from terminal_message_handler import print_error, print_warning

OUTPUT_FILENAME = "esdar-check_result.csv"


def get_output_filepath() -> str:
    """Get the full path to the output CSV file."""
    return os.path.join(config.RELATIVE_FILE_PATH, OUTPUT_FILENAME).replace("\\", "/")


def create_csv_file_with_header(filepath: str) -> bool:
    """
    Create a new CSV file with headers.
    
    Args:
        filepath: Full path to the CSV file
        
    Returns:
        True if successful, False otherwise
    """
    headers = ["Domain", "MX Record", "SPF Record", "DKIM Record", "DMARC Record"]
    
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            writer.writerow(headers)
        return True
    except PermissionError:
        print_error(f"Cannot write to {filepath} - file is open in another program. Please close it and try again.")
        return False
    except Exception as e:
        print_error(f"Error creating CSV file: {str(e)}")
        return False


def write_results_to_csv(results: List[Dict[str, Any]], append: bool = False) -> bool:
    """
    Write DNS check results to CSV file.
    
    Args:
        results: List of dictionaries containing DNS check results
        append: If True, append to existing file; if False, overwrite
        
    Returns:
        True if successful, False otherwise
    """
    if not results:
        print_warning("No results to write to CSV")
        return False
    
    filepath = get_output_filepath()
    
    # Check if file exists
    file_exists = os.path.isfile(filepath)
    
    # Define headers
    headers = ["Domain", "MX Record", "SPF Record", "DKIM Record", "DMARC Record"]
    
    try:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Determine mode and whether to write header
        if append:
            # Append mode: only write header if file doesn't exist
            mode = 'a'
            write_header = not file_exists
        else:
            # Overwrite mode: always write header
            mode = 'w'
            write_header = True
        
        with open(filepath, mode=mode, newline='', encoding='utf-8') as file:
            writer = csv.writer(file, delimiter=',', quoting=csv.QUOTE_MINIMAL)
            
            # Write header if needed
            if write_header:
                writer.writerow(headers)
            
            # Write results
            for result in results:
                # Extract values from result dictionary
                domain = result.get('domain', '')
                mx = result.get('mx', '')
                spf = result.get('spf', '')
                dkim = result.get('dkim', '')
                dmarc = result.get('dmarc', '')
                
                # Write row - each value in its own column
                writer.writerow([domain, mx, spf, dkim, dmarc])
        
        print(f"Results written to {filepath}")
        return True
        
    except PermissionError:
        print_error(f"Cannot write to {filepath} - file is open in another program. Please close it and try again.")
        return False
    except Exception as e:
        print_error(f"Error writing to CSV file: {str(e)}")
        return False


def read_domains_from_file(filepath: str) -> List[str]:
    """
    Read domains from a text file (one domain per line) or CSV file.
    Tries multiple encodings to handle different file formats.
    
    Args:
        filepath: Path to the input file
        
    Returns:
        List of domain names
    """
    domains = []
    
    if not os.path.isfile(filepath):
        print_error(f"File not found: {filepath}")
        return domains
    
    # List of encodings to try (in order of preference)
    encodings_to_try = ['utf-8', 'utf-8-sig', 'latin-1', 'iso-8859-1', 'windows-1252', 'cp1252']
    
    for encoding in encodings_to_try:
        try:
            with open(filepath, 'r', encoding=encoding) as file:
                # Try to detect if it's a CSV file
                first_line = file.readline().strip()
                file.seek(0)  # Reset to beginning
                
                # If first line looks like CSV header, skip it
                if ',' in first_line and ('domain' in first_line.lower() or 'url' in first_line.lower()):
                    # It's a CSV file
                    reader = csv.reader(file)
                    next(reader, None)  # Skip header
                    for row in reader:
                        if row and row[0].strip():
                            domains.append(row[0].strip())
                else:
                    # It's a plain text file (one domain per line)
                    for line in file:
                        domain = line.strip()
                        # Skip empty lines and comments
                        if domain and not domain.startswith('#'):
                            domains.append(domain)
            
            # If we got here, the file was read successfully
            return domains
            
        except UnicodeDecodeError:
            # Try next encoding
            continue
        except Exception as e:
            # For other errors, try next encoding but log a warning
            if encoding == encodings_to_try[-1]:
                # Last encoding failed, show error
                print_error(f"Error reading domains from file: {str(e)}")
                return domains
            continue
    
    # If all encodings failed
    print_error(f"Could not read file {filepath} with any supported encoding")
    return domains


def write_single_result_to_csv(result: Dict[str, Any], append: bool = True) -> bool:
    """
    Write a single DNS check result to CSV file (useful for processing domains one by one).
    
    Args:
        result: Dictionary containing DNS check result for one domain
        append: If True, append to existing file; if False, overwrite
        
    Returns:
        True if successful, False otherwise
    """
    return write_results_to_csv([result], append=append)
