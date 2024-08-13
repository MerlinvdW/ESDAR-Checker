"""
@author Merlin von der Weide
@version 1.2.0-beta
@date 08.08.2024
"""
import csv
import os
import sys

import config

OUTPUT_FILENAME = "esdar-check_result.csv"


def prepare_csv_output(security_check_result):
    # TODO: Design the output for the CSV output.
    return security_check_result


def create_new_csv_file_with_header():
    # Define the headers for the CSV file
    headers = ["URL", "MX Record", "SPF Record", "DKIM Record", "DMARC Record"]

    os.makedirs(os.path.dirname(config.RELATIVE_FILE_PATH + OUTPUT_FILENAME), exist_ok=True)
    # Try open the file and write output, if not working file is opened in OS and has to be closed before
    try:
        with open(config.RELATIVE_FILE_PATH + OUTPUT_FILENAME, mode='w', newline='') as file:
            writer = csv.writer(file, delimiter=",")

            # Write the headers to the CSV file
            writer.writerow(headers)
    except:
        print(
            "can't write header because %s is open or another error occured." % (config.RELATIVE_FILE_PATH + OUTPUT_FILENAME))
        sys.exit(1)


def write_rows_to_csv(prepared_output):
    """
        Writes URL information to a CSV file.

        Parameters:
        url_info_list (list of lists): A list where each element is a String (TODO: check if this is true) containing information about the DNS records.
        """

    if not os.path.isfile(config.RELATIVE_FILE_PATH + OUTPUT_FILENAME):
        os.makedirs(os.path.dirname(config.RELATIVE_FILE_PATH + OUTPUT_FILENAME), exist_ok=True)
        create_new_csv_file_with_header()

    # Try open the file and write output, if not working file is opened in OS and has to be closed before
    try:
        with open(config.RELATIVE_FILE_PATH + OUTPUT_FILENAME, mode='w', newline='') as file:
            writer = csv.writer(file, delimiter=",")
            # Add header Row
            # Define the headers for the CSV file
            headers = ["URL", "MX Record", "SPF Record", "DKIM Record", "DMARC Record"]
            writer.writerow(headers)
            # Write the URL information to the CSV file
            if len(prepared_output) > 1:
                for url_info in prepared_output:
                    writer.writerow(url_info)
            else:
                writer.writerow(prepared_output)
    except:
        print(
            "can't write output because %s is open, close the file and run the script again." % (
                    config.RELATIVE_FILE_PATH + OUTPUT_FILENAME))
        sys.exit(1)


def write_new_line_to_csv_file(lines_to_add):
    # Try to open the file and append output
    if not os.path.isfile(config.RELATIVE_FILE_PATH + OUTPUT_FILENAME):
        create_new_csv_file_with_header()
    try:
        with open(config.RELATIVE_FILE_PATH + OUTPUT_FILENAME, mode='a', newline='') as file:
            writer = csv.writer(file, delimiter=",")
            # Append the new URL information to the CSV file
            if len(lines_to_add) > 1:
                for line_to_add in lines_to_add:
                    writer.writerow(line_to_add)
            else:
                writer.writerow(lines_to_add)
    except Exception as e:
        print(
            f"Can't append output because {config.RELATIVE_FILE_PATH + OUTPUT_FILENAME} is open, close the file and run the script again.")
        sys.exit(1)
