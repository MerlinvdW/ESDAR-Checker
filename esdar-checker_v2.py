"""
ESDAR-Checker should help to check for one or more up to a larger number of domains or URL's whether the following records are present:
- DMARC
- SPF
- DKIM (requires a selector)
- MX Records

@author Merlin von der Weide
@version 1.2.0-beta
@date 08.08.2024
"""
import checkdmarc
import dns.resolver
from config import update_path, get_nameserver_list
# Import Libraries for Domain specific check
# import pkg_resources
# pkg_resources.require("checkdmarc==4.4.1")


# Message Styling
from banner_message import get_banner_message as banner_message
from checkdmarc import UnverifiedDMARCURIDestination, MultipleDMARCRecords, DMARCRecordNotFound, InvalidDMARCTagValue
from csv_helper import *
from domain_validator import validate_args
from helper import remove_new_line_char, replace_characters
from terminal_message_handler import *

# Additional Imports
import argparse

selectors = []
append_new_lines = False


def initialize():
    # TODO SELECTOR MUST BE CHANGED to be able to retrieve multiple selectors
    parser = argparse.ArgumentParser(
        prog="esdar-checker_v2.py",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    domain_argument_group = parser.add_mutually_exclusive_group(required=True)
    domain_argument_group.add_argument("--domain", type=str,
                                       help="Check a single Domain (format: google.com) for DNS records (MXRecords/SPF/DKIM/DMARC")
    domain_argument_group.add_argument("--domains_file", type=str,
                                       help="File containing list of domains to check for DNS records (MXRecords/SPF/DKIM/DMARC")
    parser.add_argument("--selector", type=str, default="",
                        help="DKIM selector which is needed for DKIM record lookup")

    parser.add_argument("--append", type=str, default=False,
                        help="New checked domains are added to already the existing csv file, if no file exists a new file will be created")
    parser.add_argument("--output_path", type=str, default="resources/output/",
                        help="""File path where the result should be saved. 
                        The path has to be an absolute file path e.g /Users/[USERNAME]/ESDAR-Checker/output/
                        If a invalid path gets provided the default project output path from the Config.py file will be used""")

    arguments = parser.parse_args()
    return arguments


def main(args):
    validate_args(args)

    domains_list = []

    if args.selector:
        selectors.append(args.selector)

    if args.append == "yes":
        global append_new_lines
        append_new_lines = True
    if is_valid_path(args.output_path):
        update_path(args.output_path)
    if args.domain:
        domains_list.append(args.domain)
    else:
        with open(args.domains_file, "r") as domains_file:
            # TODO: doesnt work correctly so far, cause for false behaviour wasnt found -> TO BE FIXED SOON
            domains_file_content = domains_file.readlines()
            cleaned_domains = remove_new_line_char(domains_file_content)
            domains_list.extend(cleaned_domains)

    domains_list = cleanup_domains_list(domains_list)

    if len(domains_list) > 0:
        # TODO: no no here should only one domain get provided and after the check it should be immediatly written to the CSV otherwise if there are to many entries it will result in an stack Overflow
        raw_esdar_check_result = perform_esdar_check(domains_list)
        if append_new_lines == True:
            write_new_line_to_csv_file(raw_esdar_check_result)
        else:
            write_rows_to_csv(raw_esdar_check_result)

    else:
        print_error("No domain(s) were provided")


def is_valid_path(output_path):
    return os.path.exists(output_path)


## performs the dns security check and returns the list with the result
def perform_esdar_check(domains_list):
    iterator = 0
    single_domain_result = []
    domains_list_result = []
    try:
        for single_domain in domains_list:
            # clear the list
            single_domain_result.clear()
            # dns security check
            single_domain_result.append(single_domain)
            print("\nTesting domain %s for:" % single_domain)
            single_domain_result.append(lookup_mxrecords(single_domain))
            single_domain_result.append(lookup_spf_record(single_domain))
            single_domain_result.append(lookup_dkim_record(single_domain, selectors, iterator))
            single_domain_result.append(lookup_dmarc_record(single_domain))
            domains_list_result.append(single_domain_result.copy())
            # Iterator is needed if there are multiple domains and therefore multiple selectors for the DKIM Lookup
            iterator += 1
        return domains_list_result
    except Exception as e:
        """
        If a unhandled error occurs the already looked up URL's get written to the csv and the Script gets terminated
        """
        print("Unfixed Error / Bug occured for details read message below:\n %s" % e)
        return domains_list_result


def lookup_mxrecords(domain):
    print(" MXRecords...")
    try:
        mx_record = dns.resolver.resolve(domain, 'MX')
        mail_servers = []
        for a in mx_record:
            mail_servers.append(a)
            return mail_servers
    except:
        return "No MXRecord found."


def lookup_spf_record(domain):
    print(" SPF record...")
    try:
        txt_records = dns.resolver.resolve(domain, "TXT")
    except dns.resolver.LifetimeTimeout:
        return "Timeout! SPF could not be retrieved"
    except Exception as e:
        return "No SPF found or could not be retrieved"

    for record in txt_records:
        spf_record = "".join([a.decode("utf-8") for a in record.strings])
        if "v=spf" in spf_record:
            return spf_record


# TODO: works so far with one domain but with domain file it doesnt work atm
def lookup_dkim_record(domain, selector="", iterator=0):
    if selector:
        print(" DKIM record with selector", selector, "...")
        try:
            test_dkim = dns.resolver.resolve(selector[iterator] + '._domainkey.' + domain, 'TXT')
            for dns_data in test_dkim:
                if 'DKIM1' in str(dns_data):
                    return str(dns_data)
        except:
            return "No DKIM record found."
            pass
    return "No selector provided"


def lookup_dmarc_record(domain):
    print(" DMARC record...")
    dmarc_record_string = ""
    try:
        raw_dmarc_record = checkdmarc.get_dmarc_record(domain, nameservers=get_nameserver_list(),
                                                       timeout=10)
        dmarc_record_list = list(raw_dmarc_record.items())
        (record, location, parsed) = dmarc_record_list
        dmarc_record_string += "Record: " + record[1] + "; " + "Location: " + location[1]
        return replace_characters(dmarc_record_string)
    except DMARCRecordNotFound:
        return "A DMARC record does not exist for %s or its base domain" % domain
    except (InvalidDMARCTagValue):
        return "Tag Value Error"
    except MultipleDMARCRecords as e:
        return e
    except Exception:
        # TODO: better error handling
        return "Error: DMARC could not be retrieved"


def prepare_summary_output(security_check_result):
    # TODO
    print(" Function not implemented atm")


def print_summary_on_terminal(prepared_output):
    # TODO
    print("Function not implemented atm")


def cleanup_domains_list(domains_list):
    domains_list = [d.lower() for d in domains_list]
    domains_list = list(dict.fromkeys(domains_list))

    domains_list.sort()
    return domains_list


if __name__ == "__main__":
    print(banner_message())
    arguments = initialize()
    main(arguments)
