"""
Domain validation module for ESDAR-Checker

@author Merlin von der Weide
@version 2.0.0
@date 2025
"""
import os
import sys
import socket
from typing import List

from validators import domain as validate_domain
from terminal_message_handler import print_error, print_warning


def validate_provided_domains(domains: List[str]) -> bool:
    """
    Validate a list of domains.
    
    Args:
        domains: List of domain strings to validate
        
    Returns:
        True if all domains are valid, False otherwise
    """
    invalid_domains = []
    for domain in domains:
        if not validate_domain(domain):
            invalid_domains.append(domain)
    
    if invalid_domains:
        for invalid in invalid_domains:
            print_warning(f"Invalid domain format: {invalid}")
        return False
    
    return True


def validate_args(args) -> bool:
    """
    Validate command-line arguments.
    
    Args:
        args: Parsed command-line arguments
        
    Returns:
        True if arguments are valid, False otherwise
    """
    domain_arg_valid = True
    domain_file_arg_valid = True
    
    # Validate single domain if provided
    if args.domain:
        domain_arg_valid = validate_domain(args.domain)
        if not domain_arg_valid:
            print_warning(f"Domain '{args.domain}' is not valid. Is it formatted correctly?")
    
    # Validate domain file if provided
    if args.domains_file:
        domain_file_arg_valid = os.path.isfile(args.domains_file)
        if not domain_file_arg_valid:
            print_warning(f"Domain file '{args.domains_file}' does not exist or is not accessible.")
    
    valid_args = domain_arg_valid and domain_file_arg_valid
    if not valid_args:
        print_error("Arguments are invalid. Please check your input.")
        sys.exit(1)
    
    return valid_args


def check_domain_exists(domain: str) -> bool:
    """
    Check if a domain exists by attempting DNS resolution.
    
    Args:
        domain: Domain name to check
        
    Returns:
        True if domain resolves, False otherwise
    """
    try:
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, socket.error):
        return False

