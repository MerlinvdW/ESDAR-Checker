"""
ESDAR-Checker (Email Security DNS Advanced Records Checker)
Checks one or more domains for DNS security records:
- DMARC
- SPF
- DKIM (requires selector(s))
- MX Records

@author Merlin von der Weide
@version 2.0.0
@date 2025
"""
import argparse
import sys
from typing import List, Optional

from banner_message import get_banner_message as banner_message
from dns_lookup import perform_complete_dns_check
from csv_helper import write_results_to_csv, read_domains_from_file
from domain_validator import validate_args
from helper import cleanup_domains_list
from terminal_message_handler import (
    print_error, print_warning, print_info, print_success,
    print_found, print_not_found, print_partial
)


def initialize_parser() -> argparse.ArgumentParser:
    """Initialize and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="esdar-checker_v2.py",
        description="Email Security DNS Advanced Records Checker - Check domains for DMARC, SPF, DKIM, and MX records",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Domain input (mutually exclusive)
    domain_argument_group = parser.add_mutually_exclusive_group(required=True)
    domain_argument_group.add_argument(
        "--domain",
        type=str,
        help="Check a single domain (format: google.com) for DNS records (MX/SPF/DKIM/DMARC)"
    )
    domain_argument_group.add_argument(
        "--domains_file",
        type=str,
        help="File containing list of domains to check (one per line or CSV with domain in first column)"
    )
    
    # DKIM selectors
    parser.add_argument(
        "--selector",
        type=str,
        default="",
        help="Single DKIM selector to check (e.g., 'default', 'google')"
    )
    parser.add_argument(
        "--selectors",
        type=str,
        default="",
        help="Multiple DKIM selectors separated by comma (e.g., 'default,google,selector1')"
    )
    parser.add_argument(
        "--auto_discover_dkim",
        action="store_true",
        help="If no DKIM selector is provided, automatically test common selectors (default, dkim, mail, email, etc.)"
    )
    
    # Output options
    parser.add_argument(
        "--append",
        type=str,
        default="no",
        choices=["yes", "no"],
        help="Append results to existing CSV file instead of overwriting"
    )
    parser.add_argument(
        "--output_path",
        type=str,
        default=None,
        help="Absolute path for output CSV file. If not provided, uses path from config.py"
    )
    
    # Advanced options
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="DNS query timeout in seconds"
    )
    parser.add_argument(
        "--skip_errors",
        action="store_true",
        help="Continue processing other domains if one fails (default: stop on first error)"
    )

    return parser


def parse_selectors(selector_arg: str, selectors_arg: str) -> List[str]:
    """
    Parse selector arguments into a list.
    
    Args:
        selector_arg: Single selector from --selector
        selectors_arg: Multiple selectors from --selectors (comma-separated)
        
    Returns:
        List of selectors
    """
    selectors = []
    
    # Add single selector if provided
    if selector_arg and selector_arg.strip():
        selectors.append(selector_arg.strip())
    
    # Add multiple selectors if provided
    if selectors_arg and selectors_arg.strip():
        # Split by comma and clean up
        multiple = [s.strip() for s in selectors_arg.split(',') if s.strip()]
        selectors.extend(multiple)
    
    # Remove duplicates while preserving order
    seen = set()
    unique_selectors = []
    for s in selectors:
        if s not in seen:
            seen.add(s)
            unique_selectors.append(s)
    
    return unique_selectors


def process_single_domain(domain: str, selectors: List[str], timeout: int, append: bool, auto_discover_dkim: bool = False) -> bool:
    """
    Process a single domain and write result to CSV immediately.
    
    Args:
        domain: Domain name to check
        selectors: List of DKIM selectors
        timeout: DNS query timeout
        append: Whether to append to CSV
        
    Returns:
        True if successful, False otherwise
    """
    print(f"\n{'='*60}")
    print(f"Checking domain: {domain}")
    print(f"{'='*60}")
    
    if selectors:
        print_info(f"DKIM selectors: {', '.join(selectors)}")
    elif auto_discover_dkim:
        print_info("DKIM: Auto-discovering common selectors (--auto_discover_dkim flag enabled)")
    else:
        print_info("DKIM: No selector provided (use --auto_discover_dkim to test common selectors)")
    
    try:
        # Perform DNS check
        result = perform_complete_dns_check(domain, selectors if selectors else None, timeout, auto_discover_dkim=auto_discover_dkim)
        
        # Print results to terminal with color coding
        # MX Records
        if 'No MX' in result['mx'] or 'does not exist' in result['mx'] or 'timeout' in result['mx'] or 'error' in result['mx'].lower():
            print_not_found(f"MX Records: {result['mx']}")
        else:
            print_found(f"MX Records: {result['mx']}")
        
        # SPF Record
        if 'No SPF' in result['spf'] or 'does not exist' in result['spf'] or 'timeout' in result['spf'] or 'error' in result['spf'].lower():
            print_not_found(f"SPF Record: {result['spf']}")
        else:
            print_found(f"SPF Record: {result['spf']}")
        
        # DKIM Record
        dkim_lower = result['dkim'].lower()
        if ('no dkim' in dkim_lower or 
            'no selector' in dkim_lower or 
            'no selectors provided' in dkim_lower or
            'no valid selectors' in dkim_lower or
            'does not exist' in result['dkim'] or 
            'timeout' in result['dkim'] or 
            'error' in dkim_lower):
            # Check if it's "no selectors provided" (user didn't provide any)
            if 'no selectors provided' in dkim_lower and 'tested common selectors' not in dkim_lower:
                print_partial(f"DKIM Record: {result['dkim']}")
            else:
                # Either auto-discovery found nothing, or explicit selector failed
                print_not_found(f"DKIM Record: {result['dkim']}")
        else:
            print_found(f"DKIM Record: {result['dkim']}")
        
        # DMARC Record
        if 'No DMARC' in result['dmarc'] or 'does not exist' in result['dmarc'] or 'timeout' in result['dmarc'] or 'error' in result['dmarc'].lower():
            print_not_found(f"DMARC Record: {result['dmarc']}")
        else:
            print_found(f"DMARC Record: {result['dmarc']}")
        
        # Print errors if any
        if result.get('errors'):
            for error in result['errors']:
                print_warning(f"Warning: {error}")
        
        # Write to CSV
        if not write_results_to_csv([result], append=append):
            print_error("Failed to write result to CSV")
            return False
        
        return True
        
    except KeyboardInterrupt:
        print_error("\nInterrupted by user")
        return False
    except Exception as e:
        error_msg = f"Error checking domain {domain}: {str(e)}"
        print_error(error_msg)
        return False


def process_multiple_domains(domains: List[str], selectors: List[str], timeout: int, append: bool, skip_errors: bool, auto_discover_dkim: bool = False) -> None:
    """
    Process multiple domains and collect all results.
    
    Args:
        domains: List of domain names to check
        selectors: List of DKIM selectors
        timeout: DNS query timeout
        append: Whether to append to CSV
        skip_errors: Whether to continue on errors
    """
    print(f"\n{'='*60}")
    print(f"Processing {len(domains)} domain(s)")
    if selectors:
        print_info(f"DKIM selectors: {', '.join(selectors)}")
    elif auto_discover_dkim:
        print_info("DKIM: Auto-discovering common selectors (--auto_discover_dkim flag enabled)")
    else:
        print_info("DKIM: No selector provided (use --auto_discover_dkim to test common selectors)")
    print(f"{'='*60}\n")
    
    results = []
    successful = 0
    failed = 0
    
    for i, domain in enumerate(domains, 1):
        print(f"\n[{i}/{len(domains)}] Checking: {domain}")
        
        try:
            result = perform_complete_dns_check(domain, selectors if selectors else None, timeout, auto_discover_dkim=auto_discover_dkim)
            results.append(result)
            successful += 1
            
            # Print brief summary with color coding
            # MX Records
            if 'No MX' in result['mx'] or 'does not exist' in result['mx'] or 'timeout' in result['mx'] or 'error' in result['mx'].lower():
                print_not_found(f"  MX: {result['mx'][:50]}..." if len(result['mx']) > 50 else f"  MX: {result['mx']}")
            else:
                print_found(f"  MX: Found")
            
            # SPF Record
            if 'No SPF' in result['spf'] or 'does not exist' in result['spf'] or 'timeout' in result['spf'] or 'error' in result['spf'].lower():
                print_not_found(f"  SPF: {result['spf'][:50]}..." if len(result['spf']) > 50 else f"  SPF: {result['spf']}")
            else:
                print_found(f"  SPF: Found")
            
            # DKIM Record
            dkim_lower = result['dkim'].lower()
            if ('no dkim' in dkim_lower or 
                'no selector' in dkim_lower or 
                'no selectors provided' in dkim_lower or
                'no valid selectors' in dkim_lower or
                'does not exist' in result['dkim'] or 
                'timeout' in result['dkim'] or 
                'error' in dkim_lower):
                # Check if it's "no selectors provided" (user didn't provide any, and auto-discovery disabled)
                if 'no selectors provided' in dkim_lower and 'tested common selectors' not in dkim_lower:
                    print_partial(f"  DKIM: {result['dkim'][:50]}..." if len(result['dkim']) > 50 else f"  DKIM: {result['dkim']}")
                else:
                    # Either auto-discovery found nothing, or explicit selector failed
                    print_not_found(f"  DKIM: {result['dkim'][:50]}..." if len(result['dkim']) > 50 else f"  DKIM: {result['dkim']}")
            else:
                print_found(f"  DKIM: Found")
            
            # DMARC Record
            if 'No DMARC' in result['dmarc'] or 'does not exist' in result['dmarc'] or 'timeout' in result['dmarc'] or 'error' in result['dmarc'].lower():
                print_not_found(f"  DMARC: {result['dmarc'][:50]}..." if len(result['dmarc']) > 50 else f"  DMARC: {result['dmarc']}")
            else:
                print_found(f"  DMARC: Found")
            
        except KeyboardInterrupt:
            print_error("\nInterrupted by user")
            if results:
                print_info(f"Writing {len(results)} completed results to CSV...")
                write_results_to_csv(results, append=append)
            sys.exit(1)
        except Exception as e:
            failed += 1
            error_msg = f"Error checking {domain}: {str(e)}"
            print_error(f"  ✗ {error_msg}")
            
            if not skip_errors:
                print_error("Stopping due to error (use --skip_errors to continue)")
                if results:
                    print_info(f"Writing {len(results)} completed results to CSV...")
                    write_results_to_csv(results, append=append)
                sys.exit(1)
    
    # Write all results to CSV
    if results:
        print(f"\n{'='*60}")
        print_info(f"Writing {len(results)} result(s) to CSV...")
        if write_results_to_csv(results, append=append):
            print_success(f"✓ Successfully processed {successful} domain(s)")
            if failed > 0:
                print_warning(f"⚠ {failed} domain(s) failed")
        else:
            print_error("Failed to write results to CSV")
    else:
        print_error("No results to write")


def main(args: argparse.Namespace) -> None:
    """Main function to orchestrate the DNS checking process."""
    # Validate arguments
    validate_args(args)
    
    # Parse selectors
    selectors = parse_selectors(args.selector, args.selectors)
    
    # Update output path if provided
    if args.output_path:
        from config import update_path
        if not update_path(args.output_path):
            print_warning(f"Invalid output path: {args.output_path}. Using default from config.py")
    
    # Determine append mode
    append_mode = args.append.lower() == "yes"
    
    # Get domains
    domains = []
    
    if args.domain:
        domains.append(args.domain)
    elif args.domains_file:
        domains = read_domains_from_file(args.domains_file)
        if not domains:
            print_error("No valid domains found in file")
            sys.exit(1)
    
    # Clean up domains list
    domains = cleanup_domains_list(domains)
    
    if not domains:
        print_error("No valid domains to check")
        sys.exit(1)
    
    # Process domains
    if len(domains) == 1:
        # Single domain - write immediately
        success = process_single_domain(domains[0], selectors, args.timeout, append_mode, args.auto_discover_dkim)
        if not success:
            sys.exit(1)
    else:
        # Multiple domains - collect and write at end
        process_multiple_domains(domains, selectors, args.timeout, append_mode, args.skip_errors, args.auto_discover_dkim)


if __name__ == "__main__":
    print(banner_message())
    parser = initialize_parser()
    arguments = parser.parse_args()
    main(arguments)
