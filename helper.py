"""
Helper functions for ESDAR-Checker

@author Merlin von der Weide
@version 2.0.0
@date 2025
"""
from typing import List


def remove_new_line_char(domains: List[str]) -> List[str]:
    """
    Remove newline characters from domain list.
    
    Args:
        domains: List of domain strings
        
    Returns:
        List of cleaned domain strings
    """
    cleaned_domains = []
    for domain in domains:
        cleaned_domain = domain.replace('\n', '').replace('\r', '').strip()
        if cleaned_domain:  # Only add non-empty domains
            cleaned_domains.append(cleaned_domain)
    return cleaned_domains


def replace_characters(record_to_check: str, char_to_replace: str = ";", new_char: str = ",") -> str:
    """
    Replace characters in a string (used for formatting DNS records).
    
    Args:
        record_to_check: String to process
        char_to_replace: Character to replace
        new_char: Replacement character
        
    Returns:
        Updated string
    """
    if not record_to_check:
        return ""
    return record_to_check.replace(char_to_replace, new_char)


def cleanup_domains_list(domains: List[str]) -> List[str]:
    """
    Clean up and deduplicate domain list.
    
    Args:
        domains: List of domain strings
        
    Returns:
        Cleaned, deduplicated, and sorted list of domains
    """
    if not domains:
        return []
    
    # Remove whitespace, convert to lowercase, and filter empty strings
    cleaned = [d.strip().lower() for d in domains if d.strip()]
    
    # Remove duplicates while preserving order
    seen = set()
    unique_domains = []
    for domain in cleaned:
        if domain not in seen:
            seen.add(domain)
            unique_domains.append(domain)
    
    # Sort alphabetically
    unique_domains.sort()
    
    return unique_domains
