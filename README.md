# ESDAR-Checker (Email Security DNS Advanced Records Checker)
## Version 2.0.0

A Python tool to check email security DNS records (DMARC, SPF, DKIM, MX) for one or multiple domains.

## Features

- Check **DMARC** records
- Check **SPF** records  
- Check **DKIM** records (with support for multiple selectors)
- Check **MX** records
- Process single domain or multiple domains from file
- Export results to CSV
- Robust error handling (continues processing on errors)
- Support for multiple DKIM selectors per domain
- Improved CSV handling (proper formatting)

## Prerequisites

- Python 3.7 or higher
- PowerShell (for Windows) or terminal access
- you have to be able to run Scripts via Powershell or at least to run the following command in Powershell: ```Set-ExecutionPolicy Unrestricted -Scope Process``` ([Stackoverflow](https://stackoverflow.com/questions/18713086/virtualenv-wont-activate-on-windows))


## Installation

1. Clone the repository to your local machine
2. Navigate to the ESDAR-Checker directory
3. Create a virtual environment:
   ```powershell
   python -m venv .venv
   ```
4. Activate the virtual environment:
   ```powershell
   # Windows PowerShell
   .\.venv\Scripts\activate
   
   # Linux/Mac
   source .venv/bin/activate
   ```
5. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
6. (Optional) Configure output path in `config.py` or use `--output_path` parameter

## Usage

### Check a single domain

```powershell
python esdar-checker_v2.py --domain "google.com"
```

### Check a single domain with DKIM selector

```powershell
python esdar-checker_v2.py --domain "google.com" --selector "google"
```

### Check a single domain with multiple DKIM selectors

```powershell
python esdar-checker_v2.py --domain "google.com" --selectors "default,google,selector1"
```

### Check multiple domains from file

```powershell
python esdar-checker_v2.py --domains_file "resources/input/input_urls.csv"
```

### Append results to existing CSV file

```powershell
python esdar-checker_v2.py --domain "google.com" --append yes
```

### Specify custom output path

```powershell
python esdar-checker_v2.py --domain "google.com" --output_path "C:/Users/YourName/Downloads/results/"
```

### Continue processing on errors

```powershell
python esdar-checker_v2.py --domains_file "domains.txt" --skip_errors
```

### Custom DNS timeout

```powershell
python esdar-checker_v2.py --domain "google.com" --timeout 15
```

## Command-Line Arguments

### Required (one of):
- `--domain DOMAIN`: Check a single domain
- `--domains_file PATH`: File containing domains (one per line or CSV)

### Optional:
- `--selector SELECTOR`: Single DKIM selector to check
- `--selectors "SELECTOR1,SELECTOR2"`: Multiple DKIM selectors (comma-separated)
- `--append yes/no`: Append to existing CSV file (default: no)
- `--output_path PATH`: Custom output directory path
- `--timeout SECONDS`: DNS query timeout in seconds (default: 10)
- `--skip_errors`: Continue processing other domains if one fails

## Input File Format

The input file can be:
- **Plain text**: One domain per line
- **CSV**: First column should contain domain names (header row is automatically skipped)

Example plain text file:
```
google.com
microsoft.com
github.com
```

Example CSV file:
```csv
Domain
google.com
microsoft.com
github.com
```

## Output

Results are saved to `esdar-check_result.csv` in the output directory (default: `resources/output/`).

CSV columns:
- **Domain**: The checked domain
- **MX Record**: MX records (priority and mail server)
- **SPF Record**: SPF record if found
- **DKIM Record**: DKIM record(s) for the provided selector(s)
- **DMARC Record**: DMARC record if found

## Configuration

Edit `config.py` to:
- Set default output path (`RELATIVE_FILE_PATH`)
- Configure nameservers for DNS lookups (`NAMESERVER_LIST`)

## Troubleshooting

### "File is open in another program"
Close the CSV file in Excel or another program before running the script.

### "No DNS records found"
- Check if the domain exists
- Verify DNS connectivity
- Some domains may not have all security records configured

### "DNS query timeout"
- Increase timeout with `--timeout` parameter
- Check your internet connection
- Try different nameservers in `config.py`

## Known Issues (Fixed in v2.0.0)
```
- CSV formatting issues - **FIXED**
- Multiple selectors support - **ADDED**
- Error handling improvements - **FIXED**
- DMARC/DKIM lookup issues - **FIXED**
```

## Use Case

This script helps users check any number of domains or URLs for the following email security DNS records:
- **DMARC** (Domain-based Message Authentication, Reporting & Conformance)
- **SPF** (Sender Policy Framework)
- **DKIM** (DomainKeys Identified Mail)
- **MX Records** (Mail Exchange)

The script checks if DNS TXT records exist for the above points and stores them for further use. Results can be displayed in the terminal or written to a CSV file.

## License

See LICENSE file for details.

## Author

Merlin von der Weide
Version 2.0.0 - 2025
