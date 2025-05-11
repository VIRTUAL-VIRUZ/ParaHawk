# PARAHAWK

A powerful and advanced Python tool for discovering URL parameters on websites through deep crawling and analysis.

[![Python Version](https://img.shields.io/badge/python-3.7%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

![Web Parameter Discoverer Banner](https://img.shields.io/badge/PARAHAWK-blue)

## Overview

PARAHAWK is a comprehensive tool designed for security researchers, web developers, and penetration testers to identify all URL parameters on a target website. It performs deep recursive crawling, JavaScript analysis, and parameter extraction to discover endpoints that might be overlooked by standard crawlers.

## Features

### Domain Handling
- **Input Flexibility**: Accept domains with or without protocol (example.com or https://example.com)
- **Domain Normalization**: Properly handle and normalize various domain formats
- **Subdomain Support**: Optional crawling of subdomains with the `--include-subdomains` flag

### Advanced Crawling
- **Multi-threaded Crawling**: Configurable thread count for parallel processing
- **Recursive Exploration**: Configurable depth limit for crawl operations
- **Rate Limiting**: Prevent overloading target servers with customizable request rates
- **Robots.txt Compliance**: Respect or ignore robots.txt with a toggle option

### Parameter Detection
- **URL Parameter Extraction**: Find all URLs with GET parameters
- **Form Parameter Detection**: Extract parameters from HTML forms
- **Custom Parameter Patterns**: Support for custom regex patterns to find specialized parameters
- **Parameter Frequency Analysis**: Track how often each parameter appears across the site

### JavaScript Analysis
- **JavaScript File Parsing**: Identify and extract parameters from JavaScript files
- **Dynamic URL Construction Detection**: Find URLs constructed in JavaScript code
- **AJAX Request Analysis**: Detect parameters in AJAX requests, fetch calls, and more
- **Embedded URLs**: Extract URLs from JavaScript string literals and template literals

### Security Features
- **User-Agent Rotation**: Randomize user-agents to avoid detection
- **SSL Verification Toggle**: Option to disable SSL verification for testing environments
- **Request Timeout Control**: Customize request timeouts

### Output Options
- **Colored Console Output**: Rich formatting for terminal output
- **Multiple Output Files**:
  - `all_urls.txt`: All discovered URLs
  - `parameter_urls.txt`: URLs containing parameters
  - `unique_parameters.txt`: List of unique parameter names
  - `parameter_frequency.csv`: Frequency analysis of parameters
  - `report.json`: Comprehensive JSON report with all findings

## Installation

### Requirements
- Python 3.7 or higher
- pip (Python package manager)

### Setup

1. Clone this repository or download the script:
   ```bash
   git clone https://github.com/VIRTUAL-VIRUZ/ParaHawk.git
   cd ParaHawk
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   Or install dependencies directly:
   ```bash
   pip install requests beautifulsoup4 tldextract rich aiohttp
   ```

## Usage

### Basic Usage

```bash
python parahawk.py example.com
```

### Advanced Options

```bash
python parahawk.py [options] domain
```

### Command Line Arguments

| Option | Description |
|--------|-------------|
| `domain` | Target domain to scan (required) |
| `--depth DEPTH` | Maximum crawl depth (default: 3) |
| `--threads THREADS` | Number of concurrent threads (default: 10) |
| `--timeout TIMEOUT` | Request timeout in seconds (default: 10) |
| `--output-dir OUTPUT_DIR` | Output directory for results (default: results_domain_timestamp) |
| `--include-subdomains` | Include subdomains in crawling |
| `--ignore-robots` | Ignore robots.txt restrictions |
| `--insecure` | Disable SSL certificate verification |
| `--parse-js` | Parse JavaScript files for URLs (default: True) |
| `--rate-limit RATE_LIMIT` | Rate limit requests per second (e.g., 5.0 for 5 req/sec) |
| `--custom-param-pattern PATTERN` | Custom regex pattern for parameter extraction |
| `--verbose`, `-v` | Enable verbose output |
| `--version` | Show program's version number and exit |

### Examples

Basic scan of a website:
```
python parahawk.py example.com
```

Deep scan with subdomain crawling:
```
python parahawk.py --depth 5 --include-subdomains example.com
```

Thorough scan with custom settings:
```
python parahawk.py --depth 4 --threads 15 --timeout 15 --rate-limit 2.5 --verbose example.com
```

## Output

The tool saves results in the specified output directory (default: `results_domain_timestamp/`):

- **Terminal Output**: Summary of findings with colored formatting
- **File Output**:
  - `all_urls.txt`: All discovered URLs during crawling
  - `parameter_urls.txt`: URLs containing parameters
  - `unique_parameters.txt`: List of unique parameter names
  - `parameter_frequency.csv`: CSV file with parameter frequency analysis
  - `report.json`: Comprehensive JSON report with all details

## Example Output

### Console Output
```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║             Web Parameter Discoverer v1.0.0              ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

Starting parameter discovery on https://example.com
Max depth: 3, Threads: 10

[+] Crawling... Found 42 URLs with parameters, Visited 156 URLs

Parameter Discovery Results for example.com
┏━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Parameter ┃ Occurrences ┃ Example URL                                               ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ id        │ 15          │ https://example.com/product?id=123                        │
│ page      │ 8           │ https://example.com/blog?page=2                           │
│ q         │ 6           │ https://example.com/search?q=test                         │
└───────────┴─────────────┴────────────────────────────────────────────────────────────┘

Summary:
  Total URLs visited: 156
  URLs with parameters: 42
  Unique parameters: 12
  Results saved to: results_example_20250511_120000/
```

## Use Cases

- **Security Research**: Discover hidden parameters for security testing
- **Web Application Analysis**: Map out application functionality
- **Parameter Discovery**: Find potential injection points
- **API Endpoint Detection**: Discover undocumented API endpoints
- **Site Mapping**: Generate a comprehensive map of a website's structure

## Contribution

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for legitimate security research and web development purposes only. Always ensure you have permission to scan the target domain. The author is not responsible for any misuse of this tool.

## Acknowledgments

- [Requests](https://docs.python-requests.org/) - HTTP library
- [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) - HTML parser
- [tldextract](https://github.com/john-kurkowski/tldextract) - Domain extraction
- [Rich](https://github.com/Textualize/rich) - Terminal formatting
