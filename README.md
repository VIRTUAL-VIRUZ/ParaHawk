# 🦅 PARA-HAWK - Advanced Website Parameter Discovery Tool

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0.0-orange.svg)](https://github.com/VIRTUAL-VIRUZ/ParaHawk)
[![Author](https://img.shields.io/badge/author-Muhammed%20Farhan-red.svg)](https://github.com/VIRTUAL-VIRUZ)

PARA-HAWK is a powerful, multi-threaded web crawler designed to discover GET parameters across entire websites. It performs deep crawling of target domains to identify all URLs containing parameters, making it an essential tool for web security testing, bug bounty hunting, and web application analysis.

**Author**: [Muhammed Farhan](https://github.com/VIRTUAL-VIRUZ)  
**Contact**: farhuzeee@gmail.com

## ✨ Features

- **🚀 Multi-threaded Crawling**: Concurrent processing with configurable thread pools
- **🎯 Deep Parameter Discovery**: Extracts parameters from HTML, JavaScript, and form actions
- **🔍 JavaScript Analysis**: Parses JS files to find hidden endpoints and parameters
- **🤖 Smart Crawling**: Respects robots.txt (optional) and implements rate limiting
- **📊 Rich Output**: Beautiful console output with progress tracking and detailed reports
- **💾 Multiple Export Formats**: JSON, CSV, and plain text output options
- **🌐 Subdomain Support**: Option to include or exclude subdomains
- **⚡ Asynchronous Processing**: Fast and efficient crawling with minimal resource usage
- **🛡️ Security Features**: SSL verification control and user agent rotation

## 🛠️ Installation

### Prerequisites

- Python 3.7 or higher
- pip package manager

### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/VIRTUAL-VIRUZ/ParaHawk.git
cd ParaHawk

# Install required packages
pip install -r requirements.txt
```

### Required Python Packages

```txt
aiohttp>=3.8.0
requests>=2.28.0
beautifulsoup4>=4.11.0
rich>=12.0.0
tldextract>=3.4.0
lxml>=4.9.0
```

Create a `requirements.txt` file with the above packages and install using:
```bash
pip install -r requirements.txt
```

## 🚀 Quick Start

### Basic Usage

```bash
# Scan a domain with default settings
python parahawk.py example.com

# Scan with custom depth and thread count
python parahawk.py --depth 5 --threads 20 example.com

# Include subdomains in the scan
python parahawk.py --include-subdomains example.com

# Quiet mode (minimal output)
python parahawk.py --quiet example.com
```

### Advanced Usage

```bash
# Full-featured scan with custom settings
python parahawk.py \
  --depth 4 \
  --threads 15 \
  --timeout 15 \
  --include-subdomains \
  --rate-limit 5 \
  --output-dir my_scan_results \
  --verbose \
  example.com

# Scan ignoring robots.txt with SSL verification disabled
python parahawk.py \
  --ignore-robots \
  --insecure \
  --parse-js \
  example.com
```

## 📋 Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `domain` | - | Target domain to scan (required) | - |
| `--depth` | - | Maximum crawl depth | 3 |
| `--threads` | - | Number of concurrent threads | 10 |
| `--timeout` | - | Request timeout in seconds | 10 |
| `--output-dir` | - | Output directory for results | Auto-generated |
| `--include-subdomains` | - | Include subdomains in crawling | False |
| `--ignore-robots` | - | Ignore robots.txt restrictions | False |
| `--insecure` | - | Disable SSL certificate verification | False |
| `--parse-js` | - | Parse JavaScript files for URLs | True |
| `--rate-limit` | - | Rate limit requests per second | None |
| `--custom-param-pattern` | - | Custom regex for parameter extraction | None |
| `--save-empty` | - | Save results even if no parameters found | False |
| `--verbose` | `-v` | Enable verbose output | False |
| `--quiet` | `-q` | Minimal output (URLs only) | False |
| `--version` | - | Show version information | - |

## 📁 Output Files

PARA-HAWK generates comprehensive reports in multiple formats:

### Generated Files

```
results_example_20231215_143022/
├── all_urls.txt              # All discovered URLs
├── parameter_urls.txt        # URLs containing parameters
├── unique_parameters.txt     # List of unique parameter names
├── parameter_frequency.csv   # Parameter usage frequency
└── report.json              # Detailed JSON report
```

### File Descriptions

- **`all_urls.txt`**: Complete list of all URLs discovered during crawling
- **`parameter_urls.txt`**: URLs that contain GET parameters
- **`unique_parameters.txt`**: Alphabetically sorted list of unique parameter names
- **`parameter_frequency.csv`**: CSV file showing how often each parameter appears
- **`report.json`**: Comprehensive JSON report with detailed metadata

### Sample JSON Report Structure

```json
{
  "domain": "example.com",
  "scan_date": "2023-12-15T14:30:22.123456",
  "urls_visited": 150,
  "parameter_urls_found": 45,
  "unique_parameters": 23,
  "parameter_details": {
    "https://example.com/search?q=test&category=books": {
      "path": "/search",
      "parameters": {
        "q": "test",
        "category": "books"
      },
      "content_type": "text/html"
    }
  },
  "parameters_list": ["category", "id", "page", "q", "sort"]
}
```

## 🎯 Use Cases

### Bug Bounty Hunting
- Discover hidden parameters that might be vulnerable to injection attacks
- Find forgotten or undocumented API endpoints
- Identify parameter pollution vulnerabilities

### Web Application Security Testing
- Map all application entry points
- Discover parameters for comprehensive security testing
- Identify potential attack vectors

### SEO and Website Analysis
- Understand website structure and URL patterns
- Identify dynamic content generation parameters
- Analyze crawlability and parameter usage

### Penetration Testing
- Reconnaissance phase parameter discovery
- Input validation testing preparation
- Attack surface mapping

## 🔧 Advanced Configuration

### Custom Parameter Patterns

Use custom regex patterns to identify non-standard parameter formats:

```bash
python parahawk.py --custom-param-pattern "([a-zA-Z_][a-zA-Z0-9_]*)=([^&]*)" example.com
```

### Rate Limiting

Implement respectful crawling with rate limiting:

```bash
# Limit to 2 requests per second
python parahawk.py --rate-limit 2 example.com
```

### JavaScript Analysis

PARA-HAWK automatically analyzes JavaScript files to find hidden endpoints:

- Extracts URLs from AJAX calls
- Parses fetch() requests
- Identifies dynamically constructed URLs
- Discovers API endpoints in JS frameworks

## 🛡️ Security and Ethics

### Responsible Usage

- **Permission**: Only scan websites you own or have explicit permission to test
- **Rate Limiting**: Use appropriate delays to avoid overwhelming target servers
- **Robots.txt**: Respect robots.txt unless explicitly testing for security purposes
- **Legal Compliance**: Ensure your usage complies with local laws and regulations

### Security Features

- **User Agent Rotation**: Randomizes user agents to avoid detection
- **SSL Certificate Handling**: Configurable SSL verification
- **Request Timeouts**: Prevents hanging requests
- **Error Handling**: Graceful handling of network errors and edge cases

## 🐛 Troubleshooting

### Common Issues

#### ImportError: No module named 'requests'
```bash
pip install requests beautifulsoup4 rich tldextract aiohttp
```

#### SSL Certificate Errors
```bash
# Disable SSL verification (use with caution)
python parahawk.py --insecure example.com
```

#### Memory Issues with Large Sites
```bash
# Reduce thread count and depth
python parahawk.py --threads 5 --depth 2 example.com
```

#### No Parameters Found
- Try increasing crawl depth: `--depth 5`
- Enable subdomain crawling: `--include-subdomains`
- Check if the site has dynamic content requiring JavaScript execution

### Performance Optimization

- **Optimal Thread Count**: Start with 10 threads, adjust based on target server response
- **Depth vs Coverage**: Deeper crawls find more parameters but take longer
- **Rate Limiting**: Balance speed with server respect

## 📊 Performance Metrics

### Typical Performance

- **Small Sites** (< 100 pages): 30-60 seconds
- **Medium Sites** (100-1000 pages): 2-10 minutes  
- **Large Sites** (1000+ pages): 10+ minutes

### Optimization Tips

1. **Adjust Thread Count**: More threads = faster scanning (within limits)
2. **Limit Depth**: Reduce depth for faster results
3. **Use Rate Limiting**: Prevent server overload and potential blocking
4. **Filter Content Types**: Focus on HTML and JavaScript content

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. **Fork the Repository**
2. **Create a Feature Branch**: `git checkout -b feature/amazing-feature`
3. **Commit Changes**: `git commit -m 'Add amazing feature'`
4. **Push to Branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Setup

```bash
# Clone your fork
git clone https://github.com/VIRTUAL-VIRUZ/ParaHawk.git
cd ParaHawk

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements-dev.txt
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Beautiful Soup** for HTML parsing
- **Rich** for beautiful console output
- **aiohttp** for asynchronous HTTP requests
- **tldextract** for domain parsing
- The security research community for inspiration and feedback

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/VIRTUAL-VIRUZ/ParaHawk/issues)
- **Discussions**: [GitHub Discussions](https://github.com/VIRTUAL-VIRUZ/ParaHawk/discussions)
- **Email**: farhuzeee@gmail.com

---

**⚠️ Disclaimer**: This tool is intended for legitimate security testing and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any websites. The authors are not responsible for any misuse of this tool.
