#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Parameter Discoverer - Advanced Website Parameter Discovery Tool

This script performs deep crawling of a target domain to identify all URLs 
containing GET parameters. It features multithreaded crawling, JavaScript parsing,
parameter extraction, and formatted output.

Usage:
    python parameter_discoverer.py [options] domain

Example:
    python parameter_discoverer.py --depth 3 --threads 10 example.com
"""

import argparse
import asyncio
import concurrent.futures
import csv
import json
import logging
import os
import random
import re
import sys
import time
import urllib.parse
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Union
from urllib.robotparser import RobotFileParser

import aiohttp
import requests
import tldextract
from bs4 import BeautifulSoup
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

# Configure rich console and logging
console = Console()
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True, console=console)]
)
logger = logging.getLogger("parameter_discoverer")

# List of common user agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36",
]

# JavaScript URL pattern matching
JS_URL_PATTERNS = [
    r'[\"\']([^\"\']*\?[^\"\']+=[^\"\']*?)[\"\']',  # "url?param=value" or 'url?param=value'
    r'\.href\s*=\s*[\"\']([^\"\']*\?[^\"\']+=[^\"\']*?)[\"\']',  # .href = "url?param=value"
    r'\.open\([\'\"](GET|POST)[\'\"],\s*[\'\"](.*?\?.*?)[\'\"]\s*[),]',  # .open("GET", "url?param")
    r'\.ajax\(\{.*?url:\s*[\'\"](.*?\?.*?)[\'\"]',  # .ajax({url: "url?param"
    r'fetch\([\'\"](.*?\?.*?)[\'\"]',  # fetch("url?param")
    r'new URL\([\'\"](.*?\?.*?)[\'\"]',  # new URL("url?param")
    r'new Request\([\'\"](.*?\?.*?)[\'\"]',  # new Request("url?param")
]

# Parameter extraction regex
PARAM_PATTERN = re.compile(r'[?&]([^=&]+)=([^&]*)')

class WebParameterDiscoverer:
    """Main class for website parameter discovery."""
    
    def __init__(self, args):
        """Initialize the parameter discoverer with command line arguments."""
        self.args = args
        self.base_domain = self._normalize_domain(args.domain)
        self.base_url = f"https://{self.base_domain}" if not self.base_domain.startswith(('http://', 'https://')) else self.base_domain
        
        # Extract the domain without protocol for comparison
        parsed = urllib.parse.urlparse(self.base_url)
        self.domain_info = tldextract.extract(self.base_url)
        self.root_domain = f"{self.domain_info.domain}.{self.domain_info.suffix}"
        
        # Data structures to hold results
        self.visited_urls: Set[str] = set()
        self.queued_urls: Set[str] = set()
        self.parameter_urls: Dict[str, Dict] = {}
        self.unique_parameters: Set[str] = set()
        self.js_files: Set[str] = set()
        self.robots_parser = None
        
        # Output directory
        self.output_dir = args.output_dir or f"results_{self.domain_info.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Set up rate limiting if specified
        self.rate_limit = args.rate_limit
        self.last_request_time = 0
        
        # Request session with timeout and retry
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        
        # Initialize robots.txt parser if needed
        if not args.ignore_robots:
            self._init_robots_parser()
    
    def _normalize_domain(self, domain: str) -> str:
        """Normalize the domain input to a standard format."""
        domain = domain.strip()
        
        # Remove protocol if present
        if domain.startswith(('http://', 'https://')):
            parsed = urllib.parse.urlparse(domain)
            domain = parsed.netloc + parsed.path.rstrip('/')
        
        # Remove trailing slash
        domain = domain.rstrip('/')
        
        return domain
    
    def _init_robots_parser(self):
        """Initialize the robots.txt parser."""
        self.robots_parser = RobotFileParser()
        robots_url = urllib.parse.urljoin(self.base_url, '/robots.txt')
        
        try:
            response = self._make_request(robots_url)
            if response and response.status_code == 200:
                self.robots_parser.parse(response.text.splitlines())
                logger.info(f"[bold green]Loaded robots.txt from {robots_url}[/bold green]")
            else:
                logger.info(f"[yellow]No robots.txt found at {robots_url}[/yellow]")
                self.robots_parser = None
        except Exception as e:
            logger.warning(f"[yellow]Failed to fetch robots.txt: {str(e)}[/yellow]")
            self.robots_parser = None
    
    def _can_fetch(self, url: str) -> bool:
        """Check if the URL can be fetched according to robots.txt."""
        if self.args.ignore_robots or self.robots_parser is None:
            return True
        
        return self.robots_parser.can_fetch(random.choice(USER_AGENTS), url)
    
    def _make_request(self, url: str) -> Optional[requests.Response]:
        """Make an HTTP request with rate limiting and user agent rotation."""
        # Apply rate limiting if enabled
        if self.rate_limit:
            current_time = time.time()
            elapsed = current_time - self.last_request_time
            if elapsed < 1.0 / self.rate_limit:
                time.sleep((1.0 / self.rate_limit) - elapsed)
            self.last_request_time = time.time()
        
        # Rotate user agent
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        
        try:
            response = self.session.get(
                url, 
                timeout=self.args.timeout,
                allow_redirects=True,
                verify=not self.args.insecure
            )
            return response
        except requests.RequestException as e:
            if self.args.verbose:
                logger.debug(f"[red]Request failed for {url}: {str(e)}[/red]")
            return None
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if a URL belongs to the same domain or allowed subdomain."""
        parsed_url = urllib.parse.urlparse(url)
        # If it's a relative URL, it's on the same domain
        if not parsed_url.netloc:
            return True
        
        url_domain_info = tldextract.extract(url)
        
        # Check if it's a resource URL (no subdomain handling needed)
        if not url_domain_info.domain:
            return False
        
        # Check if it matches the main domain
        if url_domain_info.domain == self.domain_info.domain and url_domain_info.suffix == self.domain_info.suffix:
            # If subdomains are not included, only allow the exact domain or www
            if not self.args.include_subdomains:
                return url_domain_info.subdomain in ['', 'www'] or \
                       url_domain_info.subdomain == self.domain_info.subdomain
            return True
        
        return False
    
    def _normalize_url(self, url: str, base_url: str) -> Optional[str]:
        """Normalize a URL to absolute form and ensure it's valid."""
        try:
            # Handle fragments - we don't care about them for crawling
            url = url.split('#')[0]
            if not url:
                return None
            
            # Convert relative URLs to absolute
            absolute_url = urllib.parse.urljoin(base_url, url)
            
            # Parse and reconstruct to normalize
            parsed = urllib.parse.urlparse(absolute_url)
            
            # Skip non-HTTP/HTTPS URLs
            if parsed.scheme not in ['http', 'https']:
                return None
            
            # Reconstruct the URL
            normalized = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # No fragment
            ))
            
            return normalized
        except Exception as e:
            if self.args.verbose:
                logger.debug(f"[red]URL normalization error for {url}: {str(e)}[/red]")
            return None
    
    def _extract_links_from_html(self, html_content: str, base_url: str) -> List[str]:
        """Extract all links from HTML content."""
        links = []
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Get all anchor tags
            for a_tag in soup.find_all('a', href=True):
                links.append(a_tag['href'])
            
            # Get all form actions
            for form in soup.find_all('form', action=True):
                links.append(form['action'])
            
            # Get JavaScript files
            for script in soup.find_all('script', src=True):
                js_url = self._normalize_url(script['src'], base_url)
                if js_url and js_url.endswith('.js'):
                    self.js_files.add(js_url)
            
            # Get iframe sources
            for iframe in soup.find_all('iframe', src=True):
                links.append(iframe['src'])
            
            # Get meta refresh redirects
            for meta in soup.find_all('meta', attrs={'http-equiv': lambda x: x and x.lower() == 'refresh'}):
                if 'content' in meta.attrs:
                    content = meta['content']
                    url_match = re.search(r'url=(.*)', content, re.IGNORECASE)
                    if url_match:
                        links.append(url_match.group(1).strip('"\''))
            
            return links
        except Exception as e:
            logger.warning(f"[yellow]Failed to parse HTML: {str(e)}[/yellow]")
            return links
    
    def _extract_urls_from_js(self, js_content: str, base_url: str) -> List[str]:
        """Extract potential URLs from JavaScript content."""
        potential_urls = []
        
        # Look for URL patterns in JavaScript
        for pattern in JS_URL_PATTERNS:
            matches = re.findall(pattern, js_content)
            for match in matches:
                if isinstance(match, tuple):  # Some patterns return tuples
                    for item in match:
                        if '?' in item:  # We're interested in URLs with parameters
                            potential_urls.append(item)
                elif '?' in match:  # Single string match with parameters
                    potential_urls.append(match)
        
        # Normalize all found URLs
        normalized_urls = []
        for url in potential_urls:
            # Clean common JavaScript string concatenation and template literals
            url = re.sub(r'"\s*\+\s*"', '', url)
            url = re.sub(r'`\${.*?}`', 'PLACEHOLDER', url)
            
            # Try to normalize the URL
            normalized = self._normalize_url(url, base_url)
            if normalized:
                normalized_urls.append(normalized)
        
        return normalized_urls
    
    def _parse_parameters(self, url: str) -> Dict[str, str]:
        """Extract and parse parameters from a URL."""
        parsed = urllib.parse.urlparse(url)
        params = {}
        
        if parsed.query:
            # Standard URL query parsing
            query_params = urllib.parse.parse_qs(parsed.query)
            for key, values in query_params.items():
                params[key] = values[0] if values else ''
                self.unique_parameters.add(key)
            
            # If there's a custom parameter pattern, try to match that too
            if self.args.custom_param_pattern:
                custom_matches = re.findall(self.args.custom_param_pattern, parsed.query)
                for match in custom_matches:
                    if isinstance(match, tuple) and len(match) >= 2:
                        params[match[0]] = match[1]
                        self.unique_parameters.add(match[0])
        
        return params
    
    def _process_url(self, url: str, depth: int) -> List[str]:
        """Process a single URL, extracting links and parameters."""
        if depth > self.args.depth:
            return []
        
        if url in self.visited_urls:
            return []
        
        self.visited_urls.add(url)
        
        # Check robots.txt
        if not self._can_fetch(url):
            logger.debug(f"[yellow]Skipping {url} (disallowed by robots.txt)[/yellow]")
            return []
        
        # Make the request
        response = self._make_request(url)
        if not response or response.status_code != 200:
            return []
        
        new_links = []
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Check if URL has parameters
        params = self._parse_parameters(url)
        if params:
            path = urllib.parse.urlparse(url).path or '/'
            self.parameter_urls[url] = {
                'path': path,
                'parameters': params,
                'content_type': content_type
            }
            
            if self.args.verbose:
                logger.info(f"[green]Found parameters in {url}[/green]")
        
        # Process HTML
        if 'text/html' in content_type:
            links = self._extract_links_from_html(response.text, url)
            
            for link in links:
                normalized = self._normalize_url(link, url)
                if normalized and self._is_same_domain(normalized) and normalized not in self.visited_urls and normalized not in self.queued_urls:
                    new_links.append((normalized, depth + 1))
                    self.queued_urls.add(normalized)
        
        # Process JavaScript
        elif '.js' in url or 'javascript' in content_type:
            js_urls = self._extract_urls_from_js(response.text, url)
            
            for js_url in js_urls:
                normalized = self._normalize_url(js_url, url)
                if normalized and self._is_same_domain(normalized) and normalized not in self.visited_urls and normalized not in self.queued_urls:
                    new_links.append((normalized, depth + 1))
                    self.queued_urls.add(normalized)
        
        return new_links
    
    def crawl(self):
        """Main crawling method using thread pool."""
        logger.info(f"[bold blue]Starting parameter discovery on {self.base_url}[/bold blue]")
        logger.info(f"[blue]Max depth: {self.args.depth}, Threads: {self.args.threads}[/blue]")
        
        # Create a queue of URLs to process
        queue = deque([(self.base_url, 0)])
        self.queued_urls.add(self.base_url)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Crawling...", total=None)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
                future_to_url = {}
                
                while queue or future_to_url:
                    # Submit new tasks up to the thread limit
                    while queue and len(future_to_url) < self.args.threads:
                        url, depth = queue.popleft()
                        future = executor.submit(self._process_url, url, depth)
                        future_to_url[future] = url
                    
                    # Process completed tasks
                    done, _ = concurrent.futures.wait(
                        future_to_url, 
                        timeout=0.1,
                        return_when=concurrent.futures.FIRST_COMPLETED
                    )
                    
                    for future in done:
                        url = future_to_url.pop(future)
                        try:
                            new_links = future.result()
                            for new_url, new_depth in new_links:
                                if new_depth <= self.args.depth:
                                    queue.append((new_url, new_depth))
                        except Exception as e:
                            logger.error(f"[red]Error processing {url}: {str(e)}[/red]")
                        
                        # Update progress info
                        progress.update(task, description=f"[cyan]Crawling... Found {len(self.parameter_urls)} URLs with parameters, Visited {len(self.visited_urls)} URLs[/cyan]")
        
        # Process JavaScript files separately if requested
        if self.args.parse_js and self.js_files:
            self._process_js_files()
        
        logger.info(f"[bold green]Crawling completed![/bold green]")
        logger.info(f"[green]Total URLs visited: {len(self.visited_urls)}[/green]")
        logger.info(f"[green]URLs with parameters found: {len(self.parameter_urls)}[/green]")
        logger.info(f"[green]Unique parameters discovered: {len(self.unique_parameters)}[/green]")
    
    def _process_js_files(self):
        """Process all discovered JavaScript files."""
        logger.info(f"[blue]Processing {len(self.js_files)} JavaScript files...[/blue]")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            js_task = progress.add_task("[cyan]Processing JS files...", total=len(self.js_files))
            
            for js_url in self.js_files:
                response = self._make_request(js_url)
                if response and response.status_code == 200:
                    try:
                        js_urls = self._extract_urls_from_js(response.text, js_url)
                        
                        for url in js_urls:
                            normalized = self._normalize_url(url, js_url)
                            if normalized and '?' in normalized:
                                params = self._parse_parameters(normalized)
                                if params:
                                    path = urllib.parse.urlparse(normalized).path or '/'
                                    self.parameter_urls[normalized] = {
                                        'path': path,
                                        'parameters': params,
                                        'source': 'javascript',
                                        'js_file': js_url
                                    }
                    except Exception as e:
                        if self.args.verbose:
                            logger.debug(f"[yellow]Error processing JS file {js_url}: {str(e)}[/yellow]")
                
                progress.update(js_task, advance=1)
      def save_results(self):
        """Save the discovery results to files."""
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # Save all visited URLs
        with open(os.path.join(self.output_dir, 'all_urls.txt'), 'w', encoding='utf-8') as f:
            for url in sorted(self.visited_urls):
                f.write(f"{url}\n")
        
        # Save URLs with parameters
        with open(os.path.join(self.output_dir, 'parameter_urls.txt'), 'w', encoding='utf-8') as f:
            for url in sorted(self.parameter_urls.keys()):
                f.write(f"{url}\n")
        
        # Save unique parameters
        with open(os.path.join(self.output_dir, 'unique_parameters.txt'), 'w', encoding='utf-8') as f:
            for param in sorted(self.unique_parameters):
                f.write(f"{param}\n")
        
        # Save detailed JSON report
        report = {
            'domain': self.base_domain,
            'scan_date': datetime.now().isoformat(),
            'urls_visited': len(self.visited_urls),
            'parameter_urls_found': len(self.parameter_urls),
            'unique_parameters': len(self.unique_parameters),
            'parameter_details': self.parameter_urls,
            'parameters_list': sorted(list(self.unique_parameters))
        }
        
        with open(os.path.join(self.output_dir, 'report.json'), 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4)
        
        # Save parameter occurrences
        param_counts = defaultdict(int)
        for url_data in self.parameter_urls.values():
            for param in url_data['parameters'].keys():
                param_counts[param] += 1
        
        with open(os.path.join(self.output_dir, 'parameter_frequency.csv'), 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Parameter', 'Occurrences'])
            for param, count in sorted(param_counts.items(), key=lambda x: x[1], reverse=True):
                writer.writerow([param, count])
        
        logger.info(f"[bold green]Results saved to {self.output_dir}/ directory[/bold green]")
    
    def display_results(self):
        """Display the discovery results in the console."""
        # Create a table for parameters
        table = Table(title=f"Parameter Discovery Results for {self.base_domain}")
        table.add_column("Parameter", style="cyan")
        table.add_column("Occurrences", style="green", justify="right")
        table.add_column("Example URL", style="blue")
        
        # Count parameter occurrences
        param_counts = defaultdict(int)
        param_examples = {}
        
        for url, url_data in self.parameter_urls.items():
            for param in url_data['parameters'].keys():
                param_counts[param] += 1
                if param not in param_examples:
                    param_examples[param] = url
        
        # Add rows to the table
        for param, count in sorted(param_counts.items(), key=lambda x: x[1], reverse=True):
            table.add_row(
                param,
                str(count),
                param_examples[param][:60] + ('...' if len(param_examples[param]) > 60 else '')
            )
        
        console.print(table)
        
        # Summary
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  [cyan]Total URLs visited:[/cyan] [green]{len(self.visited_urls)}[/green]")
        console.print(f"  [cyan]URLs with parameters:[/cyan] [green]{len(self.parameter_urls)}[/green]")
        console.print(f"  [cyan]Unique parameters:[/cyan] [green]{len(self.unique_parameters)}[/green]")
        console.print(f"  [cyan]Results saved to:[/cyan] [green]{self.output_dir}/[/green]")

async def async_main():
    """Asynchronous entry point for faster startup."""
    parser = argparse.ArgumentParser(description="Web Parameter Discoverer - Find all parameters on a website")
    
    # Required arguments
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    
    # Optional arguments
    parser.add_argument("--depth", type=int, default=3, help="Maximum crawl depth (default: 3)")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--output-dir", help="Output directory for results (default: results_<domain>_<timestamp>)")
    parser.add_argument("--include-subdomains", action="store_true", help="Include subdomains in crawling")
    parser.add_argument("--ignore-robots", action="store_true", help="Ignore robots.txt restrictions")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")
    parser.add_argument("--parse-js", action="store_true", help="Parse JavaScript files for URLs (default: true)")
    parser.add_argument("--rate-limit", type=float, help="Rate limit requests per second (e.g., 5.0 for 5 req/sec)")
    parser.add_argument("--custom-param-pattern", help="Custom regex pattern for parameter extraction")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--version", action="version", version="Web Parameter Discoverer v1.0.0")
    
    args = parser.parse_args()
    
    # Set default for parse_js
    if args.parse_js is None:
        args.parse_js = True
    
    # Configure logging level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        # Banner
        console.print("[bold blue]╔══════════════════════════════════════════════════════════╗[/bold blue]")
        console.print("[bold blue]║                                                          ║[/bold blue]")
        console.print("[bold blue]║             [cyan]Web Parameter Discoverer v1.0.0[/cyan]              ║[/bold blue]")
        console.print("[bold blue]║                                                          ║[/bold blue]")
        console.print("[bold blue]╚══════════════════════════════════════════════════════════╝[/bold blue]")
        
        # Initialize and run the discoverer
        discoverer = WebParameterDiscoverer(args)
        discoverer.crawl()
        discoverer.save_results()
        discoverer.display_results()
        
        return 0
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        return 1
    except Exception as e:
        console.print(f"\n[bold red]Error: {str(e)}[/bold red]")
        if args.verbose:
            import traceback
            console.print(traceback.format_exc())
        return 1

def main():
    """Main entry point for the script."""
    if sys.platform.startswith('win'):
        # Windows-specific event loop policy
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    return asyncio.run(async_main())

if __name__ == "__main__":
    sys.exit(main())
