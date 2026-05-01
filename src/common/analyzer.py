"""
analyzer.py is the URL threat analysis engine for SurfCrypt.
"""

# Imports - Default Libraries
import re
from pathlib import Path
from urllib.parse import urlparse

# Imports - External Libraries
import requests

# Imports - Internal Modules


# Constants - File Paths
_RESOURCES = Path(__file__).resolve().parent.parent.parent / 'resources'
BLACKLIST_PATH = _RESOURCES / 'malicious_domains.txt'
SHORTENERS_PATH = _RESOURCES / 'shorteners.txt'


# Constants - Network Config
REQUEST_TIMEOUT = 5
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/124.0.0.0 Safari/537.36'
)


# Constants - Scoring Logic
BASE_RATING = 5
MIN_RATING = 1
MAX_SUBDOMAIN_COUNT = 3


# Constants - Detection Patterns
EXECUTABLE_EXTENSIONS = {'.exe', '.bat', '.msi', '.apk', '.scr'}
DOWNLOAD_CONTENT_TYPES = {
    'application/octet-stream',
    'application/x-msdownload',
    'application/zip',
    'application/vnd.android.package-archive',
}


# Custom Exceptions
class AnalyzerError(Exception):
    """Base exception for URL analysis operations"""


class BlacklistLoadError(AnalyzerError):
    """Raised when blacklist file cannot be loaded"""


# Internal Functions - Domain Logic
def _extract_domain(url):
    """Extract lowercase hostname from a URL string"""
    hostname = urlparse(url).hostname
    return hostname.lower() if hostname else ''


def _is_raw_ip(domain):
    """Check if domain is a raw IPv4 address"""
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))


def _count_subdomains(domain):
    """Count subdomains in a given hostname"""
    if not domain or _is_raw_ip(domain):
        return 0
    parts = domain.split('.')
    return max(0, len(parts) - 2)


def _is_blacklisted(domain, blacklist):
    """Check domain hierarchy against blacklist set"""
    if not domain:
        return False
    parts = domain.split('.')
    for i in range(len(parts) - 1):
        if '.'.join(parts[i:]) in blacklist:
            return True
    return False


def _is_shortened(target_domain, shorteners):
    """Check domain against known link shorteners"""
    if not target_domain:
        return False
    domain = target_domain.split('/')[0]
    return domain in shorteners


def _has_executable_extension(url):
    """Check if URL path ends with executable extension"""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in EXECUTABLE_EXTENSIONS)


def _check_download_headers(response):
    """Detect unprompted file download from response headers"""
    content_disposition = response.headers.get('Content-Disposition', '')
    content_type = response.headers.get('Content-Type', '').split(';')[0].strip().lower()
    return 'attachment' in content_disposition or content_type in DOWNLOAD_CONTENT_TYPES


# Internal Functions - Resource Loading
def _load_domains_file(path, label):
    """Read domain list file and return lowercase set"""
    try:
        domains = set()
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.add(line.lower())
        return domains
    except FileNotFoundError:
        print(f'Warning: {label} not found at {path}')
        return set()
    except Exception as e:
        print(f'Warning: Failed to load {label}: {e}')
        return set()


def _load_blacklist():
    """Read malicious domains and return set"""
    return _load_domains_file(BLACKLIST_PATH, 'blacklist')


def _load_shorteners():
    """Read shortener domains and return set"""
    return _load_domains_file(SHORTENERS_PATH, 'shorteners')


# Public Utilities - Normalization
def normalize_domain(domain):
    """Normalize a domain string to standard https form"""
    if 'www.' in domain:
        domain = domain.replace('www.', '')
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain


# Main Analysis Engine
class UrlAnalyzer:
    """Engine for performing security checks on URLs"""

    def __init__(self):
        """Initialize UrlAnalyzer and load domain datasets"""
        self._blacklist = _load_blacklist()
        self._shorteners = _load_shorteners()

    def analyze(self, url):
        """
        Perform a full threat analysis on a URL and return a security verdict.

        First follows redirects to find the final destination, then inspects both
        the original and final domains against blacklists, shorteners, and
        heuristic patterns (e.g., executable extensions or raw IP addresses)
        """
        # Setup - normalize URL and extract base domain
        url = normalize_domain(url)
        original_domain = _extract_domain(url)

        # Resolution - follow redirects to find final destination
        final_url = url
        final_domain = original_domain
        redirected = False
        triggers_download = False
        network_error = None

        try:
            response = requests.get(
                url,
                stream=True,
                allow_redirects=True,
                timeout=REQUEST_TIMEOUT,
                headers={'User-Agent': USER_AGENT},
            )
            final_url = response.url
            final_domain = _extract_domain(final_url)
            redirected = (final_url != url)
            triggers_download = _check_download_headers(response)
            response.close()
        except requests.RequestException as e:
            network_error = str(e)

        # Inspection - check domain datasets and patterns
        blacklisted_original = _is_blacklisted(original_domain, self._blacklist)
        blacklisted_final = _is_blacklisted(final_domain, self._blacklist)
        executable_url = _has_executable_extension(final_url)
        is_shortened = _is_shortened(original_domain, self._shorteners)
        excess_subdomains = (
            _count_subdomains(original_domain) > MAX_SUBDOMAIN_COUNT or
            _count_subdomains(final_domain) > MAX_SUBDOMAIN_COUNT
        )
        raw_ip = _is_raw_ip(original_domain) or _is_raw_ip(final_domain)
        general_download = triggers_download and not executable_url

        # Scoring - calculate final rating and recommendation
        strikes = 0
        if blacklisted_original or blacklisted_final or executable_url:
            rating = MIN_RATING
        else:
            if is_shortened:
                strikes += 1
            if excess_subdomains:
                strikes += 1
            if raw_ip:
                strikes += 1
            if general_download:
                strikes += 1
            rating = max(MIN_RATING, BASE_RATING - strikes)

        if rating >= 4:
            recommendation = 'Safe'
        elif rating == 3:
            recommendation = 'Warning'
        else:
            recommendation = 'Danger'

        return {
            'url': url,
            'rating': rating,
            'recommendation': recommendation,
            'is_shortened': is_shortened,
            'expanded_url': final_url,
            'analysis_data': {
                'original_domain': original_domain,
                'final_domain': final_domain,
                'redirected': redirected,
                'triggers_download': triggers_download,
                'strikes': strikes,
                'blacklisted_original': blacklisted_original,
                'blacklisted_final': blacklisted_final,
                'executable_extension': executable_url,
                'excess_subdomains': excess_subdomains,
                'raw_ip': raw_ip,
                'network_error': network_error,
            },
        }
