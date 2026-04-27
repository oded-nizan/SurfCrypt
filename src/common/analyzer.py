"""
analyzer.py is the URL threat analysis engine. It takes a raw URL and returns a
security verdict: a 1-5 rating and a Safe / Warning / Danger recommendation.
"""

# Imports - Default Libraries
import re
from pathlib import Path
from urllib.parse import urlparse

# Imports - External Libraries
import requests

# Imports - Internal Modules

# Constants - Paths
_RESOURCES = Path(__file__).resolve().parent.parent.parent / 'resources'
BLACKLIST_PATH = _RESOURCES / 'malicious_domains.txt'
SHORTENERS_PATH = _RESOURCES / 'shorteners.txt'

# Constants - Network
REQUEST_TIMEOUT = 5
USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/124.0.0.0 Safari/537.36'
)

# Constants - Scoring
BASE_RATING = 5
MIN_RATING = 1
MAX_SUBDOMAIN_COUNT = 3  # More than this triggers excess-subdomain penalty

# Constants - Detection
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
    pass


class BlacklistLoadError(AnalyzerError):
    """Raised when blacklist file cannot be loaded"""
    pass


# Internal Functions - Domain Utilities
def _extract_domain(url):
    """Extract lowercase hostname from a URL string"""
    hostname = urlparse(url).hostname
    return hostname.lower() if hostname else ''


def _is_raw_ip(domain):
    """Return True if domain is a raw IPv4 address rather than a hostname"""
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain))


def _count_subdomains(domain):
    """Count subdomains; e.g. a.b.c.example.com → 3 subdomains"""
    if not domain or _is_raw_ip(domain):
        return 0
    parts = domain.split('.')
    # Registrable domain = last 2 labels; everything before is subdomains
    return max(0, len(parts) - 2)


def _is_blacklisted(domain, blacklist):
    """Check domain and all parent domains against blacklist set"""
    if not domain:
        return False
    parts = domain.split('.')
    # Walk from full domain up to registrable domain (e.g. sub.evil.com → evil.com)
    for i in range(len(parts) - 1):
        if '.'.join(parts[i:]) in blacklist:
            return True
    return False


def _has_executable_extension(url):
    """Return True if URL path ends with a known executable extension"""
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in EXECUTABLE_EXTENSIONS)


def _check_download_headers(response):
    """Return True if response headers indicate an unprompted file download"""
    content_disposition = response.headers.get('Content-Disposition', '')
    # Strip parameters (e.g. 'application/zip; charset=utf-8' → 'application/zip')
    content_type = response.headers.get('Content-Type', '').split(';')[0].strip().lower()
    return 'attachment' in content_disposition or content_type in DOWNLOAD_CONTENT_TYPES


# Internal Functions - Resource Loading
def _load_domains_file(path, label):
    """Read a domain-list file and return a lowercase set; warn and degrade gracefully on failure"""
    try:
        domains = set()
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.add(line.lower())
        return domains
    except FileNotFoundError:
        print(f'Warning: {label} not found at {path}. Proceeding with empty set.')
        return set()
    except Exception as e:
        print(f'Warning: Failed to load {label}: {e}. Proceeding with empty set.')
        return set()


def _load_blacklist():
    """Read malicious_domains.txt and return a lowercase set of domains"""
    return _load_domains_file(BLACKLIST_PATH, 'blacklist')


def _load_shorteners():
    """Read shorteners.txt and return a lowercase set of known shortener domains"""
    return _load_domains_file(SHORTENERS_PATH, 'shorteners')


# Main Class
class UrlAnalyzer:
    def __init__(self):
        """Initialize UrlAnalyzer; load blacklist and shorteners into memory for O(1) lookups"""
        self._blacklist = _load_blacklist()
        self._shorteners = _load_shorteners()

    def analyze(self, url: str) -> dict:
        """Perform full threat analysis on a URL; return verdict dictionary"""
        # Normalize - prepend scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        original_domain = _extract_domain(url)

        # Active network resolution - follow redirects to find true destination
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
            redirected = final_url != url
            triggers_download = _check_download_headers(response)
            response.close()
        except requests.RequestException as e:
            # Graceful fallback - offline analysis on original domain only
            network_error = str(e)

        # Pre-compute all detection flags before scoring
        blacklisted_original = _is_blacklisted(original_domain, self._blacklist)
        blacklisted_final = _is_blacklisted(final_domain, self._blacklist)
        executable_url = _has_executable_extension(final_url)
        is_shortened = original_domain in self._shorteners
        excess_subdomains = (
            _count_subdomains(original_domain) > MAX_SUBDOMAIN_COUNT or
            _count_subdomains(final_domain) > MAX_SUBDOMAIN_COUNT
        )
        raw_ip = _is_raw_ip(original_domain) or _is_raw_ip(final_domain)
        general_download = triggers_download and not executable_url

        # Scoring
        rating = BASE_RATING
        strikes = 0

        # Rule A: Immediate Danger - override rating to minimum
        if blacklisted_original or blacklisted_final or executable_url:
            rating = MIN_RATING
        else:
            # Rule B: Cumulative penalty deductions
            if is_shortened:
                strikes += 1
            if excess_subdomains:
                strikes += 1
            if raw_ip:
                strikes += 1
            if general_download:
                strikes += 1
            rating = max(MIN_RATING, BASE_RATING - strikes)

        # Verdict
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
