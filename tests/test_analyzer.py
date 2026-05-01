import pytest
from unittest.mock import patch, Mock, mock_open
from common.analyzer import UrlAnalyzer, _extract_domain, _is_raw_ip, _count_subdomains, _is_blacklisted, _has_executable_extension, _is_shortened, normalize_domain

def test_extract_domain():
    assert _extract_domain("http://example.com/path") == "example.com"
    assert _extract_domain("https://SUB.example.co.uk/") == "sub.example.co.uk"

def test_is_raw_ip():
    assert _is_raw_ip("192.168.1.1") == True
    assert _is_raw_ip("example.com") == False

def test_count_subdomains():
    assert _count_subdomains("example.com") == 0
    assert _count_subdomains("sub.example.com") == 1
    assert _count_subdomains("a.b.c.example.com") == 3

def test_is_blacklisted():
    blacklist = {"evil.com", "bad.org"}
    assert _is_blacklisted("evil.com", blacklist) == True
    assert _is_blacklisted("sub.evil.com", blacklist) == True
    assert _is_blacklisted("good.com", blacklist) == False

def test_has_executable_extension():
    assert _has_executable_extension("http://example.com/file.exe") == True
    assert _has_executable_extension("http://example.com/file.txt") == False

def test_normalize_domain():
    assert normalize_domain("example.com") == "https://example.com"
    assert normalize_domain("www.example.com") == "https://example.com"
    assert normalize_domain("http://example.com") == "http://example.com"
    assert normalize_domain("https://example.com") == "https://example.com"
    assert normalize_domain("http://www.example.com") == "http://example.com"

def test_is_shortened_with_path():
    shorteners = {"bit.ly", "tinyurl.com"}
    assert _is_shortened("bit.ly/123xyz", shorteners) == True
    assert _is_shortened("tinyurl.com/a", shorteners) == True
    assert _is_shortened("example.com/path", shorteners) == False
    assert _is_shortened("not_a_shortener.ly/path", shorteners) == False

@patch('common.analyzer.requests.get')
def test_analyzer_safe(mock_get):
    mock_resp = Mock()
    mock_resp.url = 'http://safe.com'
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    analyzer = UrlAnalyzer()
    analyzer._blacklist = set()
    analyzer._shorteners = set()
    
    result = analyzer.analyze("http://safe.com")
    assert result['rating'] == 5
    assert result['recommendation'] == 'Safe'

@patch('common.analyzer.requests.get')
def test_analyzer_danger_blacklisted(mock_get):
    mock_resp = Mock()
    mock_resp.url = 'http://evil.com'
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    analyzer = UrlAnalyzer()
    analyzer._blacklist = {"evil.com"}
    analyzer._shorteners = set()
    
    result = analyzer.analyze("http://evil.com")
    assert result['rating'] == 1
    assert result['recommendation'] == 'Danger'

@patch('common.analyzer.requests.get')
def test_analyzer_warning_strikes(mock_get):
    mock_resp = Mock()
    mock_resp.url = 'http://bit.ly/123'
    mock_resp.headers = {}
    mock_get.return_value = mock_resp

    analyzer = UrlAnalyzer()
    analyzer._blacklist = set()
    analyzer._shorteners = {"bit.ly"}
    
    result = analyzer.analyze("http://bit.ly/123")
    assert result['rating'] == 4  # 5 - 1 strike
    assert result['recommendation'] == 'Safe'
