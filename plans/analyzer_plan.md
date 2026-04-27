# UrlAnalyzer Implementation Plan

**Target Component:** `src/common/analyzer.py`
**Objective:** Create a standalone URL threat analysis engine from scratch.
**Target Audience:** External developer (no prior project context required).

---

## 1. Project Context & Environment
This module sits at the core of a zero-knowledge password manager and security toolkit. Its job is to take a raw URL provided by a user and return a security verdict (1 to 5 rating, plus a recommendation of Safe, Warning, or Danger).

**Key File Locations:**
*   **The Code:** `src/common/analyzer.py`
*   **The Blacklist:** `resources/malicious_domains.txt`
    *   *Note:* The blacklist path must be resolved dynamically relative to the `analyzer.py` file, e.g., `Path(__file__).resolve().parent.parent.parent / 'resources' / 'malicious_domains.txt'`.

**Required Dependencies:**
*   Standard library: `urllib.parse`, `re`, `pathlib`
*   Third-party: `requests` (must be added to `requirements.txt`)

---

## 2. Core Interface
You must implement the following class and entry point:

```python
class AnalyzerError(Exception): pass
class BlacklistLoadError(AnalyzerError): pass

class UrlAnalyzer:
    def __init__(self):
        # Load the blacklist into memory (a Python set) for O(1) lookups.
        pass
        
    def analyze(self, url: str) -> dict:
        # Perform all analysis and return the verdict dictionary.
        pass
```

---

## 3. Implementation Requirements (Step-by-Step)

### Step 1: Initialization & Blacklist Loading
*   Read `malicious_domains.txt` line by line.
*   Ignore empty lines and lines starting with `#` (comments).
*   Store domains in a lowercase `set`.
*   **Graceful Degradation:** If the file is missing, log/print a warning and initialize an empty set. Do not crash the application.

### Step 2: URL Normalization
*   If the user provides a URL without a scheme (e.g., `example.com`), prepend `http://`.
*   Extract the `original_domain` using `urllib.parse.urlparse()`.

### Step 3: Active Network Resolution
The analyzer must follow redirects to identify the true destination of shortened or obfuscated links.
*   **Action:** Use `requests.get()` to connect to the normalized URL.
*   **Parameters:** Use `stream=True` (to avoid downloading heavy page bodies), `allow_redirects=True`, and a strict `timeout=5` (seconds).
*   **Headers:** Spoof a standard web browser `User-Agent` (e.g., a modern Chrome string) so malicious sites do not block the Python request.
*   **Outcome:** Retrieve `response.url` as the `final_url` and extract the `final_domain`.
*   **Error Handling:** Catch `requests.RequestException`. If the network fails, gracefully fall back to analyzing only the `original_domain`.

### Step 4: Download Detection
Inspect the HTTP response headers (from the `requests.get(stream=True)` call) to see if the link triggers an unprompted file download.
*   Check if `Content-Disposition` contains `attachment`.
*   Check if `Content-Type` matches known binary/executable types (e.g., `application/octet-stream`, `application/x-msdownload`, `application/zip`, `application/vnd.android.package-archive`).

### Step 5: Heuristics & Scoring
Start every URL with a Base Rating of **5**. Deduct points ("strikes") based on these rules:

**Rule A: Immediate Danger (Score drops to 1)**
*   If `original_domain` OR `final_domain` is found in the blacklist. *(Note: You must also check parent domains. If `evil.com` is blacklisted, `sub.evil.com` is also blacklisted).*
*   If the `final_url` ends in a known executable extension (`.exe`, `.bat`, `.msi`, `.apk`, `.scr`).

**Rule B: Penalty Deductions (Cumulative)**
*   **Shortener (-1):** If the `original_domain` is in a hardcoded set of `KNOWN_SHORTENERS` (e.g., `bit.ly`, `tinyurl.com`, `t.co`, `goo.gl`, `ow.ly`).
*   **Excess Subdomains (-1):** If either domain has more than 3 subdomains (e.g., `a.b.c.d.example.com`).
*   **Raw IP (-1):** If either domain is a raw IPv4 address rather than a hostname.
*   **General Download (-1):** If the header analysis detected a download, but it is not an executable extension.

### Step 6: Compute Verdict & Return Format
Based on the final rating (minimum possible is 1):
*   **5 or 4:** Recommendation = `"Safe"`
*   **3:** Recommendation = `"Warning"`
*   **2 or 1:** Recommendation = `"Danger"`

**The `analyze()` method MUST return exactly this dictionary structure:**
```json
{
    "url": "http://example.com",
    "rating": 5,
    "recommendation": "Safe",
    "is_shortened": false,
    "expanded_url": "https://example.com/final/path",
    "analysis_data": {
        "original_domain": "example.com",
        "redirected": true,
        "triggers_download": false,
        "strikes": 0,
        "...": "Any other helpful metadata flags (e.g. 'blacklisted_final': true)"
    }
}
```

---

## 4. Testing & Validation
*   The module must not make any UI calls (no `print()` for regular output, no `tkinter` imports).
*   Test with a known good URL (should return 5).
*   Test with a URL that redirects.
*   Test with a blacklisted URL (should return 1).
*   Test with a fake URL to ensure the network timeout gracefully falls back to offline analysis without crashing.
