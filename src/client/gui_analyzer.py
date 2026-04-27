"""
gui_analyzer.py defines the url analyzer window of the GUI separately to relive pressure from gui_client.py
"""

# Imports - Default Libraries
import tkinter as tk
from tkinter import ttk

# Imports - Internal Modules
from common.analyzer import UrlAnalyzer

# Constants - Colors
COLOR_SAFE = '#2ecc71'
COLOR_WARNING = '#f39c12'
COLOR_DANGER = '#e74c3c'
COLOR_NEUTRAL = '#bdc3c7'

# Constants - Layout
PADX = 10
PADY = 6
ENTRY_WIDTH = 60


class AnalyzerFrame(ttk.Frame):
    """URL analyzer panel; queries server cache then falls back to local engine"""

    def __init__(self, parent, network_client, get_token, on_back=None):
        """Initialize frame and build all child widgets"""
        super().__init__(parent, padding=PADX)
        self._network = network_client
        self._get_token = get_token
        self._on_back = on_back
        self._analyzer = None

        self._build_widgets()

    def on_show(self):
        """Lifecycle hook called by MainApplication.show_frame()"""
        self._url_entry.focus_set()

    # Build UI
    def _build_widgets(self):
        """Construct and grid all child widgets"""
        header = ttk.Frame(self)
        header.grid(row=0, column=0, columnspan=3, sticky='ew', pady=(0, PADY))
        ttk.Label(header, text='URL Analyzer', font=('', 13, 'bold')).pack(side='left')
        if self._on_back:
            ttk.Button(header, text='Back to Vault', command=self._on_back).pack(side='right')

        # URL input row
        ttk.Label(self, text='URL:').grid(row=1, column=0, sticky='w', padx=(0, PADX))
        self._url_var = tk.StringVar()
        self._url_entry = ttk.Entry(self, textvariable=self._url_var, width=ENTRY_WIDTH)
        self._url_entry.grid(row=1, column=1, sticky='ew', padx=(0, PADX))
        self._url_entry.bind('<Return>', lambda _: self._analyze_action())

        self._analyze_btn = ttk.Button(self, text='Analyze', command=self._analyze_action)
        self._analyze_btn.grid(row=1, column=2, sticky='w')

        # Results panel
        results_frame = ttk.LabelFrame(self, text='Result', padding=PADX)
        results_frame.grid(row=2, column=0, columnspan=3, sticky='ew', pady=(PADY, 0))
        results_frame.columnconfigure(1, weight=1)

        ttk.Label(results_frame, text='Rating:').grid(row=0, column=0, sticky='w', pady=PADY)
        self._rating_label = ttk.Label(results_frame, text='-', font=('', 11, 'bold'))
        self._rating_label.grid(row=0, column=1, sticky='w', padx=PADX)

        ttk.Label(results_frame, text='Verdict:').grid(row=1, column=0, sticky='w', pady=PADY)
        self._verdict_label = ttk.Label(results_frame, text='-', font=('', 11, 'bold'))
        self._verdict_label.grid(row=1, column=1, sticky='w', padx=PADX)

        ttk.Label(results_frame, text='Source:').grid(row=2, column=0, sticky='w', pady=PADY)
        self._source_label = ttk.Label(results_frame, text='-', foreground=COLOR_NEUTRAL)
        self._source_label.grid(row=2, column=1, sticky='w', padx=PADX)

        ttk.Label(results_frame, text='Details:').grid(row=3, column=0, sticky='nw', pady=PADY)
        self._detail_label = ttk.Label(results_frame, text='-', wraplength=400, justify='left')
        self._detail_label.grid(row=3, column=1, sticky='w', padx=PADX)

        # Status bar
        self._status_var = tk.StringVar(value='Enter a URL and press Analyze')
        ttk.Label(self, textvariable=self._status_var, foreground=COLOR_NEUTRAL).grid(
            row=3, column=0, columnspan=3, sticky='w', pady=(PADY, 0)
        )

        self.columnconfigure(1, weight=1)

    # Analyzer actions
    def _analyze_action(self):
        """Orchestrate cache query -> local fallback -> display -> upload"""
        target_url = self._url_var.get().strip()
        if not target_url:
            self._set_status('Please enter a URL')
            return

        self._set_status('Checking server cache...')
        self._analyze_btn.config(state='disabled')

        # Query server cache
        cached = self._query_server_cache(target_url)
        if cached:
            self._display_result(cached, source='cache')
            self._set_status('Result loaded from server cache.')
            self._analyze_btn.config(state='normal')
            return

        # Run local analysis
        self._set_status('Running local analysis...')
        result = self._run_local_analysis(target_url)
        if result is None:
            self._analyze_btn.config(state='normal')
            return

        # Display result
        self._display_result(result, source='local')

        # Upload to server cache
        self._upload_to_cache(result)
        self._set_status('Analysis complete. Result cached on server.')
        self._analyze_btn.config(state='normal')

    def _query_server_cache(self, url):
        """Ask server for a cached analysis; return analysis dict or None on miss"""
        try:
            response = self._network.send_request(
                'get_url_analysis',
                {'url': url},
                self._get_token(),
            )
            if response.get('status') == 'success' and response['data'].get('found'):
                return response['data']['analysis']
        except Exception as e:
            # Network error; fall through to local analysis
            pass
        return None

    def _run_local_analysis(self, url):
        """Create analyzer instance and run analysis; return result dict or None"""
        try:
            if self._analyzer is None:
                self._analyzer = UrlAnalyzer()
            return self._analyzer.analyze(url)
        except Exception as e:
            self._set_status(f'Analysis error: {e}')
            return None

    def _upload_to_cache(self, result):
        """Send local analysis result to server for community caching"""
        try:
            self._network.send_request(
                'cache_url_analysis',
                result,
                self._get_token(),
            )
        except Exception as e:
            # Noncritical; local result already displayed
            pass

    # Display Helpers
    def _display_result(self, result, source):
        """Populate result labels with verdict data and apply color coding"""
        recommendation = result.get('recommendation', '-')
        rating = result.get('rating', '-')

        # Color mapping
        color_map = {
            'Safe': COLOR_SAFE,
            'Warning': COLOR_WARNING,
            'Danger': COLOR_DANGER,
        }
        color = color_map.get(recommendation, COLOR_NEUTRAL)

        self._rating_label.config(text=f'{rating} / 5', foreground=color)
        self._verdict_label.config(text=recommendation, foreground=color)
        self._source_label.config(
            text='Server cache' if source == 'cache' else 'Local engine',
            foreground=COLOR_NEUTRAL,
        )

        # Build human readable detail string from analysis result
        details = self._build_detail_string(result)
        self._detail_label.config(text=details if details else 'No issues detected.')

    @staticmethod
    def _build_detail_string(result):
        """Convert analysis result to readable multiline string based on analyzer.py output"""
        lines = []
        analysis_data = result.get('analysis_data', {})

        if analysis_data.get('blacklisted_original') or analysis_data.get('blacklisted_final'):
            lines.append('Domain is on the known malicious domains blacklist')
        if result.get('is_shortened'):
            lines.append('URL shortener detected - destination may be obfuscated')
        if analysis_data.get('redirected'):
            lines.append('URL redirected to a different destination')
        if analysis_data.get('excess_subdomains'):
            lines.append('Excessive subdomains detected (potential phishing)')
        if analysis_data.get('raw_ip'):
            lines.append('Raw IP address used instead of domain name')
        if analysis_data.get('executable_extension'):
            lines.append('Link points to an executable file (High Risk)')
        if analysis_data.get('triggers_download'):
            lines.append('Link triggers an automatic file download')
        if analysis_data.get('network_error'):
            lines.append('Offline analysis only (network unreachable)')

        return '\n'.join(lines)

    def _set_status(self, message):
        """Update the status bar label text"""
        self._status_var.set(message)
