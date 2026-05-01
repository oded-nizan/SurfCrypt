"""
gui_analyzer.py defines the URL analyzer frame of the GUI.
"""

# Imports - Default Libraries
import tkinter as tk
from tkinter import ttk


# Imports - Internal Modules
from client.util import build_detail_string
from common.analyzer import UrlAnalyzer, normalize_domain


# Constants - Colors
COLOR_SAFE = '#2ecc71'
COLOR_WARNING = '#f39c12'
COLOR_DANGER = '#e74c3c'
COLOR_NEUTRAL = '#bdc3c7'


# Constants - Layout
PADX = 10
PADY = 6
ENTRY_WIDTH = 60


# Main Frame Class
class AnalyzerFrame(ttk.Frame):
    """URL analyzer panel for checking domains against local engine or server cache"""

    def __init__(self, parent, network_client, get_token, on_back=None):
        """Initialize AnalyzerFrame with network client and auth callback"""
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
        # Layout - create header with title and back button
        header = ttk.Frame(self)
        header.grid(row=0, column=0, columnspan=3, sticky='ew', pady=(0, PADY))
        ttk.Label(header, text='URL Analyzer', font=('', 13, 'bold')).pack(side='left')
        if self._on_back:
            ttk.Button(header, text='Back to Vault', command=self._on_back).pack(side='right')

        # Input - URL entry and analyze button
        ttk.Label(self, text='URL:').grid(row=1, column=0, sticky='w', padx=(0, PADX))
        self._url_var = tk.StringVar()
        self._url_entry = ttk.Entry(self, textvariable=self._url_var, width=ENTRY_WIDTH)
        self._url_entry.grid(row=1, column=1, sticky='ew', padx=(0, PADX))
        self._url_entry.bind('<Return>', lambda _: self._analyze_action())

        self._analyze_btn = ttk.Button(self, text='Analyze', command=self._analyze_action)
        self._analyze_btn.grid(row=1, column=2, sticky='w')

        # Results - verdict and rating display
        results_frame = ttk.LabelFrame(self, text='Result', padding=PADX)
        results_frame.grid(row=2, column=0, columnspan=3, sticky='ew', pady=(PADY, 0))
        results_frame.columnconfigure(0, weight=1)

        hero = ttk.Frame(results_frame)
        hero.grid(row=0, column=0, sticky='ew', pady=(PADY, 4))
        hero.columnconfigure(0, weight=1)

        self._verdict_label = ttk.Label(hero, text='-', font=('', 28, 'bold'), anchor='center')
        self._verdict_label.grid(row=0, column=0, sticky='ew')

        self._rating_label = ttk.Label(hero, text='-', font=('', 16), anchor='center')
        self._rating_label.grid(row=1, column=0, sticky='ew', pady=(2, 4))

        self._source_label = ttk.Label(hero, text='-', foreground=COLOR_NEUTRAL, anchor='center')
        self._source_label.grid(row=2, column=0, sticky='ew')

        # Details - collapsible advanced info
        self._details_visible = False
        self._toggle_btn = ttk.Button(results_frame, text='Advanced Details ▸', command=self._toggle_details)
        self._toggle_btn.grid(row=1, column=0, sticky='w', pady=(6, 0))

        self._details_frame = ttk.Frame(results_frame)
        self._detail_label = ttk.Label(self._details_frame, text='-', wraplength=450, justify='left')
        self._detail_label.pack(anchor='w', padx=4, pady=4)

        # Status - message bar
        self._status_var = tk.StringVar(value='Enter a URL and press Analyze')
        ttk.Label(self, textvariable=self._status_var, foreground=COLOR_NEUTRAL).grid(
            row=3, column=0, columnspan=3, sticky='w', pady=(PADY, 0)
        )
        self.columnconfigure(1, weight=1)

    def _toggle_details(self):
        """Show or hide the advanced details section"""
        if self._details_visible:
            self._details_frame.grid_forget()
            self._toggle_btn.config(text='Advanced Details ▸')
            self._details_visible = False
        else:
            self._details_frame.grid(row=2, column=0, sticky='ew', padx=4, pady=(4, 0))
            self._toggle_btn.config(text='Advanced Details ▾')
            self._details_visible = True

    # Analyzer actions
    def _analyze_action(self):
        """Orchestrate cache query, local fallback, and result display"""
        target_url = self._url_var.get().strip()
        if not target_url:
            self._set_status('Please enter a URL')
            return

        # Setup - normalize URL and disable button
        target_url = normalize_domain(target_url)
        self._analyze_btn.config(state='disabled')
        self._set_status('Checking server cache...')

        # Cache - query community results
        cached = self._query_server_cache(target_url)
        if cached:
            self._display_result(cached, source='cache')
            self._set_status('Result loaded from server cache')
            self._analyze_btn.config(state='normal')
            return

        # Engine - run local analysis if cache missed
        self._set_status('Running local analysis...')
        result = self._run_local_analysis(target_url)
        if result is None:
            self._analyze_btn.config(state='normal')
            return

        # Output - display results and upload to cache
        self._display_result(result, source='local')
        self._upload_to_cache(result)
        self._set_status('Analysis complete. Result cached on server')
        self._analyze_btn.config(state='normal')

    def _query_server_cache(self, url):
        """Query server for cached analysis; returns dict or None"""
        try:
            # Network - send request to get cached analysis
            response = self._network.send_request('get_url_analysis', {'url': url}, self._get_token())
            if response.get('status') == 'success' and response['data'].get('found'):
                return response['data']['analysis']
        except Exception:
            pass
        return None

    def _run_local_analysis(self, url):
        """Run local engine analysis; returns result dict or None"""
        try:
            # Engine - initialize and run analysis
            if self._analyzer is None:
                self._analyzer = UrlAnalyzer()
            return self._analyzer.analyze(url)
        except Exception as e:
            self._set_status(f'Analysis error: {e}')
            return None

    def _upload_to_cache(self, result):
        """Upload local result to community cache"""
        try:
            # Network - send request to cache result
            self._network.send_request('cache_url_analysis', result, self._get_token())
        except Exception:
            pass

    def _display_result(self, result, source):
        """Update UI labels with verdict data and color coding"""
        recommendation = result.get('recommendation', '-')
        rating = result.get('rating', '-')

        # Styling - map recommendation to status color
        color_map = {
            'Safe': COLOR_SAFE,
            'Warning': COLOR_WARNING,
            'Danger': COLOR_DANGER,
        }
        color = color_map.get(recommendation, COLOR_NEUTRAL)

        # Content - update verdict and source labels
        self._verdict_label.config(text=recommendation, foreground=color)
        self._rating_label.config(text=f'Rating:  {rating} / 5', foreground=color)
        self._source_label.config(
            text='Server cache' if source == 'cache' else 'Local engine',
            foreground=COLOR_NEUTRAL,
        )

        # Details - build and set advanced detail string
        details = build_detail_string(result)
        self._detail_label.config(text=details if details else 'No issues detected')
        if self._details_visible:
            self._details_frame.grid_forget()
            self._toggle_btn.config(text='Advanced Details ▸')
            self._details_visible = False

    def _set_status(self, message):
        """Update the status bar label text"""
        self._status_var.set(message)
