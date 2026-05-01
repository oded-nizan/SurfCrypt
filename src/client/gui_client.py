"""
gui_client.py is the main desktop GUI application entry point for SurfCrypt.
"""

# Imports - Default Libraries
import tkinter as tk
from tkinter import (
    messagebox,
    ttk,
)

# Imports - External Libraries

# Imports - Internal Modules
from client.gui_analyzer import AnalyzerFrame
from client.gui_secrets import SecretModal
from client.identity import IdentityManager
from client.network import NetworkClient
from client.util import (
    _decrypt_secret_row,
    _is_session_error,
    get_searchable_text,
    secure_copy,
)
from common.crypto import CryptoError


# Constants - Window Dimensions
WINDOW_TITLE = 'SurfCrypt'
WINDOW_WIDTH = 900
WINDOW_HEIGHT = 580


# Application Class
class MainApplication:
    """Root application controller for window management and routing"""

    def __init__(self):
        """Initialize main window and core service objects"""
        # Window - configure root window
        self._root = tk.Tk()
        self._root.title(WINDOW_TITLE)
        self._root.geometry(f'{WINDOW_WIDTH}x{WINDOW_HEIGHT}')
        self._root.minsize(700, 460)

        # Services - initialize networking and identity
        self._network = NetworkClient()
        self._identity = IdentityManager(self._network)

        # Routing - setup frame container and registry
        container = ttk.Frame(self._root)
        container.pack(fill='both', expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self._frames = {}
        for FrameClass in (LoginFrame, DashboardFrame):
            frame = FrameClass(parent=container, controller=self)
            self._frames[FrameClass.__name__] = frame
            frame.grid(row=0, column=0, sticky='nsew')

        # Analyzer - special case for constructor dependency injection
        analyzer_frame = AnalyzerFrame(
            parent=container,
            network_client=self._network,
            get_token=lambda: self._identity.session_token,
            on_back=lambda: self.show_frame('DashboardFrame'),
        )
        self._frames['AnalyzerFrame'] = analyzer_frame
        analyzer_frame.grid(row=0, column=0, sticky='nsew')

        self.show_frame('LoginFrame')

        # Shortcuts - global keyboard bindings
        self._root.bind('<Control-n>', lambda _: self._shortcut_add())
        self._root.bind('<Control-f>', lambda _: self._shortcut_search())
        self._root.bind('<Control-r>', lambda _: self._shortcut_refresh())
        self._root.bind('<Delete>', lambda _: self._shortcut_delete())
        self._root.bind('<Control-u>', lambda _: self._shortcut_copy_username())
        self._root.bind('<Control-p>', lambda _: self._shortcut_copy_password())
        self._root.bind('<Escape>', lambda _: self._shortcut_escape())

    def _shortcut_add(self):
        """Handle Ctrl+N shortcut for adding a secret"""
        if self._current_frame == 'DashboardFrame':
            self._frames['DashboardFrame']._on_add()

    def _shortcut_search(self):
        """Handle Ctrl+F shortcut for focusing search"""
        if self._current_frame == 'DashboardFrame':
            self._frames['DashboardFrame']._focus_search()

    def _shortcut_refresh(self):
        """Handle Ctrl+R shortcut for refreshing vault"""
        if self._current_frame == 'DashboardFrame':
            self._frames['DashboardFrame'].refresh_vault()

    def _shortcut_delete(self):
        """Handle Delete key for removing selected secret"""
        if self._current_frame == 'DashboardFrame':
            self._frames['DashboardFrame']._on_delete()

    def _shortcut_copy_username(self):
        """Handle Ctrl+U shortcut for copying username"""
        if self._current_frame == 'DashboardFrame':
            self._frames['DashboardFrame']._on_copy_username()

    def _shortcut_copy_password(self):
        """Handle Ctrl+P shortcut for copying password"""
        if self._current_frame == 'DashboardFrame':
            self._frames['DashboardFrame']._on_copy_password()

    def _shortcut_escape(self):
        """Handle Escape key for navigating back"""
        if self._current_frame == 'AnalyzerFrame':
            self.show_frame('DashboardFrame')

    def show_frame(self, frame_name):
        """Raise named frame to the top and trigger lifecycle hook"""
        self._current_frame = frame_name
        frame = self._frames[frame_name]
        frame.tkraise()
        frame.on_show()

    def handle_session_expiry(self):
        """Clean up identity state and return to login on session failure"""
        self._identity.logout()
        messagebox.showwarning('Session Expired', 'Your session has expired. Please log in again')
        self._frames['LoginFrame'].set_status('')
        self.show_frame('LoginFrame')

    def run(self):
        """Start the Tkinter main event loop"""
        self._root.mainloop()

    @property
    def root(self):
        """Expose root window for modal parenting"""
        return self._root

    @property
    def network_client(self):
        """Expose network client service"""
        return self._network

    @property
    def identity_manager(self):
        """Expose identity manager service"""
        return self._identity


# Login View
class LoginFrame(ttk.Frame):
    """Authentication view for user login and registration"""

    def __init__(self, parent, controller):
        """Initialize LoginFrame and construct UI"""
        super().__init__(parent)
        self._controller = controller
        self._build_widgets()

    def _build_widgets(self):
        """Construct and center the login form components"""
        # Layout - center the inner frame
        inner = ttk.Frame(self, padding=40)
        inner.place(relx=0.5, rely=0.5, anchor='center')

        # Header - display application title
        ttk.Label(inner, text='SurfCrypt', font=('Helvetica', 22, 'bold')).grid(
            row=0, column=0, columnspan=2, pady=(0, 28)
        )

        # Fields - username and password inputs
        ttk.Label(inner, text='Username:').grid(row=1, column=0, sticky='e', padx=(0, 10), pady=7)
        self._username_var = tk.StringVar()
        self._username_entry = ttk.Entry(inner, textvariable=self._username_var, width=28)
        self._username_entry.grid(row=1, column=1, pady=7, sticky='ew')

        ttk.Label(inner, text='Master Password:').grid(row=2, column=0, sticky='e', padx=(0, 10), pady=7)
        self._password_var = tk.StringVar()
        ttk.Entry(inner, textvariable=self._password_var, show='*', width=28).grid(
            row=2, column=1, pady=7, sticky='ew'
        )

        # Buttons - trigger login or registration
        btn_row = ttk.Frame(inner)
        btn_row.grid(row=3, column=0, columnspan=2, pady=18)
        ttk.Button(btn_row, text='Login', command=self._on_login, width=12).pack(side='left', padx=8)
        ttk.Button(btn_row, text='Register', command=self._on_register, width=12).pack(side='left', padx=8)

        # Status - feedback messages for the user
        self._status_var = tk.StringVar()
        self._status_label = ttk.Label(inner, textvariable=self._status_var, foreground='red', wraplength=320)
        self._status_label.grid(row=4, column=0, columnspan=2)

    def on_show(self):
        """Reset form fields and focus on username when raised"""
        self._username_var.set('')
        self._password_var.set('')
        self.set_status('')
        self._username_entry.focus_set()

    def set_status(self, message, color='red'):
        """Update status message text and foreground color"""
        self._status_var.set(message)
        self._status_label.configure(foreground=color)

    def _credentials(self):
        """Return the current username and password from entry variables"""
        return self._username_var.get().strip(), self._password_var.get()

    def _on_login(self):
        """Perform login workflow via IdentityManager"""
        username, password = self._credentials()
        if not username or not password:
            self.set_status('Username and password are required')
            return

        self.set_status('Logging in...', color='gray')
        self.update_idletasks()
        try:
            self._controller.identity_manager.login(username, password)
        except Exception:
            self.set_status('Login failed. Check credentials or network')
            return

        self._password_var.set('')
        self.set_status('')
        self._controller.show_frame('DashboardFrame')

    def _on_register(self):
        """Perform registration followed by automatic login"""
        username, password = self._credentials()
        if not username or not password:
            self.set_status('Username and password are required')
            return

        self.set_status('Registering...', color='gray')
        self.update_idletasks()
        try:
            self._controller.identity_manager.register(username, password)
        except Exception:
            self.set_status('Registration failed')
            return

        # Login - automatic authentication after successful registration
        self.set_status('Registered. Logging in...', color='gray')
        self.update_idletasks()
        try:
            self._controller.identity_manager.login(username, password)
        except Exception:
            self._password_var.set('')
            self.set_status('Registered. Please log in manually', color='green')
            return

        self._password_var.set('')
        self.set_status('')
        self._controller.show_frame('DashboardFrame')


# Main View
class DashboardFrame(ttk.Frame):
    """Vault dashboard view for managing encrypted secrets"""

    _COLUMNS = ('name', 'url', 'username')
    _COL_HEADERS = {'name': 'Name', 'url': 'URL', 'username': 'Username'}
    _COL_WIDTHS = {'name': 240, 'url': 280, 'username': 200}

    def __init__(self, parent, controller):
        """Initialize DashboardFrame and setup treeview layout"""
        super().__init__(parent)
        self._controller = controller
        # Cache - decrypted plaintext stored by ID
        self._decrypted_secrets = {}

        # Layout - configure grid weighting
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._build_top_bar()
        self._build_treeview()
        self._build_action_bar()
        self._build_context_menu()

    def _build_top_bar(self):
        """Construct the top navigation and search bar"""
        bar = ttk.Frame(self, padding=(10, 7))
        bar.grid(row=0, column=0, sticky='ew')

        self._user_label = ttk.Label(bar, text='', font=('Helvetica', 10, 'bold'))
        self._user_label.pack(side='left', padx=(2, 18))

        # Controls - refresh, add, analyze buttons
        ttk.Button(bar, text='Refresh', command=self.refresh_vault).pack(side='left', padx=4)
        ttk.Button(bar, text='Add Secret', command=self._on_add).pack(side='left', padx=4)
        ttk.Button(bar, text='Analyze URL', command=self._on_analyze_url).pack(side='left', padx=4)
        ttk.Button(bar, text='Logout', command=self._on_logout).pack(side='right', padx=4)

        # Search - real-time filtering input
        self._search_var = tk.StringVar()
        self._search_var.trace_add('write', lambda *_: self._apply_search())
        self._search_entry = ttk.Entry(bar, textvariable=self._search_var, width=20)
        self._search_entry.pack(side='right', padx=(4, 8))
        ttk.Label(bar, text='Search:').pack(side='right')

    def _build_treeview(self):
        """Construct the main secret grid with scrollbar"""
        frame = ttk.Frame(self)
        frame.grid(row=1, column=0, sticky='nsew', padx=8, pady=4)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        # Treeview - define columns and headings
        self._tree = ttk.Treeview(frame, columns=self._COLUMNS, show='headings', selectmode='browse')
        for col in self._COLUMNS:
            self._tree.heading(col, text=self._COL_HEADERS[col], anchor='w')
            self._tree.column(col, width=self._COL_WIDTHS[col], minwidth=80, anchor='w')

        # Scrolling - attach vertical scrollbar
        vsb = ttk.Scrollbar(frame, orient='vertical', command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)

        self._tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')

        # Bindings - double click to edit, right click for menu
        self._tree.bind('<Double-1>', lambda _e: self._on_edit())
        self._tree.bind('<Button-3>', self._on_right_click)

    def _build_action_bar(self):
        """Construct the bottom action buttons and status display"""
        bar = ttk.Frame(self, padding=(8, 5))
        bar.grid(row=2, column=0, sticky='ew')

        # Actions - edit and delete buttons
        ttk.Button(bar, text='Edit', command=self._on_edit).pack(side='left', padx=4)
        ttk.Button(bar, text='Delete', command=self._on_delete).pack(side='left', padx=4)
        ttk.Separator(bar, orient='vertical').pack(side='left', fill='y', padx=6)

        # Clipboard - copy utilities
        ttk.Button(bar, text='Copy Username', command=self._on_copy_username).pack(side='left', padx=4)
        ttk.Button(bar, text='Copy Password', command=self._on_copy_password).pack(side='left', padx=4)

        # Status - display item counts and sync status
        self._status_var = tk.StringVar()
        ttk.Label(bar, textvariable=self._status_var, foreground='gray').pack(side='right', padx=10)

    def _build_context_menu(self):
        """Construct the right-click context menu"""
        self._ctx_menu = tk.Menu(self, tearoff=0)
        self._ctx_menu.add_command(label='Edit', command=self._on_edit)
        self._ctx_menu.add_command(label='Copy Username', command=self._on_copy_username)
        self._ctx_menu.add_command(label='Copy Password', command=self._on_copy_password)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label='Delete', command=self._on_delete)

    def on_show(self):
        """Raise the dashboard and refresh vault data"""
        username = self._controller.identity_manager.username
        self._user_label.configure(text=f'Logged in as:  {username}')
        self.refresh_vault()

    def refresh_vault(self):
        """Sync with server and repopulate the secret grid"""
        im = self._controller.identity_manager
        try:
            # Sync - fetch encrypted rows from server
            response = self._controller.network_client.send_request('sync_secrets', {}, im.session_token)
        except Exception as e:
            if _is_session_error(str(e)):
                self._controller.handle_session_expiry()
                return
            messagebox.showerror('Network Error', f'Could not fetch secrets:\n{e}')
            return

        rows = response.get('data', {}).get('secrets', [])
        vault_key = im.vault_key

        # Reset - clear cache and tree
        self._decrypted_secrets.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)

        # Process - decrypt and insert each row
        failed = 0
        for row in rows:
            try:
                plaintext = _decrypt_secret_row(row, vault_key)
            except CryptoError:
                failed += 1
                continue

            secret_id = str(row['id'])
            self._decrypted_secrets[secret_id] = plaintext
            self._tree.insert(
                '', 'end', iid=secret_id,
                values=(plaintext['name'], plaintext['url'], plaintext['username'])
            )

        # Update - set status message and re-apply search
        count = len(self._decrypted_secrets)
        suffix = f'  ({failed} row(s) could not be decrypted)' if failed else ''
        self._status_var.set(f'{count} secret(s) loaded.{suffix}')
        self._apply_search()

    def _apply_search(self):
        """Filter the grid results based on search input"""
        query = self._search_var.get().strip().lower()

        for iid in self._tree.get_children():
            self._tree.delete(iid)

        for secret_id, plaintext in self._decrypted_secrets.items():
            if query:
                searchable = get_searchable_text(plaintext)
                if query not in searchable:
                    continue
            self._tree.insert(
                '', 'end', iid=secret_id,
                values=(plaintext['name'], plaintext['url'], plaintext['username'])
            )

    def _focus_search(self):
        """Move cursor focus to the search entry field"""
        self._search_entry.focus_set()
        self._search_entry.select_range(0, 'end')

    def _selected_id(self):
        """Return the ID of the selected row or None"""
        sel = self._tree.selection()
        return sel[0] if sel else None

    def _on_right_click(self, event):
        """Show the context menu at mouse coordinates"""
        row = self._tree.identify_row(event.y)
        if row:
            self._tree.selection_set(row)
            self._ctx_menu.post(event.x_root, event.y_root)

    def _on_add(self):
        """Open the modal to add a new secret"""
        SecretModal(self, self._controller, mode='add')

    def _on_edit(self):
        """Open the modal to edit the selected secret"""
        secret_id = self._selected_id()
        if not secret_id:
            messagebox.showinfo('No Selection', 'Please select a secret to edit')
            return
        plaintext = self._decrypted_secrets.get(secret_id, {})
        SecretModal(self, self._controller, mode='edit', secret_id=secret_id, prefill=plaintext)

    def _on_delete(self):
        """Delete the selected secret from the vault"""
        secret_id = self._selected_id()
        if not secret_id:
            messagebox.showinfo('No Selection', 'Please select a secret to delete')
            return
        if not messagebox.askyesno('Confirm Delete', 'Permanently delete this secret?'):
            return

        im = self._controller.identity_manager
        try:
            # Sync - request server to remove secret
            self._controller.network_client.send_request(
                'delete_secret', {'secret_id': int(secret_id)}, im.session_token
            )
        except Exception as e:
            if _is_session_error(str(e)):
                self._controller.handle_session_expiry()
                return
            messagebox.showerror('Error', f'Failed to delete secret:\n{e}')
            return

        self.refresh_vault()

    def _on_copy_username(self):
        """Copy selected username to system clipboard"""
        secret_id = self._selected_id()
        if not secret_id:
            messagebox.showinfo('No Selection', 'Please select a secret first')
            return
        secure_copy(self._controller.root, self._decrypted_secrets[secret_id]['username'])
        self._status_var.set('Username copied to clipboard')

    def _on_copy_password(self):
        """Copy selected password to system clipboard"""
        secret_id = self._selected_id()
        if not secret_id:
            messagebox.showinfo('No Selection', 'Please select a secret first')
            return
        secure_copy(self._controller.root, self._decrypted_secrets[secret_id]['password'])
        self._status_var.set('Password copied to clipboard')

    def _on_analyze_url(self):
        """Switch view to the URL analyzer frame"""
        self._controller.show_frame('AnalyzerFrame')

    def _on_logout(self):
        """Clear local data and return to login screen"""
        self._controller.identity_manager.logout()
        self._decrypted_secrets.clear()
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._status_var.set('')
        self._controller.show_frame('LoginFrame')


