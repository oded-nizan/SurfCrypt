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
from client.util import _decrypt_secret_row, _is_session_error
from common.crypto import CryptoError

# Constants - Window
WINDOW_TITLE = 'SurfCrypt'
WINDOW_WIDTH = 900
WINDOW_HEIGHT = 580


# Application Class
class MainApplication:
    """Root application wrapper in charge of the Tk root window, shared service objects, and the frame-routing 
    mechanism"""

    def __init__(self):
        self.root = tk.Tk()
        self.root.title(WINDOW_TITLE)
        self.root.geometry(f'{WINDOW_WIDTH}x{WINDOW_HEIGHT}')
        self.root.minsize(700, 460)

        self.network_client = NetworkClient()
        self.identity_manager = IdentityManager(self.network_client)

        # Container stacks all frames on top of each other; tkraise() selects active one
        container = ttk.Frame(self.root)
        container.pack(fill='both', expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for FrameClass in (LoginFrame, DashboardFrame):
            frame = FrameClass(parent=container, controller=self)
            self.frames[FrameClass.__name__] = frame
            frame.grid(row=0, column=0, sticky='nsew')

        # AnalyzerFrame needs special constructor args
        analyzer_frame = AnalyzerFrame(
            parent=container,
            network_client=self.network_client,
            get_token=lambda: self.identity_manager.session_token,
        )
        self.frames['AnalyzerFrame'] = analyzer_frame
        analyzer_frame.grid(row=0, column=0, sticky='nsew')

        self.show_frame('LoginFrame')

        # Keyboard shortcuts (root-level so they work from any frame)
        self.root.bind('<Control-n>', lambda _: self._shortcut_add())
        self.root.bind('<Control-f>', lambda _: self._shortcut_search())
        self.root.bind('<Control-r>', lambda _: self._shortcut_refresh())
        self.root.bind('<Delete>', lambda _: self._shortcut_delete())
        self.root.bind('<Control-u>', lambda _: self._shortcut_copy_username())
        self.root.bind('<Control-p>', lambda _: self._shortcut_copy_password())
        self.root.bind('<Escape>', lambda _: self._shortcut_escape())

    def _shortcut_add(self):
        if self._current_frame == 'DashboardFrame':
            self.frames['DashboardFrame']._on_add()

    def _shortcut_search(self):
        if self._current_frame == 'DashboardFrame':
            self.frames['DashboardFrame']._focus_search()

    def _shortcut_refresh(self):
        if self._current_frame == 'DashboardFrame':
            self.frames['DashboardFrame'].refresh_vault()

    def _shortcut_delete(self):
        if self._current_frame == 'DashboardFrame':
            self.frames['DashboardFrame']._on_delete()

    def _shortcut_copy_username(self):
        if self._current_frame == 'DashboardFrame':
            self.frames['DashboardFrame']._on_copy_username()

    def _shortcut_copy_password(self):
        if self._current_frame == 'DashboardFrame':
            self.frames['DashboardFrame']._on_copy_password()

    def _shortcut_escape(self):
        if self._current_frame == 'AnalyzerFrame':
            self.show_frame('DashboardFrame')

    def show_frame(self, frame_name):
        """Raise named frame to the top and call its on_show() lifecycle hook"""
        self._current_frame = frame_name
        frame = self.frames[frame_name]
        frame.tkraise()
        frame.on_show()

    def handle_session_expiry(self):
        """Clears identity state, notifies the user, and returns to LoginFrame whenever a server response signals an
        invalid or expired session"""
        self.identity_manager.logout()
        messagebox.showwarning(
            'Session Expired',
            'Your session has expired. Please log in again.'
        )
        self.frames['LoginFrame'].set_status('')
        self.show_frame('LoginFrame')

    def run(self):
        self.root.mainloop()


# LoginFrame Class
class LoginFrame(ttk.Frame):
    """Authentication view. Handles both login and registration workflows using IdentityManager"""

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        self._build_ui()

    def _build_ui(self):
        # Use a centered inner frame so layout survives window resizing
        inner = ttk.Frame(self, padding=40)
        inner.place(relx=0.5, rely=0.5, anchor='center')

        ttk.Label(inner, text='SurfCrypt', font=('Helvetica', 22, 'bold')).grid(
            row=0, column=0, columnspan=2, pady=(0, 28)
        )

        ttk.Label(inner, text='Username:').grid(row=1, column=0, sticky='e', padx=(0, 10), pady=7)
        self._username_var = tk.StringVar()
        self._username_entry = ttk.Entry(inner, textvariable=self._username_var, width=28)
        self._username_entry.grid(row=1, column=1, pady=7, sticky='ew')

        ttk.Label(inner, text='Master Password:').grid(row=2, column=0, sticky='e', padx=(0, 10), pady=7)
        self._password_var = tk.StringVar()
        ttk.Entry(inner, textvariable=self._password_var, show='*', width=28).grid(
            row=2, column=1, pady=7, sticky='ew'
        )

        btn_row = ttk.Frame(inner)
        btn_row.grid(row=3, column=0, columnspan=2, pady=18)
        ttk.Button(btn_row, text='Login', command=self._on_login, width=12).pack(side='left', padx=8)
        ttk.Button(btn_row, text='Register', command=self._on_register, width=12).pack(side='left', padx=8)

        self._status_var = tk.StringVar()
        self._status_label = ttk.Label(
            inner, textvariable=self._status_var, foreground='red', wraplength=320
        )
        self._status_label.grid(row=4, column=0, columnspan=2)

    def on_show(self):
        """Reset form content and set focus whenever we return to the login screen"""
        self._username_var.set('')
        self._password_var.set('')
        self.set_status('')
        self._username_entry.focus_set()

    def set_status(self, message, color='red'):
        """Update the status label text and color."""
        self._status_var.set(message)
        self._status_label.configure(foreground=color)

    def _credentials(self):
        return self._username_var.get().strip(), self._password_var.get()

    def _on_login(self):
        username, password = self._credentials()
        if not username or not password:
            self.set_status('Username and password are required.')
            return
        self.set_status('Logging in...', color='gray')
        self.update_idletasks()
        try:
            self.controller.identity_manager.login(username, password)
        except Exception as e:
            self.set_status('Login failed. Please check your credentials or network connection.')
            return
        self._password_var.set('')
        self.set_status('')
        self.controller.show_frame('DashboardFrame')

    def _on_register(self):
        username, password = self._credentials()
        if not username or not password:
            self.set_status('Username and password are required.')
            return
        self.set_status('Registering...', color='gray')
        self.update_idletasks()
        try:
            self.controller.identity_manager.register(username, password)
        except Exception as e:
            self.set_status(f'Registration failed')
            return
        self._password_var.set('')
        self.set_status('Registration successful. You may now log in.', color='green')


# DashboardFrame Class
class DashboardFrame(ttk.Frame):
    """
    Vault view to display secrets in a treeview grid.
    Plaintext data is cached so that Edit and Copy actions don't require a second server round-trip
    """

    _COLUMNS = ('name', 'url', 'username')
    _COL_HEADERS = {'name': 'Name', 'url': 'URL', 'username': 'Username'}
    _COL_WIDTHS = {'name': 240, 'url': 280, 'username': 200}

    def __init__(self, parent, controller):
        super().__init__(parent)
        self.controller = controller
        # Decrypted plaintext cache: { secret_id_str: { 'name': ..., 'url': ..., ... } }
        self.decrypted_secrets = {}

        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._build_top_bar()
        self._build_treeview()
        self._build_action_bar()
        self._build_context_menu()

    # Build UI
    def _build_top_bar(self):
        bar = ttk.Frame(self, padding=(10, 7))
        bar.grid(row=0, column=0, sticky='ew')

        self._user_label = ttk.Label(bar, text='', font=('Helvetica', 10, 'bold'))
        self._user_label.pack(side='left', padx=(2, 18))

        ttk.Button(bar, text='Refresh', command=self.refresh_vault).pack(side='left', padx=4)
        ttk.Button(bar, text='Add Secret', command=self._on_add).pack(side='left', padx=4)
        ttk.Button(bar, text='Analyze URL', command=self._on_analyze_url).pack(side='left', padx=4)
        ttk.Button(bar, text='Logout', command=self._on_logout).pack(side='right', padx=4)

        # Search bar
        self._search_var = tk.StringVar()
        self._search_var.trace_add('write', lambda *_: self._apply_search())
        self._search_entry = ttk.Entry(bar, textvariable=self._search_var, width=20)
        self._search_entry.pack(side='right', padx=(4, 8))
        ttk.Label(bar, text='Search:').pack(side='right')

    def _build_treeview(self):
        frame = ttk.Frame(self)
        frame.grid(row=1, column=0, sticky='nsew', padx=8, pady=4)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            frame, columns=self._COLUMNS, show='headings', selectmode='browse'
        )
        for col in self._COLUMNS:
            self.tree.heading(col, text=self._COL_HEADERS[col], anchor='w')
            self.tree.column(col, width=self._COL_WIDTHS[col], minwidth=80, anchor='w')

        vsb = ttk.Scrollbar(frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')

        # Double click to edit; right click for context menu
        self.tree.bind('<Double-1>', lambda _e: self._on_edit())
        self.tree.bind('<Button-3>', self._on_right_click)

    def _build_action_bar(self):
        bar = ttk.Frame(self, padding=(8, 5))
        bar.grid(row=2, column=0, sticky='ew')

        ttk.Button(bar, text='Edit', command=self._on_edit).pack(side='left', padx=4)
        ttk.Button(bar, text='Delete', command=self._on_delete).pack(side='left', padx=4)
        ttk.Separator(bar, orient='vertical').pack(side='left', fill='y', padx=6)
        ttk.Button(bar, text='Copy Username', command=self._on_copy_username).pack(side='left', padx=4)
        ttk.Button(bar, text='Copy Password', command=self._on_copy_password).pack(side='left', padx=4)

        self._status_var = tk.StringVar()
        ttk.Label(bar, textvariable=self._status_var, foreground='gray').pack(side='right', padx=10)

    def _build_context_menu(self):
        self._ctx_menu = tk.Menu(self, tearoff=0)
        self._ctx_menu.add_command(label='Edit', command=self._on_edit)
        self._ctx_menu.add_command(label='Copy Username', command=self._on_copy_username)
        self._ctx_menu.add_command(label='Copy Password', command=self._on_copy_password)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label='Delete', command=self._on_delete)

    # Window Methods
    def on_show(self):
        """Called by FrameRouter each time this frame is raised"""
        username = self.controller.identity_manager.username
        self._user_label.configure(text=f'Logged in as:  {username}')
        self.refresh_vault()

    def refresh_vault(self):
        """
        Fetch all encrypted secrets for the current user, decrypt every field
        locally with VaultKey, and repopulate the Treeview.
        Skips corrupted rows without crashing the entire refresh
        """
        im = self.controller.identity_manager
        try:
            response = self.controller.network_client.send_request(
                'sync_secrets', {}, im.session_token
            )
        except Exception as e:
            if _is_session_error(str(e)):
                self.controller.handle_session_expiry()
                return
            messagebox.showerror('Network Error', f'Could not fetch secrets:\n{e}')
            return

        rows = response.get('data', {}).get('secrets', [])
        vault_key = im.vault_key

        # Clear stale data
        self.decrypted_secrets.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)

        failed = 0
        for row in rows:
            try:
                plaintext = _decrypt_secret_row(row, vault_key)
            except CryptoError:
                # Corrupted or tampered row
                failed += 1
                continue

            secret_id = str(row['id'])
            self.decrypted_secrets[secret_id] = plaintext
            self.tree.insert(
                '', 'end', iid=secret_id,
                values=(plaintext['name'], plaintext['url'], plaintext['username'])
            )

        count = len(self.decrypted_secrets)
        suffix = f'  ({failed} row(s) could not be decrypted)' if failed else ''
        self._status_var.set(f'{count} secret(s) loaded.{suffix}')
        self._apply_search()  # Re-filter if search is active

    def _apply_search(self):
        """Filter the treeview to show only secrets matching the search query"""
        query = self._search_var.get().strip().lower()

        for iid in self.tree.get_children():
            self.tree.delete(iid)

        for secret_id, plaintext in self.decrypted_secrets.items():
            if query:
                searchable = ' '.join([
                    plaintext.get('name', ''),
                    plaintext.get('url', ''),
                    plaintext.get('username', ''),
                    plaintext.get('notes', ''),
                ]).lower()
                if query not in searchable:
                    continue
            self.tree.insert(
                '', 'end', iid=secret_id,
                values=(plaintext['name'], plaintext['url'], plaintext['username'])
            )

    def _focus_search(self):
        """Set focus to the search entry (Ctrl+F shortcut)"""
        self._search_entry.focus_set()
        self._search_entry.select_range(0, 'end')

    # Row Action Handlers
    def _selected_id(self):
        """Return the iid of the currently selected Treeview row, or None"""
        sel = self.tree.selection()
        return sel[0] if sel else None

    def _on_right_click(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self._ctx_menu.post(event.x_root, event.y_root)

    def _on_add(self):
        SecretModal(self, self.controller, mode='add')

    def _on_edit(self):
        secret_id = self._selected_id()
        if not secret_id:
            messagebox.showinfo('No Selection', 'Please select a secret to edit.')
            return
        plaintext = self.decrypted_secrets.get(secret_id, {})
        SecretModal(self, self.controller, mode='edit', secret_id=secret_id, prefill=plaintext)

    def _on_delete(self):
        secret_id = self._selected_id()
        if not secret_id:
            messagebox.showinfo('No Selection', 'Please select a secret to delete.')
            return
        if not messagebox.askyesno('Confirm Delete', 'Permanently delete this secret?'):
            return

        im = self.controller.identity_manager
        try:
            self.controller.network_client.send_request(
                'delete_secret', {'secret_id': int(secret_id)}, im.session_token
            )
        except Exception as e:
            if _is_session_error(str(e)):
                self.controller.handle_session_expiry()
                return
            messagebox.showerror('Error', f'Failed to delete secret:\n{e}')
            return

        self.refresh_vault()

    def _on_copy_username(self):
        secret_id = self._selected_id()
        if not secret_id:
            messagebox.showinfo('No Selection', 'Please select a secret first.')
            return
        self._copy_to_clipboard(self.decrypted_secrets[secret_id]['username'])
        self._status_var.set('Username copied to clipboard.')

    def _on_copy_password(self):
        secret_id = self._selected_id()
        if not secret_id:
            messagebox.showinfo('No Selection', 'Please select a secret first.')
            return
        self._copy_to_clipboard(self.decrypted_secrets[secret_id]['password'])
        self._status_var.set('Password copied to clipboard.')

    def _copy_to_clipboard(self, text):
        self.controller.root.clipboard_clear()
        self.controller.root.clipboard_append(text)
        # Auto clear clipboard after 30 seconds (security)
        self.controller.root.after(30000, self.controller.root.clipboard_clear)

    def _on_analyze_url(self):
        """Switch to the URL analyzer frame"""
        self.controller.show_frame('AnalyzerFrame')

    def _on_logout(self):
        self.controller.identity_manager.logout()
        self.decrypted_secrets.clear()
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._status_var.set('')
        self.controller.show_frame('LoginFrame')


