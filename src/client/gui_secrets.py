"""
gui_secrets.py defines the SecretModal popup for adding or editing vault items.
"""

# Imports - Default Libraries
import tkinter as tk
from tkinter import ttk

# Imports - External Libraries

# Imports - Internal Modules
from client.util import (
    _encrypt_secret_row,
    _is_session_error,
    center_window,
)
from common.crypto import (
    CryptoError,
    generate_password,
)


# Modal View
class SecretModal(tk.Toplevel):
    """Modal popup for adding or editing an encrypted secret in the vault"""

    _FIELDS = ('name', 'url', 'username', 'password', 'notes')
    _LABELS = {
        'name': 'Name:', 'url': 'URL:', 'username': 'Username:',
        'password': 'Password:', 'notes': 'Notes:',
    }

    def __init__(self, dashboard, controller, mode='add', secret_id=None, prefill=None):
        """Initialize modal and setup event grab"""
        super().__init__(dashboard)
        self._dashboard = dashboard
        self._controller = controller
        self._mode = mode
        self._secret_id = secret_id
        self._prefill = prefill or {}

        # Config - set title and prevent resizing
        self.title('Add Secret' if mode == 'add' else 'Edit Secret')
        self.resizable(False, False)
        self.grab_set()

        self._build_widgets()
        center_window(self, self.master)

    def _build_widgets(self):
        """Construct the input form and action buttons"""
        # Layout - create main padding container
        outer = ttk.Frame(self, padding=24)
        outer.pack(fill='both', expand=True)
        outer.grid_columnconfigure(1, weight=1)

        # Fields - dynamically create labels and entry fields
        self._vars = {}
        for i, field in enumerate(self._FIELDS):
            ttk.Label(outer, text=self._LABELS[field]).grid(
                row=i, column=0, sticky='e', padx=(0, 10), pady=6
            )
            var = tk.StringVar(value=self._prefill.get(field, ''))
            self._vars[field] = var
            entry = ttk.Entry(
                outer, textvariable=var,
                show='*' if field == 'password' else '',
                width=34
            )
            entry.grid(row=i, column=1, sticky='ew', pady=6)

        # Generator - quick password creation button
        ttk.Button(outer, text='Generate', command=self._generate_password).grid(
            row=self._FIELDS.index('password'), column=2, padx=(6, 0), pady=6
        )

        # Options - configure character sets for generation
        gen_frame = ttk.LabelFrame(outer, text='Generator Options', padding=6)
        gen_frame.grid(row=len(self._FIELDS), column=0, columnspan=3, sticky='ew', pady=(8, 0))

        ttk.Label(gen_frame, text='Length:').grid(row=0, column=0, sticky='w', padx=(0, 4))
        self._length_var = tk.IntVar(value=16)
        self._length_spin = ttk.Spinbox(gen_frame, from_=8, to=128, width=5, textvariable=self._length_var)
        self._length_spin.grid(row=0, column=1, sticky='w', padx=(0, 12))

        self._upper_var = tk.BooleanVar(value=True)
        self._lower_var = tk.BooleanVar(value=True)
        self._digit_var = tk.BooleanVar(value=True)
        self._symbol_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(gen_frame, text='A-Z', variable=self._upper_var).grid(row=0, column=2, padx=4)
        ttk.Checkbutton(gen_frame, text='a-z', variable=self._lower_var).grid(row=0, column=3, padx=4)
        ttk.Checkbutton(gen_frame, text='0-9', variable=self._digit_var).grid(row=0, column=4, padx=4)
        ttk.Checkbutton(gen_frame, text='!@#', variable=self._symbol_var).grid(row=0, column=5, padx=4)

        # Actions - save or cancel buttons
        btn_row = ttk.Frame(outer)
        btn_row.grid(row=len(self._FIELDS) + 1, column=0, columnspan=3, pady=(16, 0))
        ttk.Button(btn_row, text='Save', command=self._save_action, width=10).pack(side='left', padx=8)
        ttk.Button(btn_row, text='Cancel', command=self.destroy, width=10).pack(side='left', padx=8)

        # Status - display error messages
        self._status_var = tk.StringVar()
        ttk.Label(outer, textvariable=self._status_var, foreground='red', wraplength=360).grid(
            row=len(self._FIELDS) + 2, column=0, columnspan=3, pady=(8, 0)
        )

    def _generate_password(self):
        """Fill password field with a random string based on options"""
        generated = generate_password(
            length=self._length_var.get(),
            uppercase=self._upper_var.get(),
            lowercase=self._lower_var.get(),
            digits=self._digit_var.get(),
            symbols=self._symbol_var.get(),
        )
        self._vars['password'].set(generated)

    def _save_action(self):
        """Encrypt all fields and send update/save request to server"""
        im = self._controller.identity_manager
        vault_key = im.vault_key
        payload = {}

        # Encryption - process each field locally
        try:
            plaintext_dict = {field: self._vars[field].get() for field in self._FIELDS}
            encrypted_fields = _encrypt_secret_row(plaintext_dict, vault_key)
            payload.update(encrypted_fields)
        except CryptoError as e:
            self._status_var.set(f'Encryption error: {e}')
            return

        # Network - dispatch appropriate action based on mode
        if self._mode == 'edit':
            payload['secret_id'] = int(self._secret_id)
            action = 'update_secret'
        else:
            action = 'save_secret'

        try:
            self._controller.network_client.send_request(action, payload, im.session_token)
        except Exception as e:
            if _is_session_error(str(e)):
                self.destroy()
                self._controller.handle_session_expiry()
                return
            self._status_var.set(f'Save failed: {e}')
            return

        # Finish - close modal and refresh parent dashboard
        self.destroy()
        self._dashboard.refresh_vault()
