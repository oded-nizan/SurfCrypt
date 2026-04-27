"""
gui_secrets.py defines the SecretModal popup of the GUI separately to relieve pressure from gui_client.py
"""

# Imports - Default Libraries
import tkinter as tk
from tkinter import ttk

# Imports - Internal Modules
from common.crypto import encrypt_field, CryptoError, generate_password
from client.util import _is_session_error


# SecretModal Class
class SecretModal(tk.Toplevel):
    """
    Modal popup for adding a new secret or editing an existing one.
    Encrypts every field individually with VaultKey before sending to the server
    """

    _FIELDS = ('name', 'url', 'username', 'password', 'notes')
    _LABELS = {
        'name': 'Name:', 'url': 'URL:', 'username': 'Username:',
        'password': 'Password:', 'notes': 'Notes:',
    }

    def __init__(self, dashboard, controller, mode='add', secret_id=None, prefill=None):
        super().__init__(dashboard)
        self.dashboard = dashboard
        self.controller = controller
        self.mode = mode            # add | edit
        self.secret_id = secret_id
        self.prefill = prefill or {}

        self.title("Add Secret" if mode == "add" else "Edit Secret")
        self.resizable(False, False)
        self.grab_set()             # Block interaction with parent while open

        self._build_ui()
        self._center_on_parent()

    def _build_ui(self):
        outer = ttk.Frame(self, padding=24)
        outer.pack(fill='both', expand=True)
        outer.grid_columnconfigure(1, weight=1)

        self._vars = {}
        for i, field in enumerate(self._FIELDS):
            ttk.Label(outer, text=self._LABELS[field]).grid(
                row=i, column=0, sticky='e', padx=(0, 10), pady=6
            )
            var = tk.StringVar(value=self.prefill.get(field, ''))
            self._vars[field] = var
            entry = ttk.Entry(
                outer, textvariable=var,
                show='*' if field == 'password' else '',
                width=34
            )
            entry.grid(row=i, column=1, sticky='ew', pady=6)

        # Generate button sits in column 2 on the password row
        ttk.Button(outer, text='Generate', command=self._generate_password).grid(
            row=self._FIELDS.index('password'), column=2, padx=(6, 0), pady=6
        )

        # Password generator options panel
        gen_frame = ttk.LabelFrame(outer, text='Generator Options', padding=6)
        gen_frame.grid(row=len(self._FIELDS), column=0, columnspan=3, sticky='ew', pady=(8, 0))

        # Length control
        ttk.Label(gen_frame, text='Length:').grid(row=0, column=0, sticky='w', padx=(0, 4))
        self._length_var = tk.IntVar(value=16)
        self._length_spin = ttk.Spinbox(gen_frame, from_=8, to=128, width=5,
                                         textvariable=self._length_var)
        self._length_spin.grid(row=0, column=1, sticky='w', padx=(0, 12))

        # Character set checkboxes
        self._upper_var = tk.BooleanVar(value=True)
        self._lower_var = tk.BooleanVar(value=True)
        self._digit_var = tk.BooleanVar(value=True)
        self._symbol_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(gen_frame, text='A-Z', variable=self._upper_var).grid(row=0, column=2, padx=4)
        ttk.Checkbutton(gen_frame, text='a-z', variable=self._lower_var).grid(row=0, column=3, padx=4)
        ttk.Checkbutton(gen_frame, text='0-9', variable=self._digit_var).grid(row=0, column=4, padx=4)
        ttk.Checkbutton(gen_frame, text='!@#', variable=self._symbol_var).grid(row=0, column=5, padx=4)

        # Action buttons
        btn_row = ttk.Frame(outer)
        btn_row.grid(row=len(self._FIELDS) + 1, column=0, columnspan=3, pady=(16, 0))
        ttk.Button(btn_row, text='Save', command=self._save_action, width=10).pack(side='left', padx=8)
        ttk.Button(btn_row, text='Cancel', command=self.destroy, width=10).pack(side='left', padx=8)

        self._status_var = tk.StringVar()
        ttk.Label(
            outer, textvariable=self._status_var, foreground='red', wraplength=360
        ).grid(row=len(self._FIELDS) + 2, column=0, columnspan=3, pady=(8, 0))

    def _center_on_parent(self):
        self.update_idletasks()
        px = self.master.winfo_rootx() + self.master.winfo_width() // 2
        py = self.master.winfo_rooty() + self.master.winfo_height() // 2
        w, h = self.winfo_width(), self.winfo_height()
        self.geometry(f'+{px - w // 2}+{py - h // 2}')

    def _generate_password(self):
        """Fill the password field with a cryptographically random string using customizable options"""
        generated = generate_password(
            length=self._length_var.get(),
            uppercase=self._upper_var.get(),
            lowercase=self._lower_var.get(),
            digits=self._digit_var.get(),
            symbols=self._symbol_var.get(),
        )
        self._vars['password'].set(generated)

    def _save_action(self):
        """Encrypt each field individually, build the server payload, and dispatch"""

        vault_key = self.controller.identity_manager.vault_key
        im = self.controller.identity_manager
        payload = {}

        try:
            for field in self._FIELDS:
                plaintext = self._vars[field].get()
                cipher_bytes, field_nonce = encrypt_field(plaintext, vault_key)
                payload[f'{field}_encrypted'] = cipher_bytes.hex()
                payload[f'nonce_{field}'] = field_nonce.hex()
        except CryptoError as e:
            self._status_var.set(f'Encryption error: {e}')
            return

        if self.mode == 'edit':
            payload["secret_id"] = int(self.secret_id)
            action = "update_secret"
        else:
            action = "save_secret"

        try:
            self.controller.network_client.send_request(action, payload, im.session_token)
        except Exception as e:
            if _is_session_error(str(e)):
                self.destroy()
                self.controller.handle_session_expiry()
                return
            self._status_var.set(f'Save failed: {e}')
            return

        self.destroy()
        self.dashboard.refresh_vault()
