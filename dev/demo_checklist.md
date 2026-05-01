# SurfCrypt Demo Checklist

This checklist is used to verify all features of SurfCrypt are working correctly in a live demonstration environment.

## 1. Setup and Initialization
- [ ] Ensure the server environment is ready with a clean test database.
- [ ] Start the server (`python -m src.server`). Verify successful initialization and schema creation.
- [ ] Start a client instance (`python -m src.client`).

## 2. Authentication Flow
- [ ] **Registration**: Register a new user (e.g., `alice` / `password123`).
- [ ] **Auto-Login**: Verify that registration immediately logs the user into their empty vault.
- [ ] **Logout**: Use the top-right button to log out. Verify return to login screen.
- [ ] **Manual Login**: Log in manually with the registered credentials.
- [ ] **Invalid Login**: Attempt to log in with an incorrect password and verify the error message.

## 3. Vault Operations
- [ ] **Add Secret**: Use the "Add Secret" button or `Ctrl+N`. Add a new service with URL, username, password, and notes.
- [ ] **View Secrets**: Verify the new secret appears in the Dashboard treeview.
- [ ] **Edit Secret**: Double-click the secret. Modify the password and save. Verify the update.
- [ ] **Search/Filter**: Add a few more secrets. Use the search bar (`Ctrl+F`) to filter them by name, URL, or username.
- [ ] **Copy Shortcuts**: Select a secret, use `Ctrl+U` to copy the username, `Ctrl+P` to copy the password. Paste elsewhere to verify clipboard contents.
- [ ] **Delete Secret**: Select a secret and press Delete (or click the Delete button). Confirm the prompt and verify the secret is removed.

## 4. Multi-Client & Synchronization
- [ ] **Concurrent Sessions**: Keep Alice logged in on Client A. Open a second client instance (Client B) and log in as Alice.
- [ ] **Data Sync**: Add a secret on Client A. On Client B, click "Refresh" (`Ctrl+R`). Verify the new secret appears.
- [ ] **Cross-User Isolation**: Log out of Client B and register a new user, `bob`. Verify Bob's vault is completely empty and cannot see Alice's secrets.

## 5. Security & Expiry
- [ ] **Session Expiry**: Simulate session expiry (by altering DB or testing short-lived tokens). Attempt to refresh the vault. Verify the client shows an expiration warning and redirects to the login screen.

## 6. URL Analyzer
- [ ] **Navigation**: Click "Analyze URL" from the dashboard.
- [ ] **Safe URL**: Enter `https://github.com` and analyze. Verify the verdict is SAFE.
- [ ] **Shortened URL**: Enter `bit.ly/3svvPmV` (or another shortened URL). Verify it successfully expands and gives a valid result.
- [ ] **Back Navigation**: Click "Back to Vault" to ensure correct routing back to the dashboard.
- [ ] **Cache Retrieval**: Re-enter the same URL and ensure the analyzer retrieves the result quickly from the cache. Check the UI details to confirm.
- [ ] **Suspicious URLs**: Enter a URL with excess subdomains or one triggering automatic downloads. Verify the verdict is UNKNOWN or SUSPICIOUS.
