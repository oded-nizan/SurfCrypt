"""
__main__.py is the primary entry point for starting the SurfCrypt client GUI.
"""

# Imports - Default Libraries
import sys
from pathlib import Path

# Path Configuration - ensure src is in path for internal module imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Imports - External Libraries
from dotenv import load_dotenv

# Imports - Internal Modules
from client.gui_client import MainApplication


# Internal Functions - Entry Point
def main():
    """Initialize and start the SurfCrypt MainApplication GUI"""
    load_dotenv()

    app = MainApplication()
    app.run()


if __name__ == '__main__':
    main()
