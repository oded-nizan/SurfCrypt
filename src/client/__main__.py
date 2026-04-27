"""
SurfCrypt Client Entry Point
"""

# Imports - Default Libraries
import sys
from pathlib import Path

# Imports - External Libraries
from dotenv import load_dotenv

# Imports - Internal Modules
from client.gui_client import MainApplication

# Ensure src is in path when running as module
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def main():
    load_dotenv()
        
    app = MainApplication()
    app.run()


if __name__ == '__main__':
    main()
