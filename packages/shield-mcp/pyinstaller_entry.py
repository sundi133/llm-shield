"""PyInstaller entry point for the standalone `shield-mcp` binary.

Kept separate from the console_scripts entry so PyInstaller has a concrete
script to freeze. Behaviour is identical to `shield-mcp` (calls the same main).
"""

import sys

from shield_mcp.cli import main

if __name__ == "__main__":
    sys.exit(main())
