"""PyInstaller entry point: the one executable the installers ship."""
import sys

from votal_device_agent.__main__ import main

if __name__ == "__main__":
    sys.exit(main())
