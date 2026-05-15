"""
PYDNS Scanner - A modern, high-performance DNS scanner with a beautiful TUI.

This package provides a Terminal User Interface for scanning IP ranges
to find working DNS servers with optional Slipstream proxy testing.
"""

__version__ = "2.0.5"
__author__ = "xullexer"

# Load .env file before anything else
from dotenv import load_dotenv
load_dotenv()

from python.dnsscanner_tui import main, DNSScannerTUI

__all__ = ["main", "DNSScannerTUI", "__version__"]
