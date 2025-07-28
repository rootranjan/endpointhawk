#!/usr/bin/env python3
"""
EndPointHawk Attack Surface Discovery Tool

Main entry point for the EndPointHawk command line interface.
Scan your repository for API routes and security vulnerabilities.
"""

import sys
import os

# Add the current directory to the Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

# Import and run the main function
from endpointhawk_core.endpointhawk import main

if __name__ == "__main__":
    main() 