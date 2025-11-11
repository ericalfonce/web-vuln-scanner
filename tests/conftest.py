"""
Pytest configuration and fixtures.
Ensures src module is importable from tests.
"""

import sys
import os

# Add the project root to the Python path
project_root = os.path.dirname(__file__)
src_path = os.path.join(project_root, '..')
if src_path not in sys.path:
    sys.path.insert(0, src_path)
