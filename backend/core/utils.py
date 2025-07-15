import sys
import os

def resource_path(relative_path):
    """
    Get the absolute path to a resource, which works for both development
    and for a PyInstaller-bundled application.
    """
    try:
        # PyInstaller creates a temp folder and stores its path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # Not running in a bundle, so the base path is the project's root
        # This assumes your script is run from the project root in development
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)