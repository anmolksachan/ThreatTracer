"""
threattracer.main
~~~~~~~~~~~~~~~~~
Package entry point – called by the ``threattracer`` console script.
"""

from threattracer.cli import app


def app_entry() -> None:
    """Setuptools entry-point wrapper."""
    app()


if __name__ == "__main__":
    app_entry()
