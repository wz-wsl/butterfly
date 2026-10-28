"""Compatibility launcher: python butterfly.py [original options]."""

from butterfly.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
