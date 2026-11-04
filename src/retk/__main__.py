"""`python -m retk` is the same program as the `retk` command."""
import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
