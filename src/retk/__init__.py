"""retk - Frida/IL2CPP record inspection toolkit (the `retk` command; see cli.py).

Kept free of imports on purpose: `retk --help` must not load frida or capstone, and setup.py reads
__version__ from here at build time."""

__version__ = "1.1.0"
