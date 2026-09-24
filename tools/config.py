"""
config.py

Default target settings for the driver scripts in tools/. Edit the values
below to set your own defaults — nothing else in tools/ should need touching.

For one-off runs (e.g. trying a series of offsets while working out a layout)
you don't have to edit this file at all: every driver also takes these as
command-line flags or environment variables, which take precedence over the
values here (CLI > env > this file):

    --target ID    / FRIDA_TARGET        overrides TARGET
    --remote H:P   / FRIDA_REMOTE_ADDR   overrides REMOTE_ADDR
    --offset HEX   / FRIDA_OFFSET        overrides FRIDA_OFFSET (hex, 0x optional)

See tools/_common.py.
"""

# Package/bundle id of the app to spawn and attach to.
TARGET = "com.example.unitygame"

# frida-server address (host:port). 27042 is frida-server's default
# listening port — change this if you're forwarding a non-default port,
# e.g. `adb forward tcp:1234 tcp:27042` -> "127.0.0.1:1234".
REMOTE_ADDR = "127.0.0.1:27042"

# Build-specific RVA (Image Base = 0) of the unpack function currently
# being hooked by whichever scripts/*.js agent you're running via
# run_hd_quality_dump.py. Find this yourself via Ghidra's Symbol Table
# for your own build — see docs/ITERATION_HISTORY.md for the methodology
# for finding it. Leave at 0x0 and the driver/agent will refuse
# to run with a reminder, instead of silently hooking the wrong address.
FRIDA_OFFSET = 0x0  # <-- SET THIS
