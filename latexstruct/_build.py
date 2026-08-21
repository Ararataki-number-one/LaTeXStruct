"""Build identity embedded into packaged LaTeXStruct executables.

Local source checkouts deliberately remain unknown.  Release CI rewrites this
small generated module immediately before PyInstaller runs, so an installed
binary does not depend on mutable process environment variables for identity.
"""

BUILD_COMMIT = "unknown"
BUILD_ID = "unknown"
