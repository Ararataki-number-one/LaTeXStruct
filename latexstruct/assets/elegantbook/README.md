# Bundled ElegantBook

This directory vendors `elegantbook.cls` v4.7 based on ElegantLaTeX/ElegantBook commit
`8b90c11e4a5ffd9d1e07174011303c133093d09c` together with its LPPL 1.3c-or-later
license. The reviewed local compatibility patch keeps the upstream fonts when
installed, uses explicit Latin Modern fallbacks otherwise, and makes unused
bibliography/decorative packages optional. Missing features still emit warnings
and remain undefined, so a document that actually uses them fails compilation
instead of being silently rendered incorrectly. LaTeXStruct verifies the reviewed
file hashes before compiling or exporting it.

The upstream project is <https://github.com/ElegantLaTeX/ElegantBook>.
