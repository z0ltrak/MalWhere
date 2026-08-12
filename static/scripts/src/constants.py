"""Shared thresholds used across the static pipeline.

Previously HIGH_ENTROPY_THRESHOLD and SKIP_CARVING_THRESHOLD were each
independently defined (same names, same values) in decryption_engine.py,
magic_carver.py, and entropy_detector.py -- three separate places that
could silently drift out of sync if only one got tuned. Consolidated here
as the single source of truth for those three; call sites that use the
raw literals inline (indicators.py, packer_parser.py, attck_mapper.py,
analyzer.py) were left as-is rather than touched wholesale in the same
pass, to keep this a targeted fix rather than a repo-wide rewrite.
"""

# Shannon entropy (bits/byte, max 8.0) above which data is considered
# high-entropy / possibly encrypted or packed.
HIGH_ENTROPY_THRESHOLD = 7.5

# Entropy above which data is considered "very high" -- e.g. skip magic
# carving entirely, since carving for embedded file signatures inside
# what's almost certainly encrypted/random data wastes time and won't
# find anything real.
SKIP_CARVING_THRESHOLD = 7.8
