"""Shared thresholds used across the static pipeline.

Single source of truth for decryption_engine.py, magic_carver.py, and
entropy_detector.py, which otherwise each independently defined the same
names/values. Some call sites (indicators.py, packer_parser.py,
attck_mapper.py, analyzer.py) still use the raw literals inline.
"""

# Shannon entropy (bits/byte, max 8.0) above which data is considered
# high-entropy / possibly encrypted or packed.
HIGH_ENTROPY_THRESHOLD = 7.5

# Entropy above which data is considered "very high" -- e.g. skip magic
# carving entirely, since carving for embedded file signatures inside
# what's almost certainly encrypted/random data wastes time and won't
# find anything real.
SKIP_CARVING_THRESHOLD = 7.8
