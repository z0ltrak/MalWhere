#!/usr/bin/env python3
"""
Fetch the official MITRE ATT&CK Enterprise STIX bundle for offline,
authoritative technique-name resolution (tier 1 in src/technique_names.py).

One-time, host-side, network-requiring step. It is NOT part of the
offline-safe analysis pipeline itself: map_attck.py works fine without this,
falling back to the smaller hardcoded dict in
src/technique_names.py's TECHNIQUE_NAME_FALLBACK. Run this once, and every
future map_attck.py run (including the resubmission loop) auto-detects the
saved bundle and uses it for every technique ID, not just previously-seen
ones.

Usage:
    python3 pipeline/mapper/fetch_attck_bundle.py
"""

import argparse
import hashlib
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from src.technique_names import DEFAULT_BUNDLE_PATH

# Pinned to a specific tag (not "master") so the bundle's content -- and its
# checksum below -- can't silently change out from under this project.
ATTCK_TAG = "ATT&CK-v19.2"
BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/"
    f"{urllib.parse.quote(ATTCK_TAG, safe='')}/enterprise-attack/enterprise-attack.json"
)
EXPECTED_SHA256 = "f7eaf37fe53b50404084fe1fe67237278f7317e61c11ad550295722d13ede259"


def sha256sum(path: Path) -> str:
    """Compute a file's SHA-256 digest, reading it in chunks.

    Args:
        path: File to hash.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    """Download and checksum-verify the pinned ATT&CK bundle.

    Returns:
        Process exit code: 0 on success (including "already up to date"), 1 on download/checksum failure.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", "-o",
        default=str(DEFAULT_BUNDLE_PATH),
        help=f"Where to save the bundle (default: {DEFAULT_BUNDLE_PATH})"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download even if a valid copy already exists"
    )
    args = parser.parse_args()

    output = Path(args.output)

    if output.exists() and not args.force:
        if sha256sum(output) == EXPECTED_SHA256:
            print(f"Already up to date: {output}")
            return 0
        print(f"Existing file at {output} doesn't match the expected checksum -- re-downloading.")

    print(f"Fetching {ATTCK_TAG} enterprise-attack.json from MITRE's public CTI repo...")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        urllib.request.urlretrieve(BUNDLE_URL, output)
    except (OSError, urllib.error.URLError) as e:
        print(f"Download failed: {e}", file=sys.stderr)
        return 1

    actual = sha256sum(output)
    if actual != EXPECTED_SHA256:
        output.unlink()
        print(
            f"Checksum mismatch (expected {EXPECTED_SHA256}, got {actual}) -- "
            "deleted, not trusting this download.",
            file=sys.stderr,
        )
        return 1

    print(f"Saved and verified: {output}")
    print("map_attck.py will now use it automatically for authoritative technique names.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
