"""Shared utility functions for Amnezia Web Panel."""
import re


def parse_wg_dump(output: str) -> dict:
    """Parse 'wg show all dump' output.
    Returns {pubkey: {rx, tx, last_seen}}
    """
    result = {}
    for line in output.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) < 8:
            continue
        pub_key = parts[1]
        if not pub_key or pub_key == "(none)":
            continue
        try:
            last_seen = int(parts[5]) if parts[5] and parts[5] != "0" else None
            rx = int(parts[6]) if parts[6].isdigit() else 0
            tx = int(parts[7]) if parts[7].isdigit() else 0
            result[pub_key] = {"rx": rx, "tx": tx, "last_seen": last_seen}
        except (ValueError, IndexError):
            pass
    return result
