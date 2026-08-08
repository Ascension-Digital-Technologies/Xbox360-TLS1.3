#!/usr/bin/env python3
"""Build an XboxTLS XTS1 trust-store blob from DER certificates."""
import argparse
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("output", help="output .xts file")
    ap.add_argument("certificates", nargs="+", help="DER root/intermediate certificates")
    ns = ap.parse_args()
    if len(ns.certificates) > 16:
        ap.error("XboxTLS native verifier currently supports at most 16 trust anchors")
    out = bytearray(b"XTS1")
    out += len(ns.certificates).to_bytes(2, "big")
    for name in ns.certificates:
        der = Path(name).read_bytes()
        if not der or len(der) > 0xFFFFFF:
            ap.error(f"invalid DER size: {name}")
        out += len(der).to_bytes(3, "big")
        out += der
    Path(ns.output).write_bytes(out)
    print(f"wrote {ns.output}: {len(ns.certificates)} certificate(s), {len(out)} bytes")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
