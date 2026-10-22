#!/usr/bin/env python3
"""Print constraint, wire and public-input counts of the bundled predicate circuits (R1CS header)."""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def header(path):
    data = path.read_bytes()
    sections = struct.unpack_from("<I", data, 8)[0]
    offset = 12
    for _ in range(sections):
        kind, length = struct.unpack_from("<IQ", data, offset)
        offset += 12
        if kind == 1:
            field_size = struct.unpack_from("<I", data, offset)[0]
            wires, outputs, inputs, _private, _labels, constraints = struct.unpack_from("<IIIIQI", data, offset + 4 + field_size)
            return constraints, wires, outputs + inputs
        offset += length
    raise SystemExit(f"FAIL: no header in {path}")


def main():
    print(f"{'circuit':<24}{'constraints':>12}{'wires':>8}{'public':>8}")
    for path in sorted((ROOT / "testdata" / "predicates").glob("*.r1cs")):
        constraints, wires, public = header(path)
        print(f"{path.stem:<24}{constraints:>12}{wires:>8}{public:>8}")


if __name__ == "__main__":
    sys.exit(main())
