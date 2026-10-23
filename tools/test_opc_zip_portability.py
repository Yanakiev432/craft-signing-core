#!/usr/bin/env python3
"""Read-only Office ZIP portability checks on disposable DOCX/XLSX specimens.

Usage: python -I test_opc_zip_portability.py unsigned.docx signed.docx
Checks ZIP32 and local-header style, preserved source OPC document parts, and
signature metadata presence. Cryptographic validity MUST be independently
checked using the Windows native OPC verifier (not by this script).
"""
import hashlib
import json
import pathlib
import sys
import zipfile

SIGNATURE_PREFIX = "package/services/digital-signature/"
MAX_INPUT_BYTES = 1024 * 1024 * 1024

def checked_package(path):
    if path.stat().st_size > MAX_INPUT_BYTES or path.stat().st_size == 0:
        raise ValueError("input size out of accepted range")
    with zipfile.ZipFile(path) as package:
        if len(package.infolist()) > 65535:
            raise ValueError("too many ZIP32 parts")
        if len({x.filename for x in package.infolist()}) != len(package.infolist()):
            raise ValueError("repeated package entries")
        if package.testzip() is not None:
            raise ValueError("ZIP CRC mismatch")
        return {name: package.read(name) for name in package.namelist()}, [
            {"name": i.filename, "min_reader_version": i.extract_version,
             "flag_bits": i.flag_bits, "compression": i.compress_type}
            for i in package.infolist()
        ]

def main():
    if len(sys.argv) != 3:
        raise ValueError("expected UNSIGNED.docx/.xlsx SIGNED.docx/.xlsx")
    unsigned = pathlib.Path(sys.argv[1]).resolve(strict=True)
    signed = pathlib.Path(sys.argv[2]).resolve(strict=True)
    if unsigned.suffix.lower() not in (".docx", ".xlsx") or unsigned.suffix.lower() != signed.suffix.lower():
        raise ValueError("source and signed output must have identical Office format")
    original, _ = checked_package(unsigned)
    converted, metadata = checked_package(signed)
    if not all(entry["min_reader_version"] <= 20 and entry["flag_bits"] & 8 == 0 for entry in metadata):
        raise ValueError("Windows OPC ZIP64/data-descriptor layout not normalized")
    if not all(entry["compression"] in (0, 8) for entry in metadata):
        raise ValueError("unsupported ZIP compression")
    if not any(name.endswith(".psdsxs") and name.startswith(SIGNATURE_PREFIX) for name in converted):
        raise ValueError("Office XML signature part not found")
    for name, contents in original.items():
        if name in ("[Content_Types].xml", "_rels/.rels"):
            continue  # OPC signature origin adds relationships and content types.
        if converted.get(name) != contents:
            raise ValueError("original non-metadata OPC part changed: " + name)
    if not converted.keys() >= original.keys():
        raise ValueError("original package parts missing")
    for name in converted.keys() - original.keys():
        if not name.startswith(SIGNATURE_PREFIX):
            raise ValueError("unexpected new non-signature OPC part: " + name)
    print(json.dumps({
        "result": "PASS", "format": signed.suffix[1:].lower(),
        "signed_zip_entries": len(metadata), "max_reader_version": max(x["min_reader_version"] for x in metadata),
        "all_entries_without_data_descriptor": True,
        "original_non_metadata_parts_preserved": True,
        "signed_sha256": hashlib.sha256(signed.read_bytes()).hexdigest(),
        "cryptographic_validity": "SEPARATELY_REQUIRED",
        "microsoft_office_interoperability": "SEPARATELY_REQUIRED",
    }, sort_keys=True))
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        print(type(error).__name__ + ": " + str(error), file=sys.stderr)
        sys.exit(2)
