#!/usr/bin/env python3
"""Synthetic-only negative tests for native Office visual signing.

Never opens, modifies or signs personal files. Ensures unsafe OPC/OOXML inputs
fail closed and leave originals unmodified. Development certificate only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import warnings
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = (ROOT / "target").resolve()
SOURCE = TARGET / "office-realistic-interop-20261023"
SIGNED = TARGET / "native-identity-appearance-20261023"
BINARY = TARGET / "debug" / "examples" / "office_visible_smoke.exe"
IMAGE = TARGET / "pdfcraft-office-appearance-2dc971c3fa2b4744acd78cf3e12638be" / "SignaturePreview.png"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inject_xml(entries: dict[str, bytes], name: str, end: bytes, addition: bytes) -> dict[str, bytes]:
    result = dict(entries)
    if end not in result[name]:
        raise ValueError(f"Missing fixture XML closing tag {end!r} in {name}")
    result[name] = result[name].replace(end, addition + end, 1)
    return result


def rewrite_zip(source: Path, dest: Path, kind: str, ext: str) -> None:
    with zipfile.ZipFile(source) as z:
        entries = {k: z.read(k) for k in z.namelist()}
    if kind == "path_traversal":
        entries["../not-allowed.txt"] = b"do not extract"
    elif kind == "unsupported_compression":
        pass
    elif kind in ("signature_relationship", "signature_relationship_encoded"):
        suffix = ("digital&#45;signature/origin" if kind.endswith("_encoded")
                  else "digital-signature/origin")
        rel = (f'<Relationship Id="rIdFakeSignature" '
               f'Type="http://schemas.openxmlformats.org/package/2006/relationships/{suffix}" '
               f'Target="obscure-signature-location.bin"/>').encode()
        entries = inject_xml(entries, "_rels/.rels", b"</Relationships>", rel)
    elif kind == "signature_content_type":
        override = (b'<Override PartName="/obscure-signature-location.bin" '
                    b'ContentType="application/vnd.openxmlformats-package.digital-signature-origin"/>')
        entries = inject_xml(entries, "[Content_Types].xml", b"</Types>", override)
    elif kind == "xml_doctype":
        name = "word/document.xml" if ext == "docx" else "xl/worksheets/sheet1.xml"
        entries[name] = b'<!DOCTYPE root [<!ENTITY test "bad">]>' + entries[name]
    elif kind == "broken_content_types":
        entries["[Content_Types].xml"] = b"<Types/>"
    elif kind == "worksheet_drawing_prefixed":
        # Deliberately normal XML prefix, but unsupported existing picture geometry.
        # Must fail *before signing*, not quietly append a second drawing.
        entries = inject_xml(entries, "xl/worksheets/sheet1.xml", b"</worksheet>",
                             b'<x15:drawing xmlns:x15="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                             b'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
                             b'r:id="rId5"/>')
    elif kind == "worksheet_drawing_unprefixed":
        entries = inject_xml(entries, "xl/worksheets/sheet1.xml", b"</worksheet>",
                             b'<drawing xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" r:id="rId5"/>')
    elif kind in {"duplicate_zip_name"}:
        pass
    else:
        raise ValueError("Unhandled mutation: " + kind)
    with zipfile.ZipFile(dest, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
        if kind == "duplicate_zip_name":
            first = next(iter(entries))
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                z.writestr(first, b"repeated OPC part")
        if kind == "unsupported_compression":
            z.writestr("unsafe-bzip2.bin", b"unsafe-compression", compress_type=zipfile.ZIP_BZIP2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev-thumbprint", required=True)
    ap.add_argument("--report-tag", default="20261023")
    args = ap.parse_args()
    if not args.report_tag.replace("-", "").isalnum() or len(args.report_tag) > 40:
        raise ValueError("Invalid report tag")
    thumb = args.dev_thumbprint
    if len(thumb) != 40 or any(c not in "0123456789abcdefABCDEF" for c in thumb):
        raise ValueError("Expected explicit 40-character development certificate thumbprint")
    if not BINARY.is_file() or not IMAGE.is_file():
        raise FileNotFoundError("Native test binary or local test PNG missing")
    output = TARGET / f"native-visible-negative-{args.report_tag}"
    if output.exists():
        raise ValueError("Refusing existing test directory: " + str(output))
    output.mkdir()
    checks = []
    for ext in ("docx", "xlsx"):
        source = SOURCE / f"sample.{ext}"
        if not source.is_file():
            raise FileNotFoundError(source)
        case_ids = ["duplicate_zip_name", "path_traversal", "unsupported_compression",
                    "xml_doctype", "broken_content_types", "signature_relationship",
                    "signature_relationship_encoded", "signature_content_type"]
        if ext == "xlsx":
            case_ids += ["worksheet_drawing_unprefixed", "worksheet_drawing_prefixed"]
        src_signed = SIGNED / f"CertificateBoundAppearance-Signed.{ext}"
        case_ids += ["already_signed"]
        for case in case_ids:
            mutant = output / f"{case}.{ext}"
            if case == "already_signed":
                shutil.copyfile(src_signed, mutant)
            else:
                rewrite_zip(source, mutant, case, ext)
            before = sha(mutant)
            result_file = output / f"{case}-signed.{ext}"
            cmd = [str(BINARY), str(mutant), str(result_file), str(IMAGE), thumb, "Craft test signer"]
            result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=45)
            combined = result.stdout + "\n" + result.stderr
            rejected = result.returncode != 0 and not result_file.exists()
            if case.startswith("worksheet_drawing"):
                rejected = rejected and "Unsupported worksheet or existing drawing" in combined
            if case == "already_signed":
                rejected = rejected and "Already signed document" in combined
            unchanged = sha(mutant) == before
            passes = rejected and unchanged
            entry = {"case": case, "format": ext, "passed": passes,
                     "failure_expected": True,
                     "failed_closed": rejected, "original_unchanged": unchanged,
                     "output_created": result_file.exists(),
                     "observed_error": (result.stderr or result.stdout).strip()[:210]}
            checks.append(entry)
            print(f"NEGATIVE_{ext.upper()}_{case}={'PASS' if passes else 'FAIL'}", flush=True)
    report = {"schema": "craft.office.visible-opc.negative-test.v1",
              "status": "PASS" if all(c["passed"] for c in checks) else "FAIL",
              "checks_total": len(checks), "checks_pass": sum(c["passed"] for c in checks),
              "checks": checks, "fixtures": "synthetic_only",
              "certificate": "local_software_dev_only",
              "personal_documents_modified": False}
    (output / "acceptance.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("REPORT=" + str(output / "acceptance.json"), flush=True)
    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
