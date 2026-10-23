#!/usr/bin/env python3
"""Independently check newly signed, synthetic visible DOCX/XLSX reject edits."""
from __future__ import annotations
import hashlib
import json
import re
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIR = ROOT / "target"
SIGNED = DIR / "native-identity-postfix-20261023"
OUT = DIR / "native-visible-postfix-tamper-fixed-20261023"
VERIFIER = DIR / "debug" / "examples" / "opc_verify_smoke.exe"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(path):
    r = subprocess.run([str(VERIFIER), str(path)], cwd=ROOT,
                       capture_output=True, text=True, timeout=45)
    return r.returncode == 0 and "OPC_VERIFY_PASS" in r.stdout


def make_changed_source(original, dest, target, extension):
    with zipfile.ZipFile(original) as z:
        content = {name: z.read(name) for name in z.namelist()}
    old = content[target]
    if extension == "xlsx":
        # A valid reference change in the signed worksheet (A1:C3 ->
        # A1:D3). The XML remains parseable but the signed part changes.
        new = old.replace(b'ref="A1:C3"', b'ref="A1:D3"', 1)
    else:
        # Word paragraph text, not the generated signature-line metadata.
        new = old.replace(b'craft-test-document', b'craft-test-changed', 1)
        if new == old:
            new = old.replace(b'Craft', b'Tamper', 1)
    if new == old:
        raise ValueError("Could not find a controlled signed XML text to modify")
    content[target] = new
    with zipfile.ZipFile(dest, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in content.items():
            z.writestr(name, data)


def make_extra_part(original, dest, extension):
    with zipfile.ZipFile(original) as z:
        content = {name: z.read(name) for name in z.namelist()}
    part = ("word/" if extension == "docx" else "xl/") + "unlinked-tamper.xml"
    with zipfile.ZipFile(dest, "x", compression=zipfile.ZIP_DEFLATED) as z:
        for name, data in content.items():
            z.writestr(name, data)
        z.writestr(part, b'<tamper xmlns="urn:craft-synthetic-test"/>')
    return part


def main():
    if OUT.exists():
        raise ValueError("Refuse overwriting previous tamper acceptance")
    OUT.mkdir()
    result = []
    for ext in ("docx", "xlsx"):
        original = SIGNED / f"Visible-AfterSecurityFix.{ext}"
        if not original.resolve(strict=True).is_relative_to(DIR.resolve()):
            raise ValueError("Only core target synthetic sources")
        pristine = sha(original)
        if not verify(original):
            raise ValueError(f"Pristine {ext} unexpectedly rejected")
        cases = ("changed_signed_part", "added_unsigned_part")
        for case in cases:
            target = OUT / f"{case}.{ext}"
            if case == "changed_signed_part":
                make_changed_source(original, target,
                                    "word/document.xml" if ext == "docx" else "xl/worksheets/sheet1.xml",
                                    ext)
            else:
                make_extra_part(original, target, ext)
            rejected = not verify(target)
            preserved = sha(original) == pristine
            passed = rejected and preserved
            result.append({"format": ext, "case": case, "passed": passed,
                           "original_preserved": preserved, "signed_mutant_rejected": rejected})
            print(f"TAMPER_{ext.upper()}_{case.upper()}={'PASS' if passed else 'FAIL'}", flush=True)
    report = {"schema": "craft.office.native-visible.tamper.v1",
              "status": "PASS" if all(r["passed"] for r in result) else "FAIL",
              "checks": len(result), "cases": result, "personal_documents_touched": False,
              "trust_and_qes": "NOT_ASSESSED"}
    (OUT / "acceptance.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("REPORT=" + str(OUT / "acceptance.json"), flush=True)
    if report["status"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
