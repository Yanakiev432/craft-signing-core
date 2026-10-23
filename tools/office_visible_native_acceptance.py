#!/usr/bin/env python3
"""Independent, offline, read-only OOXML relationship/asset acceptance on synthetic files.

Does not validate certificates, trust, timestamps, or QES. Windows OPC does
cryptographic checking separately. Refuses input outside signing-core/target.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path
import xml.etree.ElementTree as ET
import zipfile

PKG_RELS = "{http://schemas.openxmlformats.org/package/2006/relationships}"
OFFICE_REL = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
XL = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
XDR = "{http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing}"
A = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
CT = "{http://schemas.openxmlformats.org/package/2006/content-types}"
O = "{urn:schemas-microsoft-com:office:office}"
V = "{urn:schemas-microsoft-com:vml}"


def read_parts(path: Path, root: Path):
    doc = path.resolve(strict=True)
    if not doc.is_relative_to(root):
        raise ValueError("Only synthetic target input supported")
    with zipfile.ZipFile(doc, "r") as z:
        if z.testzip() is not None:
            raise ValueError("Bad ZIP CRC")
        return {name: z.read(name) for name in z.namelist() if not name.endswith("/")}


def elem(parts, name):
    if name not in parts:
        raise ValueError("Missing XML: " + name)
    return ET.fromstring(parts[name])


def relation(parts, rel_part, ref_id):
    root = elem(parts, rel_part)
    assert root.tag == PKG_RELS + "Relationships"
    matching = [item for item in root if item.get("Id") == ref_id]
    if len(matching) != 1:
        raise ValueError("Missing or duplicate reference: " + ref_id)
    return matching[0]


def verify_docx(original, signed, png):
    doc = elem(signed, "word/document.xml")
    assert doc.tag == W + "document"
    lines = list(doc.iter(O + "signatureline"))
    shapes = list(doc.iter(V + "shape"))
    images = list(doc.iter(V + "imagedata"))
    if len(lines) != 1 or len(images) != 1 or not shapes:
        raise ValueError("Expected exactly one VML signature line and picture")
    rid = images[0].get(OFFICE_REL + "id")
    rel = relation(signed, "word/_rels/document.xml.rels", rid)
    if rel.get("Type") != "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image":
        raise ValueError("Wrong Word image relation")
    target = rel.get("Target", "")
    if not target.startswith("media/") or ".." in target:
        raise ValueError("Unsafe Word picture target")
    image_part = "word/" + target
    if signed[image_part] != png:
        raise ValueError("Embedded picture differs from PDFCraft preview bytes")
    expected_changes = {"word/document.xml", "word/_rels/document.xml.rels", "[Content_Types].xml"}
    return {"line_count": len(lines), "image_part": image_part, "modified_unsigned_parts": sorted(expected_changes)}


def verify_xlsx(original, signed, png):
    sheet = elem(signed, "xl/worksheets/sheet1.xml")
    assert sheet.tag == XL + "worksheet"
    drawing = sheet.findall(XL + "drawing")
    if len(drawing) != 1:
        raise ValueError("Expected one worksheet drawing")
    rid = drawing[0].get(OFFICE_REL + "id")
    rel = relation(signed, "xl/worksheets/_rels/sheet1.xml.rels", rid)
    if rel.get("Type") != "http://schemas.openxmlformats.org/officeDocument/2006/relationships/drawing":
        raise ValueError("Wrong drawing relationship")
    drawing_part = "xl/drawings/craftSignatureDrawing.xml"
    drawing_xml = elem(signed, drawing_part)
    assert drawing_xml.tag == XDR + "wsDr"
    anchors = list(drawing_xml.iter(XDR + "oneCellAnchor"))
    if len(anchors) != 1:
        raise ValueError("Expected precisely one picture anchor")
    from_cell = anchors[0].find(XDR + "from")
    column = int(from_cell.find(XDR + "col").text)
    row = int(from_cell.find(XDR + "row").text)
    embed = drawing_xml.find(".//" + A + "blip")
    pic_rid = embed.get(OFFICE_REL + "embed")
    rel2 = relation(signed, "xl/drawings/_rels/craftSignatureDrawing.xml.rels", pic_rid)
    image = rel2.get("Target", "")
    if image.startswith("../media/") and ".." not in image[3:]:
        image_part = "xl/" + image.removeprefix("../")
    else:
        raise ValueError("Unsafe drawing image relationship")
    if signed[image_part] != png:
        raise ValueError("Drawing picture bytes differ")
    expected_changes = {"xl/worksheets/sheet1.xml", "[Content_Types].xml"}
    return {
        "drawing": drawing_part, "image_part": image_part,
        "anchor_zero_based": {"column": column, "row": row},
        "modified_unsigned_parts": sorted(expected_changes)
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--signed-dir", type=Path, required=True)
    parser.add_argument("--png", type=Path, required=True)
    args = parser.parse_args()
    root = (Path(__file__).resolve().parent.parent / "target").resolve(strict=True)
    paths = [args.source_dir.resolve(strict=True), args.signed_dir.resolve(strict=True), args.png.resolve(strict=True)]
    if any(not path.is_relative_to(root) for path in paths):
        raise ValueError("Source, signed files and PNG must stay under core/target")
    image = args.png.read_bytes()
    outcomes = []
    for ext in ("docx", "xlsx"):
        src_path = args.source_dir / f"sample.{ext}"
        dest_path = args.signed_dir / f"NativePdfCraftAppearance-Signed.{ext}"
        before_hash = hashlib.sha256(src_path.read_bytes()).hexdigest()
        before = read_parts(src_path, root)
        after = read_parts(dest_path, root)
        if any(name not in after or before[name] != after[name] for name in before if name not in
               ({"word/document.xml", "word/_rels/document.xml.rels", "[Content_Types].xml", "_rels/.rels"} if ext == "docx"
                else {"xl/worksheets/sheet1.xml", "xl/worksheets/_rels/sheet1.xml.rels", "[Content_Types].xml", "_rels/.rels"})):
            raise ValueError("One or more original unrelated OPC parts mutated")
        if ext == "docx":
            evidence = verify_docx(before, after, image)
        else:
            evidence = verify_xlsx(before, after, image)
        content_types = elem(after, "[Content_Types].xml")
        assert content_types.tag == CT + "Types"
        if not any(e.get("Extension") == "png" and e.get("ContentType") == "image/png" for e in content_types):
            raise ValueError("PNG content type missing")
        for name in after:
            if name.endswith(".xml") or name.endswith(".rels"):
                # XML-DSig chunks may use different serialization, but should still be well-formed.
                ET.fromstring(after[name])
        if before_hash != hashlib.sha256(src_path.read_bytes()).hexdigest():
            raise ValueError("Source changed during validation")
        outcomes.append({
            "format": ext, "status": "OPC_XML_ASSET_RELATIONSHIPS_PASS",
            "source_unchanged": True,
            "source_sha256": before_hash,
            "signed_sha256": hashlib.sha256(dest_path.read_bytes()).hexdigest(),
            **evidence
        })
    report = {
        "schema": "craft.office.native-visual.opc-structure-validation.v1",
        "status": "PASS",
        "outcomes": outcomes,
        "scope": "synthetic files only; XML relationships and PNG integrity, not crypto validation",
        "cryptographic_validation_separate": "WindowsBase OPC 1/1 each",
        "real_office_interaction": "NOT_TESTED",
    }
    dest = args.signed_dir / "xml_evidence.json"
    if dest.exists():
        raise ValueError("Refusing to overwrite acceptance report")
    dest.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(dest), "status": report["status"], "outcomes": outcomes}, indent=2))


if __name__ == "__main__":
    main()
