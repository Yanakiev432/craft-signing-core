#!/usr/bin/env python3
"""Private read-only EU DSS assessment of *synthetic* Office OPC signatures.

Uses a pinned HTTP loopback endpoint (127.0.0.1:18080), no proxy, no redirect,
bounded response and report. The signed documents never leave this machine.
DSS acceptance level/indication are recorded as observed: never infer QES
from a Windows trust chain or from an absent/unsupported DSS format.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import urllib.request
import urllib.error
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent.parent
TARGET = (ROOT / "target").resolve()
ENDPOINT = "http://127.0.0.1:18080/services/rest/validation/validateSignature"
MAX_DOC_BYTES = 40 * 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, msg, headers, new_url):
        raise ValueError("DSS redirects are forbidden")

def validate(path: Path, report_dir: Path):
    source = path.resolve(strict=True)
    if not source.is_relative_to(TARGET):
        raise ValueError("Only synthetic core/target test sources allowed")
    if source.suffix.lower() not in (".docx", ".xlsx"):
        raise ValueError("Only Microsoft Office OOXML document test sources allowed")
    if source.stat().st_size > MAX_DOC_BYTES:
        raise ValueError("OOXML exceeds bounded upload size")
    data = source.read_bytes()
    name = source.name
    sha = hashlib.sha256(data).hexdigest()
    payload = json.dumps({"signedDocument": {
        "bytes": base64.b64encode(data).decode("ascii"), "name": name
    }}).encode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(ENDPOINT, payload,
                                 {"Content-Type": "application/json"}, method="POST")
    result = {"source_name": name, "source_sha256": sha, "extension": source.suffix,
              "dss_qes": "NOT_ESTABLISHED", "cryptographic_validity": "NOT_ESTABLISHED",
              "qes_document_level": "NOT_ESTABLISHED"}
    raw = b""
    try:
        with opener.open(req, timeout=80) as resp:
            if resp.status != 200:
                raise RuntimeError("DSS non-200")
            raw = resp.read(MAX_REPORT_BYTES + 1)
            if len(raw) > MAX_REPORT_BYTES:
                raise ValueError("DSS report too large")
        document = json.loads(raw)
        simple = document.get("SimpleReport", document.get("simpleReport"))
        if not isinstance(simple, dict):
            raise ValueError("DSS SimpleReport not returned")
        reports = simple.get("signatureOrTimestampOrEvidenceRecord", [])
        if not isinstance(reports, list):
            raise ValueError("Unexpected DSS signatures structure")
        signatures = [item["Signature"] for item in reports if isinstance(item, dict) and isinstance(item.get("Signature"), dict)]
        statuses = []
        for signature in signatures:
            level = signature.get("SignatureLevel")
            if isinstance(level, dict): level = level.get("value")
            indication = signature.get("Indication")
            statuses.append({"indication":indication, "qualification_level":level,
                             "signature_format":signature.get("SignatureFormat")})
        accepted_qes = (len(statuses) == 1 and simple.get("SignaturesCount") == 1
                        and simple.get("ValidSignaturesCount") == 1
                        and statuses[0]["indication"] == "TOTAL_PASSED"
                        and statuses[0]["qualification_level"] == "QESig")
        result.update({"dss_status": "REPORT_PARSED", "indication": statuses,
                       "reported_signatures_count": simple.get("SignaturesCount"),
                       "reported_valid_signatures_count": simple.get("ValidSignaturesCount"),
                       "validation_time": simple.get("ValidationTime"),
                       "dss_qes": "PASS" if accepted_qes else "NOT_ESTABLISHED",
                       "qes_document_level": "DSS_QESIG_PASS" if accepted_qes else "NOT_ESTABLISHED",
                       "cryptographic_validity": "DSS_TOTAL_PASSED" if len(statuses)==1 and statuses[0]["indication"]=="TOTAL_PASSED" else "NOT_ESTABLISHED"})
    except urllib.error.HTTPError as ex:
        raw = ex.read(MAX_REPORT_BYTES)
        result.update({"dss_status":f"HTTP_{ex.code}", "reason":"DSS rejected or could not validate requested Office format"})
    except (urllib.error.URLError, ValueError, RuntimeError, OSError, KeyError, json.JSONDecodeError) as ex:
        result.update({"dss_status":"INCONCLUSIVE", "reason":type(ex).__name__+": "+str(ex)[:220]})
    if raw:
        raw_path = report_dir / (source.stem + source.suffix + ".dss-response.json")
        if raw_path.exists():
            raise ValueError("DSS report already exists")
        raw_path.write_bytes(raw)
        result["raw_dss_report_sha256"]=hashlib.sha256(raw).hexdigest()
        result["raw_dss_report_path"]=str(raw_path)
    if sha != hashlib.sha256(source.read_bytes()).hexdigest():
        raise ValueError("Source modified during DSS check")
    return result

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output", type=Path, required=True)
    ap.add_argument("sources", nargs="+", type=Path)
    args=ap.parse_args()
    if args.output.exists():
        raise ValueError("Refusing to overwrite existing acceptance directory")
    parent = args.output.resolve(strict=False).parent.resolve(strict=True)
    if not parent.is_relative_to(TARGET):
        raise ValueError("Private DSS report output must remain inside signing-core/target")
    args.output.mkdir()
    outcomes = []
    for file in args.sources:
        print("VALIDATING_OFFICE_FORMAT="+file.suffix.lower()+";NAME="+file.name, flush=True)
        item=validate(file,args.output)
        outcomes.append(item)
        print("DSS_OFFICE_STATUS="+item["dss_status"]+";QES="+item["dss_qes"], flush=True)
    report = {
        "schema": "craft.office.eu-dss.local.v1",
        "date": datetime.now(timezone.utc).isoformat(),
        "local_endpoint":ENDPOINT,
        "no_external_document_upload":True, "synthetic_only":True,
        "assessment":"QES is PASS only when DSS independently returns TOTAL_PASSED/QESig/1 of 1",
        "all_qes_pass":all(item["dss_qes"]=="PASS" for item in outcomes),
        "outcomes":outcomes,
    }
    (args.output/"acceptance.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print("DSS_OFFICE_REPORT="+str(args.output/"acceptance.json"),flush=True)

if __name__=="__main__":
    main()
