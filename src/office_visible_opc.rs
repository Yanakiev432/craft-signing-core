//! Experimental **unsigned** DOCX/XLSX visible picture writer.
//! Images are written into the OPC package *before* XMLDSig signing.
//! No public UI invokes this module yet: real document-position mapping,
//! certificate-bound render text and native Office signature-line behavior
//! need separate acceptance.
//!
//! Fail closed on already signed inputs, active drawings and unusual XML.
//! No subprocess, no private-key access and no modification of source documents.
#![cfg(windows)]
use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
};
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

const MAX_IMAGE: usize = 2 * 1024 * 1024;
const MAX_XML: usize = 8 * 1024 * 1024;
const MAX_TOTAL: u64 = 128 * 1024 * 1024;
const R_NS: &str = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";
const REL_NS: &str = "http://schemas.openxmlformats.org/package/2006/relationships";
const CT_NS: &str = "http://schemas.openxmlformats.org/package/2006/content-types";
static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Clone, Debug)]
pub enum OfficeImagePlacement {
    /// Appended as a Word paragraph before the final section properties.
    /// Not yet bound to the WordCraft screen rectangle.
    WordDocumentEnd,
    /// Picture anchored at the given zero-based column and row.
    /// Not yet bound to the GridCraft viewport rectangle.
    ExcelCell { column: u32, row: u32 },
}

/// For **unsigned** source only, create a distinct unsigned file with a PNG
/// appearance embedded as an Office image. The returned document MUST then
/// be signed by the already verified native OPC implementation.
pub fn add_unsigned_visual_appearance(
    source: &Path,
    output: &Path,
    png: &[u8],
    signer_display_name: &str,
    placement: OfficeImagePlacement,
) -> Result<(), String> {
    if source == output || output.exists() {
        return Err("Visual output must be new and distinct from input".into());
    }
    let extension = source.extension().and_then(|s| s.to_str()).unwrap_or("");
    let expected = match placement {
        OfficeImagePlacement::WordDocumentEnd => "docx",
        OfficeImagePlacement::ExcelCell { .. } => "xlsx",
    };
    if !extension.eq_ignore_ascii_case(expected) || output.extension() != source.extension() {
        return Err("Visual placement does not match DOCX/XLSX extension".into());
    }
    if !(1..=120).contains(&signer_display_name.trim().chars().count()) {
        return Err("Signer name length outside accepted range".into());
    }
    if signer_display_name.chars().any(char::is_control) {
        return Err("Signer contains control characters".into());
    }
    if png.len() > MAX_IMAGE || png.len() < 24 || !png.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Err("Only bounded real PNG bytes accepted".into());
    }
    let w = u32::from_be_bytes(png[16..20].try_into().map_err(|_| "Bad PNG width")?);
    let h = u32::from_be_bytes(png[20..24].try_into().map_err(|_| "Bad PNG height")?);
    if !(100..=2000).contains(&w) || !(40..=2000).contains(&h) {
        return Err("PNG width or height is outside appearance limits".into());
    }
    if let OfficeImagePlacement::ExcelCell { column, row } = placement
        && (column > 16383 || row > 1048575)
    {
        return Err("Excel anchor outside worksheet bounds".into());
    }

    let input = File::open(source).map_err(|e| e.to_string())?;
    let mut archive = ZipArchive::new(input).map_err(|e| e.to_string())?;
    if archive.is_empty() || archive.len() > 65520 {
        return Err("Office ZIP entry count outside accepted limit".into());
    }
    let mut bytes = std::collections::BTreeMap::<String, (Vec<u8>, CompressionMethod)>::new();
    let mut seen = HashSet::new();
    let mut total = 0u64;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| e.to_string())?;
        let name = entry.name().to_owned();
        let lower = name.to_ascii_lowercase();
        if name.is_empty() || name.starts_with('/') || name.contains('\\')
            || name.split('/').any(|segment| segment == ".." || segment == ".")
            || !seen.insert(lower.clone())
        {
            return Err("Unsafe or repeated ZIP entry name".into());
        }
        if lower.contains("_xmlsignatures")
            || lower.contains("package/services/digital-signature")
            || lower.contains("digital-signature/origin")
        {
            return Err("Already signed document: adding a visual would invalidate existing signatures".into());
        }
        if !matches!(entry.compression(), CompressionMethod::Stored | CompressionMethod::Deflated) {
            return Err("Unsupported source compression".into());
        }
        total = total.checked_add(entry.size()).ok_or("Overflow")?;
        if total > MAX_TOTAL {
            return Err("Document exceeds 128 MiB experimental safety bound".into());
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(|e| e.to_string())?;
        bytes.insert(name, (data, entry.compression()));
    }

    let stamp = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let image_filename = format!("CraftSignature-{stamp}.png");
    let rid = format!("rIdCraftSignature{stamp}");
    let base = match placement {
        OfficeImagePlacement::WordDocumentEnd => "word",
        OfficeImagePlacement::ExcelCell { .. } => "xl",
    };
    let image_part = format!("{base}/media/{image_filename}");
    if bytes.keys().any(|k| k.eq_ignore_ascii_case(&image_part)) {
        return Err("Image part collision".into());
    }
    match placement {
        OfficeImagePlacement::WordDocumentEnd => {
            inject_word(&mut bytes, &rid, &image_filename, signer_display_name, stamp)?
        }
        OfficeImagePlacement::ExcelCell { column, row } => {
            inject_excel(&mut bytes, &rid, &image_filename, stamp, column, row)?
        }
    }
    bytes.insert(image_part, (png.to_vec(), CompressionMethod::Deflated));
    let file = OpenOptions::new().write(true).create_new(true).open(output)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        let mut writer = ZipWriter::new(file);
        for (name, (data, method)) in bytes {
            writer.start_file(name, SimpleFileOptions::default()
                .compression_method(method).large_file(false))
                .map_err(|e| e.to_string())?;
            writer.write_all(&data).map_err(|e| e.to_string())?;
        }
        writer.finish().map_err(|e| e.to_string())?.sync_all()
            .map_err(|e| e.to_string())?;
        Ok::<_, String>(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(output);
    }
    result
}

fn xml_part(bytes: &std::collections::BTreeMap<String,(Vec<u8>, CompressionMethod)>, name: &str) -> Result<String, String> {
    let raw = &bytes.get(name).ok_or_else(|| format!("Missing OPC XML part {name}"))?.0;
    if raw.len() > MAX_XML {
        return Err("XML part exceeds size bound".into());
    }
    let string = std::str::from_utf8(raw).map_err(|_| format!("Non-UTF8 OPC XML in {name}"))?;
    if string.contains("<!DOCTYPE") || string.contains("<!ENTITY") {
        return Err("XML DTD/entity not supported for signed visual assets".into());
    }
    Ok(string.to_owned())
}
fn put_xml(bytes: &mut std::collections::BTreeMap<String,(Vec<u8>,CompressionMethod)>, name: &str, xml: String) {
    bytes.insert(name.to_owned(), (xml.into_bytes(), CompressionMethod::Deflated));
}
fn add_xml(bytes: &mut std::collections::BTreeMap<String,(Vec<u8>,CompressionMethod)>, name: String, xml: String) -> Result<(),String> {
    if bytes.contains_key(&name) {
        return Err(format!("OPC part already exists: {name}"));
    }
    put_xml(bytes, &name, xml);
    Ok(())
}
fn before_last(xml: &mut String, marker: &str, addition: &str) -> Result<(),String> {
    let loc = xml.rfind(marker).ok_or_else(|| format!("Missing XML insertion point {marker}"))?;
    xml.insert_str(loc, addition);
    Ok(())
}
fn sanitize_xml(input: &str) -> String {
    input.replace('&',"&amp;").replace('<',"&lt;").replace('>',"&gt;")
         .replace('"',"&quot;").replace('\'',"&apos;")
}
fn add_ct(bytes: &mut std::collections::BTreeMap<String,(Vec<u8>,CompressionMethod)>, drawing: bool) -> Result<(),String> {
    let mut ct = xml_part(bytes, "[Content_Types].xml")?;
    if !ct.contains(CT_NS) {
        return Err("Content Types namespace mismatch".into());
    }
    let mut inserts = String::new();
    if !ct.contains("Extension=\"png\"") && !ct.contains("Extension='png'") {
        inserts.push_str("<Default Extension=\"png\" ContentType=\"image/png\"/>");
    }
    if drawing {
        if ct.contains("PartName=\"/xl/drawings/craftSignatureDrawing.xml\"") {
            return Err("Drawing content-type collision".into());
        }
        inserts.push_str("<Override PartName=\"/xl/drawings/craftSignatureDrawing.xml\" ContentType=\"application/vnd.openxmlformats-officedocument.drawing+xml\"/>");
    }
    before_last(&mut ct, "</Types>", &inserts)?;
    put_xml(bytes, "[Content_Types].xml", ct);
    Ok(())
}
fn add_rel(bytes: &mut std::collections::BTreeMap<String,(Vec<u8>,CompressionMethod)>, part: &str, id: &str, relation_type: &str, target: &str) -> Result<(),String> {
    let addition = format!("<Relationship Id=\"{id}\" Type=\"{R_NS}/{relation_type}\" Target=\"{target}\"/>");
    let mut xml = if bytes.contains_key(part) {
        xml_part(bytes, part)?
    } else {
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Relationships xmlns=\"{REL_NS}\"></Relationships>")
    };
    if !xml.contains(REL_NS) || xml.contains(&format!("Id=\"{id}\"")) {
        return Err("Relationships namespace mismatch or ID collision".into());
    }
    before_last(&mut xml, "</Relationships>", &addition)?;
    put_xml(bytes, part, xml);
    Ok(())
}
fn inject_word(bytes: &mut std::collections::BTreeMap<String,(Vec<u8>,CompressionMethod)>, rid: &str, file: &str, signer: &str, stamp: u64) -> Result<(),String> {
    let mut xml = xml_part(bytes,"word/document.xml")?;
    if !xml.contains("http://schemas.openxmlformats.org/wordprocessingml/2006/main")
        || !xml.contains("<w:body") || !xml.contains("</w:body>") {
        return Err("Unsupported Word DOCX main body structure".into());
    }
    let safe_signer = sanitize_xml(signer);
    // Office VML signature-line metadata remains experimental; the picture
    // is fully embedded into the cryptographically covered unsigned document.
    let paragraph = format!(
        "<w:p><w:r><w:pict><v:shape xmlns:v=\"urn:schemas-microsoft-com:vml\" \
         xmlns:o=\"urn:schemas-microsoft-com:office:office\" \
         xmlns:r=\"{R_NS}\" \
         id=\"_x0000_s{stamp}\" style=\"width:330pt;height:95pt\" filled=\"f\" stroked=\"f\">\
         <v:imagedata r:id=\"{rid}\" o:title=\"Craft signature appearance\"/>\
         <o:signatureline v:ext=\"edit\" id=\"{{00000000-0000-4000-8000-{stamp:012}}}\" \
         provid=\"{{00000000-0000-0000-0000-000000000000}}\" issignatureline=\"t\" \
         showsigndate=\"t\" suggestedsigner=\"{safe_signer}\"/>\
         </v:shape></w:pict></w:r></w:p>");
    let body_close = xml.rfind("</w:body>").ok_or("Word body closure missing")?;
    let before_section = xml[..body_close].rfind("<w:sectPr").unwrap_or(body_close);
    xml.insert_str(before_section, &paragraph);
    put_xml(bytes,"word/document.xml",xml);
    add_rel(bytes,"word/_rels/document.xml.rels",rid,"image",&format!("media/{file}"))?;
    add_ct(bytes,false)
}
fn inject_excel(bytes: &mut std::collections::BTreeMap<String,(Vec<u8>,CompressionMethod)>, rid: &str, file: &str, stamp: u64, column: u32, row: u32) -> Result<(),String> {
    let mut xml = xml_part(bytes,"xl/worksheets/sheet1.xml")?;
    if !xml.contains("http://schemas.openxmlformats.org/spreadsheetml/2006/main")
        || !xml.contains("</worksheet>")
        || xml.contains("<drawing") || xml.contains("<x:drawing") {
        return Err("Unsupported worksheet or existing drawing: no destructive replacement".into());
    }
    let node=format!("<drawing xmlns:r=\"{R_NS}\" r:id=\"{rid}\"/>");
    let pos=xml.find("<extLst").unwrap_or_else(||xml.rfind("</worksheet>").unwrap());
    xml.insert_str(pos,&node);
    put_xml(bytes,"xl/worksheets/sheet1.xml",xml);
    let drawing_name="xl/drawings/craftSignatureDrawing.xml".to_string();
    if bytes.contains_key(&drawing_name) {return Err("Existing Craft drawing collision".into());}
    add_rel(bytes,"xl/worksheets/_rels/sheet1.xml.rels",rid,"drawing","../drawings/craftSignatureDrawing.xml")?;
    let picture_rid=format!("rIdCraftSignaturePicture{stamp}");
    let drawing=format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <xdr:wsDr xmlns:xdr=\"http://schemas.openxmlformats.org/drawingml/2006/spreadsheetDrawing\" \
         xmlns:a=\"http://schemas.openxmlformats.org/drawingml/2006/main\" xmlns:r=\"{R_NS}\">\
         <xdr:oneCellAnchor><xdr:from><xdr:col>{column}</xdr:col><xdr:colOff>0</xdr:colOff>\
         <xdr:row>{row}</xdr:row><xdr:rowOff>0</xdr:rowOff></xdr:from>\
         <xdr:ext cx=\"4876800\" cy=\"1414275\"/>\
         <xdr:pic><xdr:nvPicPr><xdr:cNvPr id=\"1\" name=\"Craft digital signature\"/>\
         <xdr:cNvPicPr><a:picLocks noChangeAspect=\"1\"/></xdr:cNvPicPr></xdr:nvPicPr>\
         <xdr:blipFill><a:blip r:embed=\"{picture_rid}\"/><a:stretch><a:fillRect/>\
         </a:stretch></xdr:blipFill><xdr:spPr><a:xfrm><a:off x=\"0\" y=\"0\"/>\
         <a:ext cx=\"4876800\" cy=\"1414275\"/></a:xfrm>\
         <a:prstGeom prst=\"rect\"><a:avLst/></a:prstGeom></xdr:spPr>\
         </xdr:pic><xdr:clientData/></xdr:oneCellAnchor></xdr:wsDr>");
    add_xml(bytes,drawing_name,drawing)?;
    add_xml(bytes,"xl/drawings/_rels/craftSignatureDrawing.xml.rels".to_string(),
            format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
            <Relationships xmlns=\"{REL_NS}\">\
            <Relationship Id=\"{picture_rid}\" Type=\"{R_NS}/image\" Target=\"../media/{file}\"/>\
            </Relationships>"))?;
    add_ct(bytes,true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escapes_untrusted_certificate_display_names() {
        assert_eq!(sanitize_xml("A < B & \"C\""), "A &lt; B &amp; &quot;C&quot;");
    }
    #[test]
    fn no_missing_xml_close_accepted() {
        let mut xml="<Types />".to_owned();
        assert!(before_last(&mut xml,"</Types>","<Default/>").is_err());
    }
}
