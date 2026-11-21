//! The scan for object bodies appended after signing that no cross-reference entry reads.

use std::sync::Arc;

use cleonpdf_cos::Document;

use super::unlisted_bodies;

fn pdf(objs: &[&str], trailer_extra: &str) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R {trailer_extra} >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    out
}

/// `signed` with a revision appended that writes `before` and then object 3, listed where its
/// header is.
fn append_object_3(signed: &[u8], before: &[u8]) -> Vec<u8> {
    let at = signed.windows(9).rposition(|w| w == b"startxref").unwrap() + 9;
    let prev: String =
        signed.get(at..).unwrap().iter().skip_while(|b| b.is_ascii_whitespace()).take_while(|b| b.is_ascii_digit()).map(|b| *b as char).collect();
    let mut bytes = signed.to_vec();
    bytes.extend_from_slice(before);
    let object = bytes.len();
    bytes.extend_from_slice(b"3 0 obj\n(x)\nendobj\n");
    let section = bytes.len();
    bytes.extend_from_slice(
        format!("xref\n3 1\n{object:010} 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R /Prev {prev} >>\nstartxref\n{section}\n%%EOF\n").as_bytes(),
    );
    bytes
}

/// A comment of digits (`%1%1%1…`), a run of signed numbers (`1 +1+1+1…`), or a short one
/// before long white space, appended after signing, would make the header scan start at each
/// digit and read to the end of the run every time, quadratic in the appended bytes. Past a
/// bound on that work the appended bytes are not judged; an ordinary revision is.
#[test]
fn the_header_scan_is_bounded_on_runs_that_restart_it() {
    let signed = pdf(&["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [] /Count 0 >>"], "");
    let old = Document::open(Arc::new(signed.clone())).unwrap();
    let comment = [b"%".to_vec(), b"1%".repeat(50_000), b"\n".to_vec()].concat();
    let numbers = [b"1 ".to_vec(), b"+1".repeat(50_000), b"\n".to_vec()].concat();
    // Each start reads the short run of numbers, then the same long white space after it.
    let spaced = [b"1".to_vec(), b"+1".repeat(2_000), b" ".repeat(1 << 20), b"\n".to_vec()].concat();
    for (what, run) in [("a comment of digits", comment), ("a run of signed numbers", numbers), ("signed numbers before white space", spaced)] {
        let doc = Document::open(Arc::new(append_object_3(&signed, &run))).unwrap();
        assert_eq!(unlisted_bodies(&doc, &old), None, "{what}");
    }
    let doc = Document::open(Arc::new(append_object_3(&signed, b"% an ordinary comment 1 2 3\n"))).unwrap();
    assert_eq!(unlisted_bodies(&doc, &old), Some(Vec::new()));
}

/// Many entries of an appended section that point at one place before a long run of white
/// space would make matching each header to its entry read that run again every time. Past
/// the same bound on work, the appended bytes are not judged.
#[test]
fn matching_headers_to_their_entries_is_bounded_too() {
    let signed = pdf(&["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [] /Count 0 >>"], "");
    let old = Document::open(Arc::new(signed.clone())).unwrap();
    let at = signed.windows(9).rposition(|w| w == b"startxref").unwrap() + 9;
    let prev: String =
        signed.get(at..).unwrap().iter().skip_while(|b| b.is_ascii_whitespace()).take_while(|b| b.is_ascii_digit()).map(|b| *b as char).collect();
    let mut bytes = signed.clone();
    let blank = bytes.len();
    bytes.extend_from_slice(&b" ".repeat(1 << 20));
    bytes.push(b'\n');
    let count = 2_000u32;
    for num in 3..3 + count {
        bytes.extend_from_slice(format!("{num} 0 obj\n(x)\nendobj\n").as_bytes());
    }
    let section = bytes.len();
    bytes.extend_from_slice(format!("xref\n3 {count}\n").as_bytes());
    for _ in 0..count {
        bytes.extend_from_slice(format!("{blank:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R /Prev {prev} >>\nstartxref\n{section}\n%%EOF\n", 3 + count).as_bytes());
    let doc = Document::open(Arc::new(bytes)).unwrap();
    assert_eq!(unlisted_bodies(&doc, &old), None);
}
