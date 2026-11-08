//! Locking form fields when signing (FieldMDP): what the signature records, and what later
//! changes to the locked fields do to it.

use std::sync::Arc;

use cleonpdf_cos::{Dict, Document, ObjRef, Object, PdfString, SaveOptions, Stream, write_incremental};
use cleonpdf_sign::{FieldLock, Modification, SignError, SignOptions, SignatureInfo, Status, TrustStore, kind, pkcs12, signatures};

fn data(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn open(b: &[u8]) -> Document {
    Document::open(Arc::new(b.to_vec())).unwrap()
}

fn r(num: u32) -> ObjRef {
    ObjRef { num, generation: 0 }
}

/// A form: signature fields `Approval` (6) and `Second` (12), text fields `name` (7) and
/// `amount` (8), and the group `grp` (9) with the fields `a` (10) and `b` (11). Fields 7, 8, 10
/// and 11 each draw from their own appearance stream (13–16).
fn fixture() -> Vec<u8> {
    let stream = |text: &str| format!("<< /Type /XObject /Subtype /Form /BBox [0 0 100 20] /Length {} >>\nstream\n{text}\nendstream", text.len());
    let widget = |t: &str, v: &str, ap: u32, y: u32, parent: &str| {
        format!(
            "<< /Type /Annot /Subtype /Widget {parent} /FT /Tx /T ({t}) /V ({v}) /Rect [20 {y} 120 {}] /P 3 0 R /F 4 /AP << /N {ap} 0 R >> >>",
            y + 20
        )
    };
    let objs: Vec<String> = vec![
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R 7 0 R 8 0 R 9 0 R 12 0 R] >> >>".into(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".into(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> /Annots [6 0 R 7 0 R 8 0 R 10 0 R 11 0 R 12 0 R] >>".into(),
        "<< /Length 44 >>\nstream\nBT /F1 14 Tf 20 250 Td (Contract text) Tj ET\nendstream".into(),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".into(),
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Approval) /Rect [150 20 280 70] /P 3 0 R /F 4 >>".into(),
        widget("name", "Alice", 13, 200, ""),
        widget("amount", "100", 14, 170, ""),
        "<< /T (grp) /FT /Tx /Kids [10 0 R 11 0 R] >>".into(),
        widget("a", "x", 15, 140, "/Parent 9 0 R"),
        widget("b", "y", 16, 110, "/Parent 9 0 R"),
        "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Second) /Rect [150 80 280 130] /P 3 0 R /F 4 >>".into(),
        stream("Alice"),
        stream("100"),
        stream("x"),
        stream("y"),
    ];
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
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    out
}

fn opts(field: &str, lock: Option<FieldLock>) -> SignOptions {
    SignOptions { field: Some(field.into()), lock, date: "D:20261002120000+01'00'".into(), ..SignOptions::default() }
}

fn names(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_string()).collect()
}

fn id() -> cleonpdf_sign::DigitalId {
    pkcs12::open(&data("rsa-aes.p12"), "test").unwrap()
}

/// `bytes` signed in `field`, locking `lock`.
fn signed(bytes: &[u8], field: &str, lock: Option<FieldLock>) -> Vec<u8> {
    cleonpdf_sign::sign(&open(bytes), &id(), &opts(field, lock)).unwrap()
}

fn check(bytes: &[u8], field: &str) -> SignatureInfo {
    let trust = TrustStore { certs: vec![id().certificate.clone()], ..TrustStore::default() };
    signatures(&open(bytes), bytes, &trust).into_iter().find(|s| s.field == field).unwrap()
}

fn edit_after(bytes: &[u8], f: impl FnOnce(&mut Document)) -> Vec<u8> {
    let mut doc = open(bytes);
    f(&mut doc);
    write_incremental(&doc, &SaveOptions { object_streams: false, ..SaveOptions::default() }).unwrap()
}

fn set_value(num: u32, v: &str) -> impl FnOnce(&mut Document) {
    let v = v.to_string();
    move |doc| doc.update_dict(r(num), |d| d.set(b"V".to_vec(), PdfString::text(&v))).unwrap()
}

fn redraw(num: u32) -> impl FnOnce(&mut Document) {
    move |doc| {
        let ap = doc.add(Object::Stream(Stream::from_raw(Dict::new(), b"0 0 m 10 10 l S".to_vec())));
        let mut n = Dict::new();
        n.set(b"N".to_vec(), Object::Ref(ap));
        doc.update_dict(r(num), |d| d.set(b"AP".to_vec(), Object::Dict(n))).unwrap();
    }
}

#[test]
fn signing_records_the_lock_in_the_signature_and_on_the_field() {
    let lock = FieldLock::Include(names(&["name", "grp"]));
    let bytes = signed(&fixture(), "Approval", Some(lock.clone()));
    let s = check(&bytes, "Approval");
    assert_eq!(s.status, Status::Valid, "{:?}", s.details);
    assert_eq!(s.field_locks, vec![lock.clone()]);
    assert_eq!(s.modification, Modification::None);
    // The field says it too, so the next reader of the form knows what signing it locked.
    let doc = open(&bytes);
    let field = doc.get(r(6));
    let field = field.as_dict().unwrap();
    let on_field = field.get(b"Lock").map(|l| doc.resolve(l)).unwrap();
    let on_field = on_field.as_dict().unwrap();
    assert_eq!((on_field.name(b"Type"), on_field.name(b"Action")), (Some(&b"SigFieldLock"[..]), Some(&b"Include"[..])));
    let listed: Vec<String> =
        doc.resolve(on_field.get(b"Fields").unwrap()).as_array().unwrap().iter().map(|n| doc.resolve(n).as_string().unwrap().to_text()).collect();
    assert_eq!(listed, names(&["name", "grp"]));
    // The reference names the catalog as its data, as FieldMDP requires.
    let sig = doc.resolve(field.get(b"V").unwrap());
    let reference = doc.resolve(sig.as_dict().unwrap().get(b"Reference").unwrap());
    let first = doc.resolve(&reference.as_array().unwrap()[0]);
    let first = first.as_dict().unwrap();
    assert_eq!((first.name(b"TransformMethod"), first.reference(b"Data")), (Some(&b"FieldMDP"[..]), doc.root()));
    // A signature that locks nothing has no such reference.
    let plain = signed(&fixture(), "Approval", None);
    assert!(check(&plain, "Approval").field_locks.is_empty());
}

#[test]
fn changing_a_locked_field_invalidates_the_signature_and_changing_another_does_not() {
    let lock = FieldLock::Include(names(&["name"]));
    let bytes = signed(&fixture(), "Approval", Some(lock));
    // Another field may be filled in: an approval signature permits it.
    let s = check(&edit_after(&bytes, set_value(8, "250")), "Approval");
    assert_eq!((s.status, s.modification), (Status::Valid, Modification::Allowed(vec![kind::FORM_FILL])), "{:?}", s.details);
    // The locked field may not.
    let s = check(&edit_after(&bytes, set_value(7, "Mallory")), "Approval");
    assert_eq!(s.status, Status::Invalid);
    assert_eq!(s.modification, Modification::Disallowed(vec![kind::LOCKED_FIELDS]));
}

#[test]
fn a_locked_fields_appearance_is_locked_too() {
    let bytes = signed(&fixture(), "Approval", Some(FieldLock::Include(names(&["name"]))));
    // Same /V, redrawn: what the page shows changed.
    let s = check(&edit_after(&bytes, redraw(7)), "Approval");
    assert_eq!((s.status, s.modification), (Status::Invalid, Modification::Disallowed(vec![kind::LOCKED_FIELDS])));
    assert_eq!(check(&edit_after(&bytes, redraw(8)), "Approval").status, Status::Valid);
    // Rewriting the stream itself is no change to the field, but never a permitted one.
    let s = check(&edit_after(&bytes, |doc| doc.set(r(13), Object::Stream(Stream::from_raw(Dict::new(), b"0 0 m 10 10 l S".to_vec())))), "Approval");
    assert_eq!(s.status, Status::Invalid);
}

#[test]
fn a_parents_name_locks_the_fields_below_it() {
    let bytes = signed(&fixture(), "Approval", Some(FieldLock::Include(names(&["grp"]))));
    for child in [10, 11] {
        let s = check(&edit_after(&bytes, set_value(child, "z")), "Approval");
        assert_eq!(s.modification, Modification::Disallowed(vec![kind::LOCKED_FIELDS]), "field {child}");
    }
    assert_eq!(check(&edit_after(&bytes, set_value(7, "z")), "Approval").status, Status::Valid);
    // A value the children inherit from their parent is theirs too.
    let s = check(&edit_after(&bytes, |d| d.update_dict(r(9), |p| p.set(b"V".to_vec(), PdfString::text("inherited"))).unwrap()), "Approval");
    assert_eq!(s.modification, Modification::Disallowed(vec![kind::LOCKED_FIELDS]));
    // The same when only one child is locked: the parent is not locked, what it hands down is.
    let bytes = signed(&fixture(), "Approval", Some(FieldLock::Include(names(&["grp.a"]))));
    let parent_value = |doc: &mut Document| doc.update_dict(r(9), |p| p.set(b"V".to_vec(), PdfString::text("inherited"))).unwrap();
    assert_eq!(check(&edit_after(&bytes, parent_value), "Approval").modification, Modification::Disallowed(vec![kind::LOCKED_FIELDS]));
    assert_eq!(check(&edit_after(&bytes, set_value(11, "z")), "Approval").status, Status::Valid);
    // Only a prefix up to a dot: locking `grp` doesn't lock `grpx`.
    let bytes = signed(&fixture(), "Approval", Some(FieldLock::Include(names(&["name"]))));
    assert_eq!(check(&edit_after(&bytes, set_value(10, "z")), "Approval").status, Status::Valid);
}

#[test]
fn exclude_locks_everything_else_including_fields_added_later() {
    let bytes = signed(&fixture(), "Approval", Some(FieldLock::Exclude(names(&["amount", "Second"]))));
    assert_eq!(check(&edit_after(&bytes, set_value(8, "250")), "Approval").status, Status::Valid);
    for n in [7, 10] {
        assert_eq!(check(&edit_after(&bytes, set_value(n, "z")), "Approval").modification, Modification::Disallowed(vec![kind::LOCKED_FIELDS]));
    }
    // A field added afterwards is one the lock did not list, so it is locked.
    let added = |name: &'static str| {
        move |doc: &mut Document| {
            let mut w = Dict::new();
            w.set(b"Type".to_vec(), Object::name("Annot"));
            w.set(b"Subtype".to_vec(), Object::name("Widget"));
            w.set(b"FT".to_vec(), Object::name("Tx"));
            w.set(b"T".to_vec(), PdfString::text(name));
            w.set(b"Rect".to_vec(), Object::Array(vec![Object::Int(0), Object::Int(0), Object::Int(10), Object::Int(10)]));
            let wr = doc.add(Object::Dict(w));
            doc.update_dict(r(3), |p| {
                if let Some(Object::Array(a)) = p.get_mut(b"Annots") {
                    a.push(Object::Ref(wr));
                }
            })
            .unwrap();
            let af = doc.get(r(1)).as_dict().and_then(|c| c.get(b"AcroForm").cloned()).unwrap();
            let mut af = af.as_dict().cloned().unwrap();
            let mut fields = af.get(b"Fields").and_then(|f| f.as_array().cloned()).unwrap();
            fields.push(Object::Ref(wr));
            af.set(b"Fields".to_vec(), Object::Array(fields));
            doc.update_dict(r(1), |c| c.set(b"AcroForm".to_vec(), Object::Dict(af))).unwrap();
        }
    };
    let s = check(&edit_after(&bytes, added("extra")), "Approval");
    assert_eq!((s.status, s.modification.clone()), (Status::Invalid, Modification::Disallowed(vec![kind::LOCKED_FIELDS])), "{:?}", s.details);
    // Under Include the new field is not covered.
    let bytes = signed(&fixture(), "Approval", Some(FieldLock::Include(names(&["name"]))));
    assert_eq!(check(&edit_after(&bytes, added("extra")), "Approval").status, Status::Valid);
    // All covers everything, a new field as well as the old ones.
    let bytes = signed(&fixture(), "Approval", Some(FieldLock::All));
    assert_eq!(check(&edit_after(&bytes, added("extra")), "Approval").status, Status::Invalid);
    assert_eq!(check(&edit_after(&bytes, set_value(8, "250")), "Approval").status, Status::Invalid);
}

#[test]
fn removing_a_locked_field_from_the_form_breaks_the_lock() {
    let bytes = signed(&fixture(), "Approval", Some(FieldLock::Include(names(&["name"]))));
    let hidden = edit_after(&bytes, |doc| {
        let af = doc.get(r(1)).as_dict().and_then(|c| c.get(b"AcroForm").cloned()).unwrap();
        let mut af = af.as_dict().cloned().unwrap();
        let fields: Vec<Object> =
            af.get(b"Fields").and_then(|f| f.as_array().cloned()).unwrap().into_iter().filter(|f| f.as_ref() != Some(r(7))).collect();
        af.set(b"Fields".to_vec(), Object::Array(fields));
        doc.update_dict(r(1), |c| c.set(b"AcroForm".to_vec(), Object::Dict(af))).unwrap();
    });
    assert_eq!(check(&hidden, "Approval").modification, Modification::Disallowed(vec![kind::LOCKED_FIELDS]));
}

#[test]
fn a_later_signature_in_another_field_leaves_the_first_valid_unless_it_locked_that_field() {
    let first = signed(&fixture(), "Approval", Some(FieldLock::Include(names(&["name"]))));
    let both = signed(&first, "Second", None);
    assert_eq!(check(&both, "Approval").status, Status::Valid);
    assert_eq!(check(&both, "Second").status, Status::Valid);
    // Signing a field the first signature locked is a change to it.
    let locked_first = signed(&fixture(), "Approval", Some(FieldLock::Include(names(&["Second"]))));
    let both = signed(&locked_first, "Second", None);
    assert_eq!(check(&both, "Approval").modification, Modification::Disallowed(vec![kind::LOCKED_FIELDS]));
}

#[test]
fn a_field_prepared_with_a_lock_signs_with_it() {
    let lock = FieldLock::Include(names(&["amount"]));
    let prepared = edit_after(&fixture(), |doc| {
        doc.update_dict(r(6), |d| {
            let mut l = Dict::new();
            l.set(b"Type".to_vec(), Object::name("SigFieldLock"));
            l.set(b"Action".to_vec(), Object::name("Include"));
            l.set(b"Fields".to_vec(), Object::Array(vec![Object::String(PdfString::text("amount"))]));
            d.set(b"Lock".to_vec(), Object::Dict(l));
        })
        .unwrap();
    });
    let bytes = signed(&prepared, "Approval", None);
    assert_eq!(check(&bytes, "Approval").field_locks, vec![lock.clone()]);
    assert_eq!(check(&edit_after(&bytes, set_value(8, "1")), "Approval").status, Status::Invalid);
    // Asking for the same lock is fine; asking for another is refused, whatever it would lock.
    assert!(cleonpdf_sign::sign(&open(&prepared), &id(), &opts("Approval", Some(lock))).is_ok());
    for other in [FieldLock::Include(names(&["name"])), FieldLock::All] {
        match cleonpdf_sign::sign(&open(&prepared), &id(), &opts("Approval", Some(other))) {
            Err(SignError::Pdf(e)) => assert!(e.contains("already says which fields it locks"), "{e}"),
            other => panic!("{:?}", other.map(|b| b.len())),
        }
    }
}

#[test]
fn a_lock_must_name_fields_the_form_has() {
    for lock in [FieldLock::Include(names(&["nmae"])), FieldLock::Exclude(names(&["name", "nope"])), FieldLock::Include(vec![String::new()])] {
        match cleonpdf_sign::sign(&open(&fixture()), &id(), &opts("Approval", Some(lock.clone()))) {
            Err(SignError::Pdf(_)) => {}
            other => panic!("{lock:?}: {:?}", other.map(|b| b.len())),
        }
    }
    // A new signature field can be left out of its own lock by name.
    let new = SignOptions {
        field: None,
        new_field_name: Some("Fresh".into()),
        page: 0,
        rect: Some([10.0, 10.0, 100.0, 50.0]),
        lock: Some(FieldLock::Exclude(names(&["Fresh", "amount"]))),
        date: "D:20261002120000+01'00'".into(),
        ..SignOptions::default()
    };
    let bytes = cleonpdf_sign::sign(&open(&fixture()), &id(), &new).unwrap();
    assert_eq!(check(&bytes, "Fresh").field_locks, vec![new.lock.clone().unwrap()]);
    assert_eq!(check(&edit_after(&bytes, set_value(7, "z")), "Fresh").status, Status::Invalid);
}

#[test]
fn a_certification_and_a_lock_sit_side_by_side() {
    let o = SignOptions { certify: Some(2), ..opts("Approval", Some(FieldLock::Include(names(&["name"])))) };
    let bytes = cleonpdf_sign::sign(&open(&fixture()), &id(), &o).unwrap();
    let s = check(&bytes, "Approval");
    assert_eq!((s.certify, s.field_locks.len(), s.status), (Some(2), 1, Status::Valid), "{:?}", s.details);
    assert_eq!(check(&edit_after(&bytes, set_value(8, "1")), "Approval").status, Status::Valid);
    assert_eq!(check(&edit_after(&bytes, set_value(7, "1")), "Approval").status, Status::Invalid);
}

#[test]
fn a_hostile_form_does_not_hang_or_panic_the_check() {
    let bytes = signed(&fixture(), "Approval", Some(FieldLock::All));
    // Fields that are their own kids, a parent chain that loops, and a lock that names nothing sane.
    let looped = edit_after(&bytes, |doc| {
        doc.update_dict(r(9), |d| d.set(b"Kids".to_vec(), Object::Array(vec![Object::Ref(r(9)), Object::Ref(r(10)), Object::Ref(r(11))]))).unwrap();
        doc.update_dict(r(10), |d| d.set(b"Parent".to_vec(), Object::Ref(r(10)))).unwrap();
    });
    let _ = check(&looped, "Approval");
}
