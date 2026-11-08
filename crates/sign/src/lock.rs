//! Locking form fields when signing (ISO 32000-2 §12.8.2.4 FieldMDP, §12.7.5.5 `/Lock`).
//!
//! A signature field may carry a `/Lock` dictionary naming the form fields that signing it
//! freezes. The signature dictionary then gets a `/Reference` with `/TransformMethod /FieldMDP`
//! and the same `/Action` and `/Fields`, which is what a validator reads: the lock is a promise
//! the signer made about the signed bytes, not a property of the field that a later revision
//! could edit away.
//!
//! Validation compares the signed revision with the document as it is now (see
//! [`changed`]); the fields are looked up in the signed revision, so a later revision cannot
//! rename, re-parent or hide a locked field.

use std::collections::HashSet;

use cleonpdf_cos::{Dict, Document, ObjRef, Object, PdfString};

/// Most fields (and widgets) walked in a form; a form with more is read as far as this.
const MAX_FIELDS: usize = 100_000;
/// Most names a lock lists. A longer list is truncated when read and refused when written.
pub(crate) const MAX_NAMES: usize = 1_000;
/// Longest field name written into a lock.
const MAX_NAME_LEN: usize = 1_024;
/// How deep field names nest before the walk stops.
const MAX_DEPTH: usize = 32;

/// Which form fields a signature locks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldLock {
    /// Every field in the document.
    All,
    /// Only these fields (a parent's name covers the fields below it).
    Include(Vec<String>),
    /// Every field except these (and the fields below them).
    Exclude(Vec<String>),
}

/// Whether `name` is `listed` or a field below it (`parent.child`).
fn is_listed(listed: &[String], name: &str) -> bool {
    listed.iter().any(|l| name == l || name.strip_prefix(l.as_str()).is_some_and(|rest| rest.starts_with('.')))
}

impl FieldLock {
    /// Whether the field with this full name is locked.
    #[must_use]
    pub fn covers(&self, name: &str) -> bool {
        match self {
            Self::All => true,
            Self::Include(l) => is_listed(l, name),
            Self::Exclude(l) => !is_listed(l, name),
        }
    }

    /// The field names the lock lists (none for [`FieldLock::All`]).
    #[must_use]
    pub fn names(&self) -> &[String] {
        match self {
            Self::All => &[],
            Self::Include(l) | Self::Exclude(l) => l,
        }
    }

    /// Read `/Action` and `/Fields` from a `/Lock` or FieldMDP `/TransformParams` dictionary.
    /// An action that is missing or not one the standard defines locks everything: a lock that
    /// cannot be read must not be read as a looser one.
    pub(crate) fn from_dict(doc: &Document, d: &Dict) -> Self {
        let names = || -> Vec<String> {
            d.get(b"Fields")
                .map(|f| doc.resolve(f))
                .and_then(|f| f.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .take(MAX_NAMES)
                .filter_map(|n| match &*doc.resolve(n) {
                    Object::String(s) => Some(s.to_text()),
                    _ => None,
                })
                .collect()
        };
        match d.name(b"Action") {
            Some(b"Include") => Self::Include(names()),
            Some(b"Exclude") => Self::Exclude(names()),
            _ => Self::All,
        }
    }

    /// The `/Lock` dictionary of a field (`ty` = `SigFieldLock`) or the transform parameters of a
    /// signature reference (`ty` = `TransformParams`, which also carries the version).
    pub(crate) fn to_dict(&self, ty: &str) -> Dict {
        let mut d = Dict::new();
        d.set(b"Type".to_vec(), Object::name(ty));
        let (action, names) = match self {
            Self::All => ("All", &[][..]),
            Self::Include(l) => ("Include", l.as_slice()),
            Self::Exclude(l) => ("Exclude", l.as_slice()),
        };
        d.set(b"Action".to_vec(), Object::name(action));
        if !matches!(self, Self::All) {
            d.set(b"Fields".to_vec(), Object::Array(names.iter().map(|n| Object::String(PdfString::text(n))).collect()));
        }
        if ty == "TransformParams" {
            d.set(b"V".to_vec(), Object::name("1.2"));
        }
        d
    }

    /// Whether the lock can be written: a bounded number of reasonably short names.
    pub(crate) fn check_size(&self) -> Result<(), String> {
        let names = self.names();
        if names.len() > MAX_NAMES {
            return Err(format!("a signature can lock at most {MAX_NAMES} fields by name"));
        }
        if names.iter().any(|n| n.is_empty() || n.len() > MAX_NAME_LEN) {
            return Err("a field name to lock is empty or too long".into());
        }
        Ok(())
    }
}

/// A named form field and every object that decides what it shows.
pub(crate) struct FormField {
    /// The full name (`parent.child`).
    pub name: String,
    /// The field and its widgets. What they point at (a value, an appearance stream) is not
    /// listed: rewriting such an object is a change the signature never permits, and a new one
    /// can only be reached through a field or widget that changed.
    pub refs: Vec<ObjRef>,
    /// The fields above it, whose inheritable entries (a value, flags) apply to it too.
    pub ancestors: Vec<ObjRef>,
}

/// Entries a field inherits from its parents.
const INHERITED: [&[u8]; 8] = [b"FT", b"Ff", b"V", b"DV", b"DA", b"Q", b"MaxLen", b"Opt"];

/// Every named field of the interactive form, parents included, in `/Fields` order.
pub(crate) fn form_fields(doc: &Document) -> Vec<FormField> {
    let mut out = Vec::new();
    let Some(root) = doc.root() else { return out };
    let Some(form) = doc.get(root).as_dict().and_then(|c| c.get(b"AcroForm").map(|a| doc.resolve(a))).and_then(|a| a.as_dict().cloned()) else {
        return out;
    };
    let Some(fields) = form.get(b"Fields").map(|f| doc.resolve(f)).and_then(|f| f.as_array().cloned()) else { return out };
    let mut seen = HashSet::new();
    let mut stack: Vec<(Object, String, Vec<ObjRef>)> = fields.into_iter().rev().map(|f| (f, String::new(), Vec::new())).collect();
    let mut walked = 0usize;
    while let Some((o, prefix, ancestors)) = stack.pop() {
        walked += 1;
        if walked > MAX_FIELDS {
            break;
        }
        if let Some(r) = o.as_ref()
            && !seen.insert(r)
        {
            continue;
        }
        let Some(d) = doc.resolve(&o).as_dict().cloned() else { continue };
        let part = match d.get(b"T").map(|t| doc.resolve(t)).as_deref() {
            Some(Object::String(s)) => Some(s.to_text()),
            _ => None,
        };
        let name = match (&part, prefix.is_empty()) {
            (Some(p), true) => p.clone(),
            (Some(p), false) => format!("{prefix}.{p}"),
            (None, _) => prefix.clone(),
        };
        let kids: Vec<Object> = d.get(b"Kids").map(|k| doc.resolve(k)).and_then(|k| k.as_array().cloned()).unwrap_or_default();
        // Kids with a /T are fields of their own; the others are this field's widgets.
        let (sub, widgets): (Vec<Object>, Vec<Object>) = kids.into_iter().partition(|k| doc.resolve(k).as_dict().is_some_and(|kd| kd.contains(b"T")));
        let mut below = ancestors.clone();
        below.extend(o.as_ref());
        if below.len() <= MAX_DEPTH {
            for k in sub.into_iter().rev() {
                stack.push((k, name.clone(), below.clone()));
            }
        }
        if part.is_none() {
            continue;
        }
        let mut refs: Vec<ObjRef> = o.as_ref().into_iter().collect();
        refs.extend(widgets.iter().take(MAX_FIELDS).filter_map(Object::as_ref));
        out.push(FormField { name, refs, ancestors });
    }
    out
}

/// Whether the locked fields differ between the signed revision `old` and `doc` as it is now:
/// a locked field changed, or went missing, or (when the lock reaches fields it did not list) a
/// field was added that it covers.
pub(crate) fn changed(doc: &Document, old: &Document, locks: &[FieldLock]) -> bool {
    if locks.is_empty() {
        return false;
    }
    let locked = |name: &str| locks.iter().any(|l| l.covers(name));
    let before = form_fields(old);
    let now = form_fields(doc);
    let now_names: HashSet<&str> = now.iter().map(|f| f.name.as_str()).collect();
    let was_names: HashSet<&str> = before.iter().map(|f| f.name.as_str()).collect();
    let differs = |r: ObjRef| *old.get(r) != *doc.get(r);
    let inherited_differs = |r: ObjRef| {
        let pick = |o: &Object| INHERITED.iter().map(|k| o.as_dict().and_then(|d| d.get(k)).cloned()).collect::<Vec<_>>();
        pick(&old.get(r)) != pick(&doc.get(r))
    };
    before
        .iter()
        .filter(|f| locked(&f.name))
        .any(|f| !now_names.contains(f.name.as_str()) || f.refs.iter().any(|r| differs(*r)) || f.ancestors.iter().any(|r| inherited_differs(*r)))
        || now.iter().any(|f| !was_names.contains(f.name.as_str()) && locked(&f.name))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn what_each_action_covers() {
        let inc = FieldLock::Include(names(&["a", "grp"]));
        assert!(inc.covers("a") && inc.covers("grp") && inc.covers("grp.child") && inc.covers("grp.child.leaf"));
        assert!(!inc.covers("ab") && !inc.covers("b") && !inc.covers("grpx") && !inc.covers("x.a"));
        let exc = FieldLock::Exclude(names(&["a", "grp"]));
        assert!(!exc.covers("a") && !exc.covers("grp.child") && exc.covers("ab") && exc.covers("b"));
        assert!(FieldLock::All.covers("anything"));
        assert!(!FieldLock::Include(Vec::new()).covers("a") && FieldLock::Exclude(Vec::new()).covers("a"));
    }

    #[test]
    fn a_dictionary_round_trips_and_an_unreadable_one_locks_everything() {
        let doc = Document::new();
        for l in [FieldLock::All, FieldLock::Include(names(&["x", "y.z"])), FieldLock::Exclude(names(&["x"])), FieldLock::Include(Vec::new())] {
            for ty in ["SigFieldLock", "TransformParams"] {
                assert_eq!(FieldLock::from_dict(&doc, &l.to_dict(ty)), l);
            }
        }
        let mut d = Dict::new();
        d.set(b"Action".to_vec(), Object::name("Sometimes"));
        assert_eq!(FieldLock::from_dict(&doc, &d), FieldLock::All);
        assert_eq!(FieldLock::from_dict(&doc, &Dict::new()), FieldLock::All);
    }

    #[test]
    fn sizes_are_bounded() {
        assert!(FieldLock::Include(names(&["a"])).check_size().is_ok());
        assert!(FieldLock::Include(vec![String::new()]).check_size().is_err());
        assert!(FieldLock::Include(vec!["a".repeat(MAX_NAME_LEN + 1)]).check_size().is_err());
        assert!(FieldLock::Exclude(vec!["a".to_string(); MAX_NAMES + 1]).check_size().is_err());
        // A hostile list is cut when read.
        let doc = Document::new();
        let mut d = Dict::new();
        d.set(b"Action".to_vec(), Object::name("Include"));
        d.set(b"Fields".to_vec(), Object::Array((0..MAX_NAMES + 50).map(|i| PdfString::text(&i.to_string())).collect()));
        assert_eq!(FieldLock::from_dict(&doc, &d).names().len(), MAX_NAMES);
    }
}
