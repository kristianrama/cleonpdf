//! `cargo xtask interop`: every kind of PDF CleonPDF writes, opened by other readers.
//!
//! Each case runs `cleonpdf-cli run --script` (the automation tools, so the app's own code paths)
//! on synthetic inputs written by hand here, never by the writer under test, and saves the result
//! under `interop-out/` (git-ignored). The result is then read by every reader installed here, run
//! as an external oracle process and never linked (AGENTS.md §1.3): qpdf (`--check`, and `--json`
//! for form fields and bookmarks), Poppler (`pdfinfo`, `pdftotext`, `pdfsig`), MuPDF (`mutool`)
//! and Ghostscript (`gs`). pdf.js is left out: driving it needs handwritten JavaScript, which the
//! build does not allow.
//!
//! For each output, each reader must:
//! - open it, with the open password when there is one and not without it;
//! - report no errors and no repair warnings;
//! - count the same pages as the case expects;
//! - find the text the case added, and none of the text it removed.
//!
//! Some cases also check:
//! - field values and bookmark titles (qpdf);
//! - valid signatures (Poppler's `pdfsig`).
//!
//! A reader that isn't installed is skipped with a note; `--require-all` (CI) fails instead.
//!
//! ```text
//! cargo xtask interop [--only NAME] [--require-all]
//! ```

use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::fuzz::{build_pdf, helvetica_pdf, text_line, toc_book};
use crate::gates::{release_cli, root};

/// The open (user) password of every encrypted case, and the permissions (owner) password.
const USER: &str = "interop-user";
const OWNER: &str = "interop-owner";
/// The password of the signing identity the setup creates.
const SIGNER: &str = "interop-signer";

/// One kind of output: the tool calls that make it, and what other readers must find in it.
struct Case {
    name: &'static str,
    /// Copy this input to the output path before the steps run, so they can save in place (an
    /// incremental update).
    copy: Option<&'static str>,
    steps: Vec<Value>,
    pages: usize,
    /// The open password: readers must open the file with it and refuse it without.
    password: Option<&'static str>,
    text: Vec<&'static str>,
    absent: Vec<&'static str>,
    fields: Vec<(&'static str, &'static str)>,
    outlines: Vec<&'static str>,
    signatures: usize,
}

impl Case {
    fn new(name: &'static str, pages: usize) -> Self {
        Case {
            name,
            copy: None,
            steps: Vec::new(),
            pages,
            password: None,
            text: Vec::new(),
            absent: Vec::new(),
            fields: Vec::new(),
            outlines: Vec::new(),
            signatures: 0,
        }
    }

    /// Where the case writes its output, relative to `interop-out/`.
    fn out(&self) -> String {
        format!("out/{}.pdf", self.name)
    }

    fn step(mut self, tool: &str, args: Value) -> Self {
        self.steps.push(json!({ "tool": tool, "args": args }));
        self
    }

    /// Open `input` as document 1.
    fn open(self, input: &str) -> Self {
        self.step("doc_open", json!({ "path": input }))
    }

    /// Save document `doc` as the case's output (a full rewrite).
    fn save(self, doc: u64) -> Self {
        let out = self.out();
        self.step("doc_save", json!({ "doc": doc, "path": out }))
    }

    /// Copy `input` to the output and open that copy as document 1, to save it in place.
    fn edit_copy(self, input: &'static str) -> Self {
        self.edit_copy_with(input, None)
    }

    /// [`Case::edit_copy`] for an encrypted input, opened with `password`.
    fn edit_copy_with(mut self, input: &'static str, password: Option<&str>) -> Self {
        self.copy = Some(input);
        let out = self.out();
        let mut args = json!({ "path": out });
        if let Some(p) = password {
            args["password"] = json!(p);
        }
        self.step("doc_open", args)
    }

    fn text(mut self, t: &[&'static str]) -> Self {
        self.text.extend_from_slice(t);
        self
    }

    fn absent(mut self, t: &[&'static str]) -> Self {
        self.absent.extend_from_slice(t);
        self
    }

    fn password(mut self, p: &'static str) -> Self {
        self.password = Some(p);
        self
    }

    fn fields(mut self, f: &[(&'static str, &'static str)]) -> Self {
        self.fields.extend_from_slice(f);
        self
    }

    fn outlines(mut self, o: &[&'static str]) -> Self {
        self.outlines.extend_from_slice(o);
        self
    }

    fn signatures(mut self, n: usize) -> Self {
        self.signatures = n;
        self
    }
}

const BASE: &str = "in/base.pdf";
const TOC: &str = "in/toc.pdf";
const IMAGE: &str = "in/image.png";
const ID: &str = "in/signer.p12";
/// A form another program made: a text field with no appearance and `/NeedAppearances true`.
const FORM: &str = "in/form.pdf";
/// [`BASE`] rewritten by qpdf: with object streams and a cross-reference stream, linearized, and
/// encrypted with the open password [`USER`] (AES-256 and RC4-128). Cases on them are skipped
/// when qpdf isn't installed.
const OBJSTM: &str = "in/objstm.pdf";
const LINEARIZED: &str = "in/linearized.pdf";
const ENCRYPTED_AES: &str = "in/encrypted-aes.pdf";
const ENCRYPTED_RC4: &str = "in/encrypted-rc4.pdf";

/// The inputs: written by hand (PDF) or encoded here (PNG), never by CleonPDF; then [`BASE`] in
/// other shapes, made by qpdf when it is installed.
fn write_inputs(dir: &Path, qpdf: bool) -> Result<()> {
    std::fs::create_dir_all(dir.join("in"))?;
    let pages = [
        ["Page one alpha", "Contact alice@example.com for details"],
        ["Page two bravo", "Bravo is mentioned twice: bravo"],
        ["Page three charlie", "The last page of the base document"],
    ];
    let pages: Vec<String> = pages.iter().map(|[a, b]| format!("{}{}", text_line(14, 72, 760, a), text_line(10, 72, 730, b))).collect();
    std::fs::write(dir.join(BASE), helvetica_pdf(&pages, ""))?;
    std::fs::write(dir.join(TOC), toc_book(false))?;
    let content = text_line(14, 72, 760, "A form from another program");
    let form = [
        "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [5 0 R] /NeedAppearances true /DA (/Helv 0 Tf 0 g) /DR << /Font << /Helv 6 0 R >> >> >> >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>",
        "<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << /Font << /F1 6 0 R >> >> /Annots [5 0 R] >>",
        &format!("<< /Length {} >>\nstream\n{content}endstream", content.len()),
        "<< /Type /Annot /Subtype /Widget /FT /Tx /T (name) /F 4 /Rect [72 600 300 620] /P 3 0 R /DA (/Helv 12 Tf 0 g) >>",
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
    ];
    std::fs::write(dir.join(FORM), build_pdf(&form, "/Root 1 0 R"))?;
    if qpdf {
        let base = dir.join(BASE);
        let made: [(&str, &[&str]); 4] = [
            (OBJSTM, &["--object-streams=generate"]),
            (LINEARIZED, &["--linearize"]),
            (ENCRYPTED_AES, &["--encrypt", USER, OWNER, "256", "--"]),
            (ENCRYPTED_RC4, &["--allow-weak-crypto", "--encrypt", USER, OWNER, "128", "--use-aes=n", "--"]),
        ];
        for (out, args) in made {
            let o = run(Command::new("qpdf").args(args).arg(&base).arg(dir.join(out)), TIMEOUT).context("qpdf did not finish")?;
            if o.code != Some(0) {
                bail!("qpdf could not make {out}: {}", o.stderr.trim());
            }
        }
    }
    // A 64 × 48 colour gradient.
    let (w, h) = (64u32, 48u32);
    let mut data = Vec::with_capacity((w * h * 3) as usize);
    for y in 0..h {
        for x in 0..w {
            data.extend_from_slice(&[(x * 4) as u8, (y * 5) as u8, 160]);
        }
    }
    let file = std::fs::File::create(dir.join(IMAGE))?;
    let mut enc = png::Encoder::new(std::io::BufWriter::new(file), w, h);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.write_header()?.write_image_data(&data)?;
    Ok(())
}

fn cases() -> Vec<Case> {
    let protect = |name, compatibility| {
        Case::new(name, 3)
            .open(BASE)
            .step(
                "doc_protect",
                json!({ "doc": 1, "compatibility": compatibility, "open_password": USER, "permissions_password": OWNER, "printing": "low", "copy": false }),
            )
            .save(1)
            .password(USER)
            .text(&["Page one alpha", "Page three charlie"])
    };
    let signed = |name, certify: Option<&str>| {
        let mut args = json!({ "doc": 1, "id": ID, "password": SIGNER, "out": format!("out/{name}.pdf"), "reason": "Interop", "page": 1, "rect": [72, 72, 272, 132] });
        if let Some(c) = certify {
            args["certify"] = json!(c);
        }
        Case::new(name, 3).open(BASE).step("sign_document", args).signatures(1).text(&["Page one alpha"])
    };
    vec![
        // Saving
        Case::new("save-incremental", 3)
            .edit_copy(BASE)
            .step("doc_set_info", json!({ "doc": 1, "key": "Title", "value": "Interop incremental" }))
            .step("doc_save", json!({ "doc": 1 }))
            .text(&["Page one alpha", "Page three charlie"]),
        Case::new("save-full", 3)
            .open(BASE)
            .step("doc_set_info", json!({ "doc": 1, "key": "Title", "value": "Interop full" }))
            .save(1)
            .text(&["Page one alpha", "Page three charlie"]),
        // Saving inputs of other shapes
        Case::new("incremental-objstm", 3)
            .edit_copy(OBJSTM)
            .step("page_add_text", json!({ "doc": 1, "page": 1, "text": "Added to an object-stream file", "at": [72, 600] }))
            .step("doc_save", json!({ "doc": 1 }))
            .text(&["Added to an object-stream file", "Page three charlie"]),
        Case::new("full-objstm", 3)
            .open(OBJSTM)
            .step("doc_set_info", json!({ "doc": 1, "key": "Title", "value": "Interop" }))
            .save(1)
            .text(&["Page one alpha"]),
        Case::new("incremental-linearized", 3)
            .edit_copy(LINEARIZED)
            .step("page_add_text", json!({ "doc": 1, "page": 2, "text": "Added to a linearized file", "at": [72, 600] }))
            .step("doc_save", json!({ "doc": 1 }))
            .text(&["Added to a linearized file", "Page one alpha"]),
        Case::new("incremental-encrypted-aes", 3)
            .edit_copy_with(ENCRYPTED_AES, Some(OWNER))
            .step("page_add_text", json!({ "doc": 1, "page": 1, "text": "Added to an AES file", "at": [72, 600] }))
            .step("doc_save", json!({ "doc": 1 }))
            .password(USER)
            .text(&["Added to an AES file", "Page two bravo"]),
        Case::new("incremental-encrypted-rc4", 3)
            .edit_copy_with(ENCRYPTED_RC4, Some(OWNER))
            .step("page_add_text", json!({ "doc": 1, "page": 1, "text": "Added to an RC4 file", "at": [72, 600] }))
            .step("doc_save", json!({ "doc": 1 }))
            .password(USER)
            .text(&["Added to an RC4 file", "Page two bravo"]),
        Case::new("fill-foreign-form", 1)
            .edit_copy(FORM)
            .step("form_fill", json!({ "doc": 1, "values": { "name": "Filled foreign form" } }))
            .step("doc_save", json!({ "doc": 1 }))
            .fields(&[("name", "Filled foreign form")])
            .text(&["Filled foreign form", "A form from another program"]),
        // Creating
        Case::new("create-blank", 2).step("doc_create", json!({ "from": "blank", "pages": 2 })).save(1),
        Case::new("create-text", 1)
            .step("doc_create", json!({ "from": "text", "text": "Created from text for the interop suite" }))
            .save(1)
            .text(&["Created from text for the interop suite"]),
        Case::new("create-images", 1).step("doc_create", json!({ "from": "images", "paths": [IMAGE] })).save(1),
        // Encrypting
        protect("protect-aes-256", "aes-256"),
        protect("protect-aes-128", "aes-128"),
        protect("protect-rc4-128", "rc4-128"),
        protect("protect-rc4-40", "rc4-40"),
        Case::new("protect-permissions-only", 3)
            .open(BASE)
            .step(
                "doc_protect",
                json!({ "doc": 1, "compatibility": "aes-256", "permissions_password": OWNER, "printing": "none", "changes": "none" }),
            )
            .save(1)
            .text(&["Page one alpha"]),
        Case::new("protect-then-edit", 3)
            .open(BASE)
            .step("doc_protect", json!({ "doc": 1, "compatibility": "aes-256", "open_password": USER, "permissions_password": OWNER }))
            .save(1)
            .step("doc_open", json!({ "path": "out/protect-then-edit.pdf", "password": OWNER }))
            .step("page_add_text", json!({ "doc": 2, "page": 1, "text": "Added after encryption", "at": [72, 600] }))
            .step("doc_save", json!({ "doc": 2 }))
            .password(USER)
            .text(&["Page one alpha", "Added after encryption"]),
        Case::new("unprotect", 3)
            .open(BASE)
            .step("doc_protect", json!({ "doc": 1, "compatibility": "aes-256", "open_password": USER, "permissions_password": OWNER }))
            .step("doc_save", json!({ "doc": 1, "path": "out/unprotect-locked.pdf" }))
            .step("doc_open", json!({ "path": "out/unprotect-locked.pdf", "password": OWNER }))
            .step("doc_unprotect", json!({ "doc": 2 }))
            .save(2)
            .text(&["Page one alpha"]),
        // Pages
        Case::new("rotate", 3).open(BASE).step("page_rotate", json!({ "doc": 1, "degrees": 90, "pages": [2] })).save(1).text(&["Page two bravo"]),
        Case::new("delete", 2)
            .open(BASE)
            .step("page_delete", json!({ "doc": 1, "pages": [2] }))
            .save(1)
            .text(&["Page one alpha"])
            .absent(&["Page two bravo"]),
        Case::new("insert-blank", 4).open(BASE).step("page_insert_blank", json!({ "doc": 1, "at": 2 })).save(1).text(&["Page two bravo"]),
        Case::new("insert-file", 8)
            .open(BASE)
            .step("page_insert_file", json!({ "doc": 1, "at": 2, "path": TOC }))
            .save(1)
            .text(&["Contents", "Page three charlie"]),
        Case::new("extract", 2)
            .open(BASE)
            .step("page_extract", json!({ "doc": 1, "pages": [2, 3], "out": "out/extract.pdf" }))
            .text(&["Page two bravo", "Page three charlie"])
            .absent(&["Page one alpha"]),
        Case::new("combine", 8)
            .step("doc_combine", json!({ "paths": [BASE, TOC], "out": "out/combine.pdf" }))
            .text(&["Page one alpha", "Getting started"]),
        // Comments and markup
        Case::new("comments", 3)
            .open(BASE)
            .step("comment_add", json!({ "doc": 1, "page": 1, "type": "note", "at": [400, 760], "contents": "A sticky note" }))
            .step("comment_add", json!({ "doc": 1, "page": 1, "type": "highlight", "find": "alpha" }))
            .step("comment_add", json!({ "doc": 1, "page": 1, "type": "underline", "find": "Contact" }))
            .step("comment_add", json!({ "doc": 1, "page": 2, "type": "strikeout", "find": "bravo" }))
            .step("comment_add", json!({ "doc": 1, "page": 1, "type": "rectangle", "rect": [72, 500, 200, 560] }))
            .step("comment_add", json!({ "doc": 1, "page": 1, "type": "oval", "rect": [220, 500, 340, 560] }))
            .step("comment_add", json!({ "doc": 1, "page": 1, "type": "arrow", "from": [72, 450], "to": [200, 420] }))
            .step("comment_add", json!({ "doc": 1, "page": 1, "type": "ink", "strokes": [[[72, 380], [120, 400], [160, 370]]] }))
            .step(
                "comment_add",
                json!({ "doc": 1, "page": 1, "type": "textbox", "rect": [72, 300, 300, 340], "contents": "Text box comment interop" }),
            )
            .step("comment_add", json!({ "doc": 1, "page": 1, "type": "polygon", "points": [[320, 300], [380, 340], [440, 300]] }))
            .step("comment_add", json!({ "doc": 1, "page": 1, "type": "stamp", "at": [400, 200] }))
            .save(1)
            .text(&["Page one alpha", "Text box comment interop"]),
        // Forms
        Case::new("forms", 3)
            .open(BASE)
            .step("form_add_field", json!({ "doc": 1, "page": 1, "type": "text", "name": "name", "rect": [72, 600, 300, 620] }))
            .step("form_add_field", json!({ "doc": 1, "page": 1, "type": "checkbox", "name": "agree", "rect": [72, 570, 86, 584] }))
            .step(
                "form_add_field",
                json!({ "doc": 1, "page": 1, "type": "combo", "name": "colour", "options": ["Red", "Green"], "rect": [72, 540, 200, 560] }),
            )
            .step("form_fill", json!({ "doc": 1, "values": { "name": "Filled value interop", "colour": "Green" } }))
            .save(1)
            .fields(&[("name", "Filled value interop"), ("colour", "Green")])
            .text(&["Filled value interop"]),
        Case::new("flatten", 3)
            .open(BASE)
            .step("form_add_field", json!({ "doc": 1, "page": 1, "type": "text", "name": "name", "rect": [72, 600, 300, 620] }))
            .step("form_fill", json!({ "doc": 1, "values": { "name": "Flattened value interop" } }))
            .step(
                "comment_add",
                json!({ "doc": 1, "page": 1, "type": "textbox", "rect": [72, 300, 300, 340], "contents": "Flattened comment interop" }),
            )
            .step("doc_flatten", json!({ "doc": 1, "fields": true, "comments": true }))
            .save(1)
            .text(&["Flattened value interop", "Flattened comment interop"]),
        // Page content
        Case::new("add-text", 3)
            .open(BASE)
            .step("page_add_text", json!({ "doc": 1, "page": 1, "text": "Added text interop", "at": [72, 600] }))
            .save(1)
            .text(&["Added text interop", "Page one alpha"]),
        Case::new("add-image", 3)
            .open(BASE)
            .step("page_add_image", json!({ "doc": 1, "page": 1, "path": IMAGE, "rect": [72, 500, 200, 596] }))
            .save(1)
            .text(&["Page one alpha"]),
        Case::new("watermark", 3)
            .open(BASE)
            .step("doc_watermark", json!({ "doc": 1, "text": "WATERMARK INTEROP", "opacity": 0.3, "rotation": 45 }))
            .save(1)
            .text(&["WATERMARK INTEROP", "Page two bravo"]),
        Case::new("header-footer", 3)
            .open(BASE)
            .step("doc_header_footer", json!({ "doc": 1, "footer_center": "Interop footer", "header_right": "Interop header" }))
            .save(1)
            .text(&["Interop footer", "Interop header", "Page one alpha"]),
        Case::new("background", 3).open(BASE).step("doc_background", json!({ "doc": 1, "color": "#ffeecc" })).save(1).text(&["Page one alpha"]),
        Case::new("text-edit", 3)
            .open(BASE)
            .step("text_edit", json!({ "doc": 1, "page": 1, "line": 1, "text": "Edited line interop" }))
            .save(1)
            .text(&["Edited line interop", "Contact alice@example.com"])
            .absent(&["Page one alpha"]),
        // Removing content
        Case::new("redact", 3)
            .open(BASE)
            .step("redact_mark", json!({ "doc": 1, "find": "bravo" }))
            .step("redact_mark", json!({ "doc": 1, "pattern": "email" }))
            .step("redact_apply", json!({ "doc": 1 }))
            .save(1)
            .text(&["Page one alpha", "Page three charlie"])
            .absent(&["bravo", "alice@example.com"]),
        Case::new("remove-hidden", 3).open(BASE).step("doc_remove_hidden", json!({ "doc": 1 })).save(1).text(&["Page one alpha"]),
        // Optimizing and standards
        Case::new("optimize", 3).open(BASE).step("doc_optimize", json!({ "doc": 1, "path": "out/optimize.pdf" })).text(&["Page one alpha"]),
        Case::new("reduce", 3).open(BASE).step("doc_reduce", json!({ "doc": 1, "path": "out/reduce.pdf" })).text(&["Page one alpha"]),
        Case::new("pdfa-2b", 3).open(BASE).step("pdfa_convert", json!({ "doc": 1, "level": "2b" })).save(1).text(&["Page one alpha"]),
        Case::new("autotag", 3).open(BASE).step("accessibility_autotag_apply", json!({ "doc": 1 })).save(1).text(&["Page one alpha"]),
        // Navigation
        Case::new("links-bookmarks", 3)
            .open(BASE)
            .step("link_add", json!({ "doc": 1, "page": 1, "rect": [72, 755, 200, 775], "url": "https://example.com/interop" }))
            .step("link_add", json!({ "doc": 1, "page": 1, "rect": [72, 725, 200, 745], "to_page": 3 }))
            .step("bookmark_add", json!({ "doc": 1, "page": 2, "title": "Interop bookmark" }))
            .save(1)
            .outlines(&["Interop bookmark"])
            .text(&["Page one alpha"]),
        Case::new("toc-link", 5)
            .open(TOC)
            .step("toc_link", json!({ "doc": 1 }))
            .save(1)
            .outlines(&["Introduction", "1 Getting started", "2 Using it"])
            .text(&["Contents"]),
        Case::new("initial-view", 3)
            .open(BASE)
            .step("doc_initial_view", json!({ "doc": 1, "layout": "two_up", "page": 2 }))
            .save(1)
            .text(&["Page one alpha"]),
        Case::new("document-script", 3)
            .open(BASE)
            .step("js_set_document_script", json!({ "doc": 1, "name": "init", "script": "var interop = 1;" }))
            .save(1)
            .text(&["Page one alpha"]),
        // Fill & Sign and stamps
        Case::new("fill-sign", 3)
            .open(BASE)
            .step("fill_sign_add", json!({ "doc": 1, "page": 1, "type": "text", "text": "Fill and sign interop", "at": [72, 600] }))
            .step("fill_sign_add", json!({ "doc": 1, "page": 1, "type": "check", "at": [72, 570] }))
            .save(1)
            .text(&["Fill and sign interop"]),
        Case::new("fill-sign-flattened", 3)
            .open(BASE)
            .step("fill_sign_add", json!({ "doc": 1, "page": 1, "type": "text", "text": "Fill and sign flattened", "at": [72, 600] }))
            .step("doc_save", json!({ "doc": 1, "path": "out/fill-sign-flattened.pdf", "flatten_fill_sign": true }))
            .text(&["Fill and sign flattened"]),
        Case::new("stamp-image", 3)
            .open(BASE)
            .step("stamp_custom", json!({ "doc": 1, "page": 1, "path": IMAGE, "at": [300, 400] }))
            .save(1)
            .text(&["Page one alpha"]),
        Case::new("measure", 3)
            .open(BASE)
            .step("measure_distance", json!({ "doc": 1, "page": 1, "points": [[72, 400], [272, 400]] }))
            .save(1)
            .text(&["Page one alpha"]),
        // Signing
        signed("sign", None),
        signed("sign-certify", Some("form_fill")),
        Case::new("sign-then-comment", 3)
            .open(BASE)
            .step(
                "sign_document",
                json!({ "doc": 1, "id": ID, "password": SIGNER, "out": "out/sign-then-comment.pdf", "page": 1, "rect": [72, 72, 272, 132] }),
            )
            .step("doc_open", json!({ "path": "out/sign-then-comment.pdf" }))
            .step("comment_add", json!({ "doc": 2, "page": 2, "type": "textbox", "rect": [72, 300, 300, 340], "contents": "Comment after signing" }))
            .step("doc_save", json!({ "doc": 2 }))
            .signatures(1)
            .text(&["Page one alpha", "Comment after signing"]),
    ]
}

/// A finished child process: exit code (None when killed by a signal), stdout, stderr.
struct Output {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Run `cmd`, killing it after `timeout`. `None` when it can't start or runs too long.
fn run(cmd: &mut Command, timeout: Duration) -> Option<Output> {
    let mut child = cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().ok()?;
    let mut out = child.stdout.take()?;
    let mut err = child.stderr.take()?;
    let read_out = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = out.read_to_end(&mut b);
        b
    });
    let read_err = std::thread::spawn(move || {
        let mut b = Vec::new();
        let _ = err.read_to_end(&mut b);
        b
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if start.elapsed() > timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(5)),
            Err(_) => return None,
        }
    };
    let stdout = String::from_utf8_lossy(&read_out.join().ok()?).into_owned();
    let stderr = String::from_utf8_lossy(&read_err.join().ok()?).into_owned();
    Some(Output { code: status.code(), stdout, stderr })
}

const TIMEOUT: Duration = Duration::from_secs(60);

/// What one reader made of one file.
#[derive(Default)]
struct Reading {
    /// It opened the file (with the password, if any).
    opened: bool,
    pages: Option<usize>,
    text: Option<String>,
    /// Errors and repair warnings it printed.
    notes: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reader {
    Qpdf,
    Poppler,
    MuPdf,
    Ghostscript,
}

impl Reader {
    const ALL: [Reader; 4] = [Reader::Qpdf, Reader::Poppler, Reader::MuPdf, Reader::Ghostscript];

    fn name(self) -> &'static str {
        match self {
            Reader::Qpdf => "qpdf",
            Reader::Poppler => "poppler",
            Reader::MuPdf => "mupdf",
            Reader::Ghostscript => "ghostscript",
        }
    }

    /// Its version, or `None` when it isn't installed.
    fn version(self) -> Option<String> {
        let (prog, arg) = match self {
            Reader::Qpdf => ("qpdf", "--version"),
            Reader::Poppler => ("pdfinfo", "-v"),
            Reader::MuPdf => ("mutool", "-v"),
            Reader::Ghostscript => ("gs", "--version"),
        };
        let o = run(Command::new(prog).arg(arg), TIMEOUT)?;
        let all = format!("{}{}", o.stdout, o.stderr);
        all.lines().find(|l| l.chars().any(|c| c.is_ascii_digit())).map(|l| l.trim().to_string())
    }

    /// Read `file`, with `password` when given.
    fn read(self, file: &Path, password: Option<&str>) -> Reading {
        match self {
            Reader::Qpdf => qpdf(file, password),
            Reader::Poppler => poppler(file, password),
            Reader::MuPdf => mupdf(file, password),
            Reader::Ghostscript => ghostscript(file, password),
        }
    }
}

/// The lines of `text` that contain one of `markers` (case-sensitively), trimmed.
fn lines_with(text: &str, markers: &[&str]) -> Vec<String> {
    text.lines().filter(|l| markers.iter().any(|m| l.contains(m))).map(|l| l.trim().to_string()).collect()
}

fn qpdf(file: &Path, password: Option<&str>) -> Reading {
    let with_password = |c: &mut Command| {
        if let Some(p) = password {
            c.arg(format!("--password={p}"));
        }
    };
    let mut r = Reading::default();
    let mut check = Command::new("qpdf");
    with_password(&mut check);
    let Some(o) = run(check.arg("--check").arg(file), TIMEOUT) else {
        r.notes.push("qpdf --check did not finish".into());
        return r;
    };
    let all = format!("{}{}", o.stdout, o.stderr);
    // 0: fine; 3: warnings (the file was readable); 2: errors.
    r.opened = matches!(o.code, Some(0 | 3));
    // Its closing line ("No syntax or stream encoding errors found; the file may still contain
    // errors that qpdf cannot detect") is not a finding.
    r.notes = lines_with(&all, &["WARNING", "invalid password"]);
    if o.code == Some(2) && r.notes.is_empty() {
        r.notes.push(all.lines().last().unwrap_or("").trim().to_string());
    }
    let mut npages = Command::new("qpdf");
    with_password(&mut npages);
    r.pages = run(npages.arg("--show-npages").arg(file), TIMEOUT).and_then(|o| o.stdout.trim().parse().ok());
    r
}

fn poppler(file: &Path, password: Option<&str>) -> Reading {
    let with_password = |c: &mut Command| {
        if let Some(p) = password {
            c.args(["-upw", p]);
        }
    };
    let mut r = Reading::default();
    let mut info = Command::new("pdfinfo");
    with_password(&mut info);
    let Some(o) = run(info.arg(file), TIMEOUT) else {
        r.notes.push("pdfinfo did not finish".into());
        return r;
    };
    r.opened = o.code == Some(0);
    r.pages = o.stdout.lines().find_map(|l| l.strip_prefix("Pages:")).and_then(|n| n.trim().parse().ok());
    r.notes = o.stderr.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    if !r.opened {
        return r;
    }
    let mut text = Command::new("pdftotext");
    with_password(&mut text);
    if let Some(o) = run(text.arg(file).arg("-"), TIMEOUT) {
        r.notes.extend(o.stderr.lines().map(str::trim).filter(|l| !l.is_empty()).map(|l| format!("pdftotext: {l}")));
        r.text = Some(o.stdout);
    }
    r
}

fn mupdf(file: &Path, password: Option<&str>) -> Reading {
    let with_password = |c: &mut Command| {
        if let Some(p) = password {
            c.args(["-p", p]);
        }
    };
    let mut r = Reading::default();
    let mut info = Command::new("mutool");
    info.arg("info");
    with_password(&mut info);
    let Some(o) = run(info.arg(file), TIMEOUT) else {
        r.notes.push("mutool info did not finish".into());
        return r;
    };
    r.pages = o.stdout.lines().find_map(|l| l.trim().strip_prefix("Pages:")).and_then(|n| n.trim().parse().ok());
    r.opened = o.code == Some(0) && r.pages.is_some();
    r.notes = lines_with(&o.stderr, &["warning", "error"]);
    if !r.opened {
        if r.notes.is_empty() {
            r.notes.push(o.stderr.lines().last().unwrap_or("mutool info failed").trim().to_string());
        }
        return r;
    }
    let mut draw = Command::new("mutool");
    draw.args(["draw", "-q", "-F", "txt", "-o", "-"]);
    with_password(&mut draw);
    if let Some(o) = run(draw.arg(file), TIMEOUT) {
        r.notes.extend(lines_with(&o.stderr, &["warning", "error"]).into_iter().map(|l| format!("draw: {l}")));
        r.text = Some(o.stdout);
    }
    r
}

fn ghostscript(file: &Path, password: Option<&str>) -> Reading {
    let gs = |device: &str| {
        let mut c = Command::new("gs");
        c.args(["-q", "-dNOPAUSE", "-dBATCH", "-dSAFER", "-sstdout=%stderr", &format!("-sDEVICE={device}"), "-sOutputFile=-"]);
        if let Some(p) = password {
            c.arg(format!("-sPDFPassword={p}"));
        }
        c.arg(file);
        c
    };
    let mut r = Reading::default();
    // bbox writes one %%BoundingBox line per page to stderr: the page count.
    let Some(o) = run(&mut gs("bbox"), TIMEOUT) else {
        r.notes.push("gs did not finish".into());
        return r;
    };
    let boxes = o.stderr.lines().filter(|l| l.starts_with("%%BoundingBox:")).count();
    r.opened = o.code == Some(0) && boxes > 0;
    r.pages = (boxes > 0).then_some(boxes);
    r.notes = o.stderr.lines().filter(|l| !l.starts_with("%%")).map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    if !r.opened {
        return r;
    }
    if let Some(o) = run(&mut gs("txtwrite"), TIMEOUT) {
        r.notes.extend(o.stderr.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).map(|l| format!("txtwrite: {l}")));
        r.text = Some(o.stdout);
    }
    r
}

/// Text without its whitespace, so text each reader splits differently still matches: Poppler
/// breaks diagonal text (a 45° watermark) into a letter or two per "word".
fn squash(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

/// qpdf's JSON (version 2) for the form fields and bookmarks of `file`.
fn qpdf_json(file: &Path, password: Option<&str>) -> Option<Value> {
    let mut c = Command::new("qpdf");
    if let Some(p) = password {
        c.arg(format!("--password={p}"));
    }
    let o = run(c.args(["--json=2", "--json-key=acroform", "--json-key=outlines"]).arg(file), TIMEOUT)?;
    serde_json::from_str(&o.stdout).ok()
}

/// A string from qpdf's JSON, which marks text `u:` and binary `b:`.
fn qpdf_string(v: &Value) -> String {
    match v.as_str() {
        Some(s) => s.strip_prefix("u:").or_else(|| s.strip_prefix("b:")).unwrap_or(s).to_string(),
        None => v.to_string(),
    }
}

fn outline_titles(items: &Value, out: &mut Vec<String>) {
    for item in items.as_array().into_iter().flatten() {
        out.push(qpdf_string(&item["title"]));
        outline_titles(&item["kids"], out);
    }
}

/// `pdfsig`'s count of valid signatures.
fn valid_signatures(file: &Path) -> Option<(usize, Vec<String>)> {
    let o = run(Command::new("pdfsig").arg(file), TIMEOUT)?;
    let valid = o.stdout.lines().filter(|l| l.contains("Signature Validation: Signature is Valid")).count();
    let notes =
        o.stdout.lines().filter(|l| l.contains("Signature Validation:") && !l.contains("Signature is Valid")).map(|l| l.trim().to_string()).collect();
    Some((valid, notes))
}

/// The problems other readers have with one case's output.
/// `noise[i]`: what reader `readers[i]` prints for the hand-written input, ignored everywhere.
fn check(case: &Case, file: &Path, readers: &[Reader], noise: &[Vec<String>]) -> Vec<String> {
    let mut problems = Vec::new();
    for (i, &reader) in readers.iter().enumerate() {
        let name = reader.name();
        let r = reader.read(file, case.password);
        if !r.opened {
            problems.push(format!("{name}: does not open it ({})", r.notes.join("; ")));
            continue;
        }
        let noise = noise.get(i).map(Vec::as_slice).unwrap_or_default();
        problems.extend(r.notes.iter().filter(|n| !noise.contains(n)).map(|n| format!("{name}: {n}")));
        match r.pages {
            Some(p) if p == case.pages => {}
            Some(p) => problems.push(format!("{name}: {p} pages, expected {}", case.pages)),
            None => problems.push(format!("{name}: no page count")),
        }
        if let Some(text) = &r.text {
            let text = squash(text);
            for t in &case.text {
                if !text.contains(&squash(t)) {
                    problems.push(format!("{name}: text {t:?} missing"));
                }
            }
            for t in &case.absent {
                if text.contains(&squash(t)) {
                    problems.push(format!("{name}: text {t:?} should be gone"));
                }
            }
        }
        if case.password.is_some() && reader.read(file, None).opened {
            problems.push(format!("{name}: opens it without the password"));
        }
    }
    if readers.contains(&Reader::Qpdf) && (!case.fields.is_empty() || !case.outlines.is_empty()) {
        match qpdf_json(file, case.password) {
            None => problems.push("qpdf: no JSON".into()),
            Some(j) => {
                let fields = j["acroform"]["fields"].as_array().cloned().unwrap_or_default();
                for (name, value) in &case.fields {
                    match fields.iter().find(|f| qpdf_string(&f["fullname"]) == *name) {
                        None => problems.push(format!("qpdf: field {name:?} missing")),
                        Some(f) => {
                            let v = qpdf_string(&f["value"]);
                            if v.trim_start_matches('/') != *value {
                                problems.push(format!("qpdf: field {name:?} is {v:?}, expected {value:?}"));
                            }
                        }
                    }
                }
                let mut titles = Vec::new();
                outline_titles(&j["outlines"], &mut titles);
                for o in &case.outlines {
                    if !titles.iter().any(|t| t == o) {
                        problems.push(format!("qpdf: bookmark {o:?} missing (has {titles:?})"));
                    }
                }
            }
        }
    }
    if case.signatures > 0 && readers.contains(&Reader::Poppler) {
        match valid_signatures(file) {
            None => problems.push("pdfsig: did not run".into()),
            Some((valid, notes)) => {
                if valid != case.signatures {
                    problems.push(format!("pdfsig: {valid} valid signature(s), expected {} ({})", case.signatures, notes.join("; ")));
                }
            }
        }
    }
    problems
}

pub fn run_cmd(args: &[String]) -> Result<()> {
    let only = args.iter().position(|a| a == "--only").and_then(|i| args.get(i + 1)).cloned();
    let require_all = args.iter().any(|a| a == "--require-all");
    let mut readers = Vec::new();
    for r in Reader::ALL {
        match r.version() {
            Some(v) => {
                println!("interop: {} ({v})", r.name());
                readers.push(r);
            }
            None if require_all => bail!("{} is not installed (--require-all)", r.name()),
            None => println!("interop: {} not installed, skipped", r.name()),
        }
    }
    if readers.is_empty() {
        bail!("no reader installed: install qpdf, poppler-utils, mupdf-tools or ghostscript");
    }
    crate::gates::run_args(&["build", "--release", "-q", "-p", "cleonpdf-cli"])?;
    let cli = release_cli();
    let dir = root().join("interop-out");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("out"))?;
    write_inputs(&dir, readers.contains(&Reader::Qpdf))?;
    let setup = json!([{ "tool": "sign_id_create", "args": { "name": "Interop Signer", "password": SIGNER, "path": ID } }]);
    script(&cli, &dir, "setup", &setup).context("creating the signing identity")?;

    // What each reader says about the hand-written input is about the reader (a build without
    // ICC support, a Ghostscript device bug), not about anything CleonPDF wrote.
    let mut noise = Vec::new();
    for &reader in &readers {
        let r = reader.read(&dir.join(BASE), None);
        if !r.opened {
            bail!("{} can't open the hand-written input: {}", reader.name(), r.notes.join("; "));
        }
        for n in &r.notes {
            println!("interop: {} says this about the hand-written input too, ignored: {n}", reader.name());
        }
        noise.push(r.notes);
    }

    let mut failed = 0;
    let mut ran = 0;
    for case in cases().into_iter().filter(|c| only.as_deref().is_none_or(|o| c.name == o)) {
        ran += 1;
        let out = dir.join(case.out());
        let mut original = None;
        if let Some(input) = case.copy {
            if !dir.join(input).is_file() {
                println!("  skip  {} ({input} needs qpdf to make it)", case.name);
                continue;
            }
            std::fs::copy(dir.join(input), &out)?;
            original = Some(std::fs::read(&out)?);
        }
        let mut problems = match script(&cli, &dir, case.name, &Value::Array(case.steps.clone())) {
            Err(e) => vec![format!("cleonpdf: {e:#}")],
            Ok(()) if !out.is_file() => vec![format!("cleonpdf: wrote no {}", case.out())],
            Ok(()) => check(&case, &out, &readers, &noise),
        };
        // Saving in place is an incremental update: the original bytes, then the changes.
        if let Some(original) = original
            && !std::fs::read(&out).is_ok_and(|now| now.len() > original.len() && now.starts_with(&original))
        {
            problems.push("cleonpdf: saving in place did not append to the original bytes".into());
        }
        if problems.is_empty() {
            println!("  ok    {}", case.name);
        } else {
            failed += 1;
            println!("  FAIL  {}", case.name);
            for p in problems {
                println!("          {p}");
            }
        }
    }
    println!("interop: {ran} case(s), {failed} with problems; outputs in interop-out/out/");
    if failed > 0 {
        bail!("{failed} case(s) with problems");
    }
    Ok(())
}

/// Run `steps` with `cleonpdf-cli run --script`, confined to `dir`.
fn script(cli: &Path, dir: &Path, name: &str, steps: &Value) -> Result<()> {
    let file = dir.join(format!("{name}.json"));
    std::fs::write(&file, serde_json::to_string_pretty(steps)?)?;
    let o = run(Command::new(cli).current_dir(dir).args(["run", "--root"]).arg(dir).arg("--script").arg(&file), TIMEOUT)
        .with_context(|| format!("{name}: cleonpdf-cli did not finish"))?;
    if o.code != Some(0) {
        bail!("{}", o.stderr.trim());
    }
    Ok(())
}
