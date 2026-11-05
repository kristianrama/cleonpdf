//! The Windows spooler end to end: a job goes through `spool::submit`, the system's print queue
//! and a real printer driver, and the PDF that comes out is read back.
//!
//! The printer is Windows' own "Microsoft Print to PDF" on a queue whose port is a file, so no
//! dialog appears and no paper is used. CI creates that queue (`.github/workflows/ci.yml`, job
//! `print-windows`) and names it in two variables:
//!
//! - `CLEONPDF_TEST_PRINTER`: the queue name;
//! - `CLEONPDF_TEST_PRINTER_FILE`: the file its port writes.
//!
//! With neither set the tests do nothing, so `cargo test` works on any machine. Setting
//! `CLEONPDF_TEST_PRINTER_REQUIRED` makes a missing queue a failure instead.
//!
//! This proves the software path (the spooler accepts the job, the driver keeps the page count
//! and each sheet's paper size). It does not prove anything about paper, ink or a physical
//! printer's margins: that still needs a person at a printer.
#![cfg(windows)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cleonpdf_cos::Document;
use cleonpdf_print::spool::{self, Job};

/// Both tests use the one queue and its one output file, so they run one at a time.
static ONE_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct Queue {
    name: String,
    file: PathBuf,
}

fn queue() -> Option<Queue> {
    let name = std::env::var("CLEONPDF_TEST_PRINTER").ok().filter(|s| !s.is_empty());
    let file = std::env::var_os("CLEONPDF_TEST_PRINTER_FILE").map(PathBuf::from);
    match (name, file) {
        (Some(name), Some(file)) => Some(Queue { name, file }),
        _ => {
            assert!(
                std::env::var_os("CLEONPDF_TEST_PRINTER_REQUIRED").is_none(),
                "CLEONPDF_TEST_PRINTER and CLEONPDF_TEST_PRINTER_FILE must name the test queue"
            );
            eprintln!("skipped: no test print queue (set CLEONPDF_TEST_PRINTER and CLEONPDF_TEST_PRINTER_FILE)");
            None
        }
    }
}

/// A PDF of `(width, height)` pages in points, each with a page number and a frame, so a driver
/// that drops or scales a page shows up.
fn pdf_with_pages(sizes: &[(u32, u32)]) -> Vec<u8> {
    let n = sizes.len();
    let mut objs: Vec<Vec<u8>> = vec![b"<< /Type /Catalog /Pages 2 0 R >>".to_vec()];
    let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", 4 + 2 * i)).collect();
    objs.push(format!("<< /Type /Pages /Kids [{}] /Count {n} >>", kids.join(" ")).into_bytes());
    objs.push(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec());
    for (i, (w, h)) in sizes.iter().enumerate() {
        objs.push(
            format!("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w} {h}] /Contents {} 0 R /Resources << /Font << /F1 3 0 R >> >> >>", 5 + 2 * i)
                .into_bytes(),
        );
        let body = format!("0.5 w 18 18 {} {} re S BT /F1 36 Tf 40 {} Td (Page {}) Tj ET", w - 36, h - 36, h / 2, i + 1);
        objs.push(format!("<< /Length {} >>\nstream\n{body}\nendstream", body.len()).into_bytes());
    }
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(o);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objs.len() + 1).as_bytes());
    out
}

/// The file the queue's port writes, once it has appeared and stopped growing.
fn wait_for_output(file: &std::path::Path) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut last = (0u64, 0u32);
    loop {
        let len = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
        if len > 0 && len == last.0 {
            last.1 += 1;
            // Unchanged for three polls: the driver has finished.
            if last.1 >= 3
                && let Ok(bytes) = std::fs::read(file)
            {
                return bytes;
            }
        } else {
            last = (len, 0);
        }
        assert!(Instant::now() < deadline, "no finished PDF in {} after 90 s (size {len})", file.display());
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// The printed pages' sizes in points, as displayed (width, height).
fn page_sizes(bytes: Vec<u8>) -> Vec<(f64, f64)> {
    assert!(bytes.starts_with(b"%PDF-"), "the queue wrote something that is not a PDF: {:?}", &bytes[..bytes.len().min(16)]);
    let doc = Document::open(Arc::new(bytes)).expect("the printed PDF opens");
    cleonpdf_model::pages(&doc)
        .iter()
        .map(|p| {
            let c = p.crop(&doc);
            let (w, h) = (c[2] - c[0], c[3] - c[1]);
            if p.rotation(&doc) % 180 == 90 { (h, w) } else { (w, h) }
        })
        .collect()
}

#[test]
fn a_landscape_sheet_is_turned_onto_the_jobs_portrait_paper_and_every_page_arrives() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(q) = queue() else { return };
    let _ = std::fs::remove_file(&q.file);
    // A4 portrait, A4 landscape, A4 portrait: one paper, two orientations. The job's paper and
    // orientation come from its first sheet, so the landscape sheet is turned onto portrait
    // paper (CI's log showed its content rotated, the 18 pt frame margin kept, no scaling) and
    // the PDF has three portrait pages. If craft-print ever sets orientation per page, this
    // expectation changes to [(595, 842), (842, 595), (595, 842)] and the README with it.
    let wanted = [(595.0, 842.0), (595.0, 842.0), (595.0, 842.0)];
    let pdf = pdf_with_pages(&[(595, 842), (842, 595), (595, 842)]);
    let job = Job { printer: Some(q.name.clone()), title: "cleonpdf windows spooler test".into(), ..Job::default() };
    let id = spool::submit(&pdf, &job).expect("the spooler accepts the job");
    eprintln!("submitted: {id}");
    let printed = page_sizes(wait_for_output(&q.file));
    eprintln!("printed pages (points): {printed:?}");
    assert_eq!(printed.len(), wanted.len(), "page count, got {printed:?}");
    for (i, ((w, h), (ew, eh))) in printed.iter().zip(wanted).enumerate() {
        // The driver rounds paper to its own units; a point or two is not a change of paper.
        assert!((w - ew).abs() <= 3.0 && (h - eh).abs() <= 3.0, "page {} is {w} x {h} pt, wanted {ew} x {eh}", i + 1);
    }
}

#[test]
fn a_job_that_mixes_paper_sizes_is_refused_and_nothing_is_printed() {
    let _one = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
    let Some(q) = queue() else { return };
    let _ = std::fs::remove_file(&q.file);
    // A4 then US Letter: a Windows job has one paper size, so this is refused, not shrunk.
    let pdf = pdf_with_pages(&[(595, 842), (612, 792)]);
    let job = Job { printer: Some(q.name.clone()), title: "cleonpdf windows spooler test".into(), ..Job::default() };
    let err = spool::submit(&pdf, &job).expect_err("two paper sizes in one job are refused").to_string();
    assert!(err.contains("one paper size per job"), "the refusal names the reason: {err}");
    std::thread::sleep(Duration::from_secs(3));
    assert!(!q.file.exists(), "a refused job must not reach the driver");
}
