//! Windows only: embed version info (VERSIONINFO) into `cleonpdf-cli.exe`, so Explorer's
//! Details tab, `(Get-Item cleonpdf-cli.exe).VersionInfo` and inventory tools can read the version
//! and publisher, as they can for `cleonpdf.exe` (`apps/cleonpdf/build.rs`).
//!
//! On every other target this does nothing. A missing resource compiler is a warning, so a
//! cross-compile from macOS or Linux still links, unless `CLEONPDF_REQUIRE_WINRES=1` turns it
//! into an error (for release builds).

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CLEONPDF_REQUIRE_WINRES");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "CleonPDF")
        .set("FileDescription", "CleonPDF command-line tool")
        .set(
            "LegalCopyright",
            "Copyright (c) 2026 Kristian Rama. Based on PdfCraft, Copyright (c) 2026 ArtCraft Team and the PdfCraft contributors. MIT OR Apache-2.0.",
        )
        .set("OriginalFilename", "cleonpdf-cli.exe")
        .set("InternalName", "cleonpdf-cli");
    if let Err(e) = res.compile() {
        if std::env::var_os("CLEONPDF_REQUIRE_WINRES").is_some() {
            println!("cargo::error=embedding Windows resources failed: {e}");
            return;
        }
        println!("cargo:warning=cleonpdf-cli.exe built without version resources: {e}");
    }
}
