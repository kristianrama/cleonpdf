//! vendor/winit patch (12) (vendor/README.md).

#[test]
fn winit_puts_a_glass_backdrop_under_transparent_macos_windows() {
    // Preferences ▸ Glass window: on macOS the app asks winit for a glass backdrop before its window
    // exists (`platform::macos::set_glass_backdrop`). winit 0.30 has no such thing: it makes a
    // transparent window's view the content view and nothing is behind it. vendor/winit puts
    // NSGlassEffectView (macOS 26) or NSVisualEffectView under the view instead, and keeps the
    // view itself (the content view is then the backdrop). A re-vendored copy without the patch
    // fails to build CleonPDF on macOS; this keeps the parts that wouldn't.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let delegate = std::fs::read_to_string(root.join("vendor/winit/src/platform_impl/macos/window_delegate.rs")).unwrap();
    assert!(delegate.contains("fn install_glass_backdrop("), "no glass backdrop");
    assert!(delegate.contains("\"NSGlassEffectView\"") && delegate.contains("\"NSVisualEffectView\""), "Liquid Glass or its fallback is gone");
    assert!(delegate.contains("accessibilityDisplayShouldReduceTransparency"), "Reduce transparency isn't honoured");
    assert!(delegate.contains("self.ivars().view.clone()"), "the view is cast from the content view, which is the backdrop now");
    let platform = std::fs::read_to_string(root.join("vendor/winit/src/platform/macos.rs")).unwrap();
    assert!(platform.contains("pub fn set_glass_backdrop(") && platform.contains("pub fn glass_backdrop("));
}
